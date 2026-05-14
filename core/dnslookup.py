import argparse
import socket
import json
import os
import sys
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR, SAVE_REPORTS, DNS_RESOLVERS

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'admin',
    'administrator', 'cpanel', 'whm', 'plesk', 'directadmin',
    'api', 'api2', 'api-v1', 'api-v2', 'v1', 'v2', 'v3',
    'dev', 'develop', 'development', 'staging', 'stage', 'stg',
    'test', 'testing', 'uat', 'qa', 'sandbox', 'demo',
    'blog', 'news', 'forum', 'shop', 'store', 'pay', 'payment',
    'portal', 'app', 'apps', 'mobile', 'm', 'cdn', 'static', 'assets',
    'media', 'images', 'img', 'files', 'upload', 'uploads',
    'vpn', 'remote', 'rdp', 'ssh', 'sftp',
    'git', 'gitlab', 'github', 'svn', 'bitbucket', 'jira', 'confluence',
    'jenkins', 'ci', 'cd', 'build',
    'mysql', 'db', 'database', 'redis', 'mongo', 'elastic',
    'grafana', 'kibana', 'prometheus', 'zabbix', 'nagios',
    'ns', 'ns1', 'ns2', 'ns3', 'dns', 'dns1', 'dns2',
    'mx', 'mx1', 'mx2', 'smtp1', 'smtp2', 'mail1', 'mail2',
    'support', 'help', 'docs', 'documentation', 'wiki',
    'status', 'health', 'monitor', 'dashboard',
    'secure', 'ssl', 'login', 'auth', 'sso', 'oauth',
    'old', 'new', 'backup', 'bak', 'archive', 'legacy',
    'internal', 'intranet', 'extranet', 'private',
    'proxy', 'gateway', 'lb', 'loadbalancer',
    'beta', 'alpha', 'preview', 'rc',
    'cloud', 'aws', 'gcp', 'azure',
    'ww', 'ww1', 'ww2', 'www1', 'www2', 'web', 'web1', 'web2',
]

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA', 'DMARC', 'SPF']

def _sep(title=''):
    if title:
        print(f"\n{LY}{'─'*20} {W}{title} {LY}{'─'*20}{N}")
    else:
        print(f"{LY}{'─'*65}{N}")

def _make_resolver(nameservers=None):
    if not HAS_DNSPYTHON:
        return None
    r = dns.resolver.Resolver()
    r.lifetime = 8
    r.timeout  = 4
    if nameservers:
        r.nameservers = nameservers
    return r

def full_dns_lookup(domain, resolvers=None):
    results = {}
    if not HAS_DNSPYTHON:
        print(f"{warning} dnspython not installed — socket fallback (A only)")
        try:
            ips = list({r[4][0] for r in socket.getaddrinfo(domain, None)})
            results['A'] = ips
        except Exception as e:
            results['_error'] = str(e)
        return results

    resolver = _make_resolver(resolvers)

    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA']:
        try:
            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records = [str(r) for r in answers]
            if records:
                results[rtype] = records
        except dns.resolver.NXDOMAIN:
            results['_nxdomain'] = True
            break
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.Timeout:
            results[rtype] = ['TIMEOUT']
        except Exception:
            pass

    try:
        ans = resolver.resolve(f'_dmarc.{domain}', 'TXT', raise_on_no_answer=False)
        dmarc = [str(r) for r in ans]
        if dmarc:
            results['DMARC'] = dmarc
    except Exception:
        pass

    if 'TXT' in results:
        spf = [r for r in results['TXT'] if 'v=spf1' in r.lower()]
        if spf:
            results['SPF'] = spf

    return results

def check_zone_transfer(domain, nameservers=None):
    _sep('Zone Transfer Check')
    vulnerable = []

    if not HAS_DNSPYTHON:
        print(f"  {warning} dnspython required for zone transfer check")
        return vulnerable

    resolver = _make_resolver()
    ns_list  = nameservers or []

    if not ns_list:
        try:
            ans = resolver.resolve(domain, 'NS')
            ns_list = [str(r).rstrip('.') for r in ans]
        except Exception as e:
            print(f"  {err} Could not get NS records: {e}")
            return vulnerable

    for ns in ns_list:
        print(f"  {star} Trying AXFR on {LY}{ns}{N}...", end=' ', flush=True)
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8))
            names = [str(n) for n in z.nodes.keys()]
            print(f"{LR}VULNERABLE!{N} ({len(names)} records leaked)")
            vulnerable.append({'ns': ns, 'ns_ip': ns_ip, 'records': names[:50]})
        except dns.exception.FormError:
            print(f"{LG}refused{N}")
        except Exception as e:
            msg = str(e)[:50]
            if 'refused' in msg.lower() or 'timed out' in msg.lower():
                print(f"{LG}refused/timeout{N}")
            else:
                print(f"{DG}{msg}{N}")

    if not vulnerable:
        print(f"  {sukses} {LG}No zone transfer vulnerability found{N}")
    return vulnerable

def reverse_lookup(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return None

def reverse_lookup_all(domain, a_records):
    _sep('Reverse DNS Lookup')
    results = {}
    for ip in a_records:
        hostname = reverse_lookup(ip)
        if hostname:
            print(f"  {sukses} {LY}{ip}{N} → {LG}{hostname}{N}")
            results[ip] = hostname
        else:
            print(f"  {DG}{ip}{N} → {DG}(no PTR record){N}")
            results[ip] = None
    return results

def enum_subdomains(domain, wordlist=None, threads=30, resolvers=None):
    _sep('Subdomain Enumeration')
    words   = wordlist or SUBDOMAIN_WORDLIST
    found   = {}
    total   = len(words)
    counter = [0]

    def _check(sub):
        fqdn = f"{sub}.{domain}"
        counter[0] += 1
        try:
            if HAS_DNSPYTHON:
                r = _make_resolver(resolvers)
                ans = r.resolve(fqdn, 'A', raise_on_no_answer=False)
                ips = [str(a) for a in ans]
            else:
                info = socket.getaddrinfo(fqdn, None)
                ips  = list({r[4][0] for r in info})
            if ips:
                return fqdn, ips
        except Exception:
            pass
        return None, None

    print(f"  {note} Testing {LY}{total}{N} subdomains on {LC}{domain}{N}...")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check, w): w for w in words}
        for future in as_completed(futures):
            fqdn, ips = future.result()
            if fqdn:
                print(f"  {sukses} {LG}{fqdn}{N} → {LY}{', '.join(ips)}{N}")
                found[fqdn] = ips

    print(f"\n  {note} Found {LG}{len(found)}{N} subdomains out of {total} checked")
    return found

def check_email_security(domain, results):
    _sep('Email Security')
    issues = []

    spf = results.get('SPF', [])
    if not spf:
        print(f"  {warn} {LR}SPF record missing{N} — domain may be used for spoofing")
        issues.append('No SPF record')
    else:
        print(f"  {sukses} {LG}SPF found{N}: {DG}{spf[0][:80]}{N}")
        if '-all' in spf[0]:
            print(f"       {LG}Policy: HARD FAIL (-all) ✓{N}")
        elif '~all' in spf[0]:
            print(f"       {LY}Policy: SOFT FAIL (~all) — consider -all{N}")
        elif '?all' in spf[0]:
            print(f"       {LR}Policy: NEUTRAL (?all) — weak protection{N}")

    dmarc = results.get('DMARC', [])
    if not dmarc:
        print(f"  {warn} {LR}DMARC record missing{N} — no email authentication policy")
        issues.append('No DMARC record')
    else:
        print(f"  {sukses} {LG}DMARC found{N}: {DG}{dmarc[0][:80]}{N}")
        if 'p=reject' in dmarc[0]:
            print(f"       {LG}Policy: reject ✓{N}")
        elif 'p=quarantine' in dmarc[0]:
            print(f"       {LY}Policy: quarantine — consider p=reject{N}")
        elif 'p=none' in dmarc[0]:
            print(f"       {LR}Policy: none — monitoring only, no enforcement{N}")
            issues.append('DMARC policy=none (no enforcement)')

    mx = results.get('MX', [])
    if mx:
        print(f"  {info} MX records found — DKIM check requires selector knowledge")

    return issues

def check_dnssec(domain):
    _sep('DNSSEC Check')
    if not HAS_DNSPYTHON:
        print(f"  {warning} dnspython required for DNSSEC check")
        return False
    try:
        resolver = _make_resolver()
        ans = resolver.resolve(domain, 'DNSKEY', raise_on_no_answer=False)
        keys = [str(k) for k in ans]
        if keys:
            print(f"  {sukses} {LG}DNSSEC enabled{N} ({len(keys)} key(s))")
            return True
        else:
            print(f"  {warn} {LY}DNSSEC not configured{N}")
            return False
    except Exception:
        print(f"  {warn} {LY}DNSSEC not configured or not detectable{N}")
        return False

def print_dns_results(domain, results):
    _sep('DNS Records')
    if results.get('_nxdomain'):
        print(f"  {err} Domain does not exist (NXDOMAIN)")
        return
    if '_error' in results:
        print(f"  {err} {results['_error']}")
        return
    for rtype in ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA', 'SPF', 'DMARC']:
        if rtype in results:
            print(f"\n  {LC}{rtype}{N} Records:")
            for val in results[rtype]:
                print(f"    {sukses} {W}{val}{N}")

def main():
    print(logo)
    parser = argparse.ArgumentParser(description=LY + "Merlin — DNS Deep Lookup & Recon")
    parser.add_argument('-d', '--domain',      required=True)
    parser.add_argument('-r', '--resolvers',   default=DNS_RESOLVERS)
    parser.add_argument('--zone-transfer',     action='store_true', help='Try AXFR zone transfer')
    parser.add_argument('--subdomains',        action='store_true', help='Enumerate subdomains')
    parser.add_argument('--reverse',           action='store_true', help='Reverse DNS lookup on A records')
    parser.add_argument('--email-security',    action='store_true', help='Check SPF/DMARC')
    parser.add_argument('--dnssec',            action='store_true', help='Check DNSSEC')
    parser.add_argument('--all',               action='store_true', help='Run all checks')
    parser.add_argument('--threads',           type=int, default=30)
    parser.add_argument('-o', '--output',      dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    domain    = args.domain.strip().lower()
    resolvers = [r.strip() for r in args.resolvers.split(',')]
    run_all   = args.all

    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}DNS Recon{N} → {LC}{domain}{N}")
    print(f"{LY}{'═'*65}{N}")

    report   = {"domain": domain}
    dns_data = full_dns_lookup(domain, resolvers)
    print_dns_results(domain, dns_data)
    report['dns_records'] = dns_data

    if args.zone_transfer or run_all:
        ns_list = [r.rstrip('.') for r in dns_data.get('NS', [])]
        zt = check_zone_transfer(domain, ns_list)
        report['zone_transfer'] = zt

    if (args.reverse or run_all) and 'A' in dns_data:
        rdns = reverse_lookup_all(domain, dns_data['A'])
        report['reverse_dns'] = rdns

    if args.subdomains or run_all:
        subs = enum_subdomains(domain, threads=args.threads, resolvers=resolvers)
        report['subdomains'] = subs

    if args.email_security or run_all:
        issues = check_email_security(domain, dns_data)
        report['email_security_issues'] = issues

    if args.dnssec or run_all:
        dnssec = check_dnssec(domain)
        report['dnssec'] = dnssec

    if SAVE_REPORTS:
        os.makedirs(args.output_dir, exist_ok=True)
        fname = os.path.join(args.output_dir, f"dns_{domain.replace('.','_')}.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"\n{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    main()
