import argparse
import socket
import json
import os
import sys
import re
import time
from datetime import datetime, timezone
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR, SAVE_REPORTS

try:
    import whois as pythonwhois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

WHOIS_SERVERS = {
    'com':'whois.verisign-grs.com', 'net':'whois.verisign-grs.com',
    'org':'whois.pir.org',          'io':'whois.nic.io',
    'id':'whois.id',                'co':'whois.nic.co',
    'info':'whois.afilias.net',     'biz':'whois.neulevel.biz',
    'us':'whois.nic.us',            'uk':'whois.nic.uk',
    'de':'whois.denic.de',          'fr':'whois.afnic.fr',
    'nl':'whois.domain-registry.nl','au':'whois.auda.org.au',
    'ca':'whois.cira.ca',           'jp':'whois.jprs.jp',
    'cn':'whois.cnnic.cn',          'ru':'whois.tcinet.ru',
    'br':'whois.registro.br',       'in':'whois.registry.in',
    'sg':'whois.sgnic.sg',          'my':'whois.mynic.my',
    'ph':'whois.dot.ph',            'th':'whois.thnic.co.th',
    'vn':'whois.vnnic.vn',          'app':'whois.nic.google',
    'dev':'whois.nic.google',       'xyz':'whois.nic.xyz',
    'online':'whois.nic.online',    'store':'whois.nic.store',
    'tech':'whois.nic.tech',        'site':'whois.nic.site',
    'web':'whois.nic.web',          'club':'whois.nic.club',
    'live':'whois.nic.live',        'news':'whois.nic.news',
    'shop':'whois.nic.shop',        'blog':'whois.nic.blog',
}

def _raw_whois(domain, server=None):
    tld = domain.split('.')[-1].lower()
    if not server:
        server = WHOIS_SERVERS.get(tld, f'whois.nic.{tld}')
    try:
        with socket.create_connection((server, 43), timeout=12) as s:
            s.sendall((domain + '\r\n').encode())
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return b''.join(chunks).decode(errors='replace')
    except Exception as e:
        return f"WHOIS socket error ({server}): {e}"

def _parse_raw(raw):
    parsed = {}
    patterns = {
        'registrar':        r'(?:Registrar|Sponsoring Registrar):\s*(.+)',
        'registrar_url':    r'Registrar URL:\s*(.+)',
        'registrar_abuse_email': r'Registrar Abuse Contact Email:\s*(.+)',
        'registrar_abuse_phone': r'Registrar Abuse Contact Phone:\s*(.+)',
        'whois_server':     r'WHOIS Server:\s*(.+)',
        'creation_date':    r'(?:Creation Date|Created|Domain Registration Date):\s*(.+)',
        'expiration_date':  r'(?:Expir(?:y|ation) Date|Registry Expiry Date|Registrar Registration Expiration Date):\s*(.+)',
        'updated_date':     r'(?:Updated Date|Last Modified|Last Updated):\s*(.+)',
        'status':           r'Domain Status:\s*(.+)',
        'name_servers':     r'Name Server:\s*(.+)',
        'dnssec':           r'DNSSEC:\s*(.+)',
        'registrant_name':  r'Registrant Name:\s*(.+)',
        'registrant_org':   r'Registrant Organization:\s*(.+)',
        'registrant_email': r'Registrant Email:\s*(.+)',
        'registrant_country':r'Registrant Country:\s*(.+)',
        'admin_email':      r'Admin Email:\s*(.+)',
        'tech_email':       r'Tech Email:\s*(.+)',
    }
    for key, pat in patterns.items():
        matches = re.findall(pat, raw, re.IGNORECASE)
        if matches:
            cleaned = [m.strip() for m in matches if m.strip()]
            parsed[key] = cleaned[0] if len(cleaned) == 1 else cleaned
    return parsed

def _analyze_expiry(expiry_str):
    if not expiry_str:
        return None, None
    formats = [
        '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d', '%d-%b-%Y',
        '%Y-%m-%dT%H:%M:%S', '%Y/%m/%d',
        '%d/%m/%Y', '%B %d, %Y',
    ]
    s = re.sub(r'\s*\(.*?\)', '', str(expiry_str)).strip()
    dt = None
    for fmt in formats:
        try:
            dt = datetime.strptime(s[:len(fmt)+2].strip(), fmt)
            break
        except Exception:
            pass
    if not dt:
        return None, str(expiry_str)

    now  = datetime.now()
    diff = dt - now
    days = diff.days
    return days, dt.strftime('%Y-%m-%d')

def _expiry_status(days):
    if days is None:
        return DG + 'unknown' + N
    if days < 0:
        return LR + f'EXPIRED {abs(days)} days ago!' + N
    if days <= 14:
        return LR + f'CRITICAL: expires in {days} days!' + N
    if days <= 30:
        return LR + f'WARNING: expires in {days} days' + N
    if days <= 90:
        return LY + f'expiring in {days} days' + N
    return LG + f'{days} days remaining' + N

def _check_privacy(parsed):
    issues = []
    privacy_keywords = ['privacy', 'redacted', 'withheld', 'protected',
                        'whoisguard', 'domains by proxy', 'contactprivacy']
    for key in ['registrant_name', 'registrant_email', 'registrant_org']:
        val = parsed.get(key, '')
        if isinstance(val, list):
            val = ' '.join(val)
        if any(kw in val.lower() for kw in privacy_keywords):
            issues.append(f'WHOIS privacy active on {key}')
    return issues

EPPDOMAIN_STATUS = {
    'clientTransferProhibited': 'Transfer locked by registrar',
    'clientUpdateProhibited':   'Updates locked by registrar',
    'clientDeleteProhibited':   'Deletion locked by registrar',
    'serverTransferProhibited': 'Transfer locked by registry',
    'serverUpdateProhibited':   'Updates locked by registry',
    'serverDeleteProhibited':   'Deletion locked by registry',
    'clientHold':               'Domain on hold (may be suspended)',
    'serverHold':               'Domain on hold by registry',
    'inactive':                 'Domain inactive / no nameservers',
    'pendingDelete':            'Domain pending deletion',
    'pendingTransfer':          'Transfer in progress',
    'ok':                       'Active and in good standing',
}

def do_whois(domain):
    parsed = {}
    raw    = ''
    error  = None

    if HAS_WHOIS:
        try:
            w = pythonwhois.whois(domain)
            fields = [
                'domain_name', 'registrar', 'whois_server', 'referral_url',
                'updated_date', 'creation_date', 'expiration_date',
                'name_servers', 'status', 'emails', 'dnssec',
                'org', 'country', 'state', 'city', 'address',
                'registrant_name', 'admin_email', 'tech_email',
            ]
            for field in fields:
                val = getattr(w, field, None)
                if val:
                    if isinstance(val, list):
                        val = [str(v) for v in val if v]
                    else:
                        val = str(val)
                    parsed[field] = val
        except Exception as e:
            error = str(e)

    raw = _raw_whois(domain)
    raw_parsed = _parse_raw(raw)
    for k, v in raw_parsed.items():
        if k not in parsed:
            parsed[k] = v

    return parsed, raw, error

def _sep(title=''):
    print(f"\n{LY}{'─'*20} {W}{title} {LY}{'─'*20}{N}" if title else f"{LY}{'─'*65}{N}")

def print_whois(domain, parsed, raw, error):
    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}WHOIS Report for{N} {LG}{domain}{N}")
    print(f"{LY}{'═'*65}{N}")

    if error:
        print(f"  {warn} Parser error: {DG}{error}{N} (raw data used)")

    expiry_str = parsed.get('expiration_date') or parsed.get('expiry_date')
    if isinstance(expiry_str, list):
        expiry_str = expiry_str[0]
    days, expiry_fmt = _analyze_expiry(expiry_str)
    _sep('Registration Info')
    print(f"  {LC}Registrar         {N}: {W}{parsed.get('registrar', DG+'(unknown)'+N)}{N}")
    print(f"  {LC}Registrar URL     {N}: {LB}{parsed.get('registrar_url', DG+'(unknown)'+N)}{N}")
    print(f"  {LC}WHOIS Server      {N}: {W}{parsed.get('whois_server', DG+'(unknown)'+N)}{N}")
    print(f"  {LC}Created           {N}: {LY}{parsed.get('creation_date', DG+'(unknown)'+N)}{N}")
    print(f"  {LC}Updated           {N}: {LY}{parsed.get('updated_date', DG+'(unknown)'+N)}{N}")
    print(f"  {LC}Expiry            {N}: {LY}{expiry_fmt or expiry_str or DG+'(unknown)'+N}{N}")
    print(f"  {LC}Expiry Status     {N}: {_expiry_status(days)}")

    _sep('Registrant')
    print(f"  {LC}Name    {N}: {W}{parsed.get('registrant_name', DG+'(redacted/unknown)'+N)}{N}")
    print(f"  {LC}Org     {N}: {W}{parsed.get('registrant_org', parsed.get('org', DG+'(unknown)'+N))}{N}")
    print(f"  {LC}Email   {N}: {W}{parsed.get('registrant_email', parsed.get('emails', DG+'(unknown)'+N))}{N}")
    print(f"  {LC}Country {N}: {W}{parsed.get('registrant_country', parsed.get('country', DG+'(unknown)'+N))}{N}")

    privacy = _check_privacy(parsed)
    if privacy:
        for p in privacy:
            print(f"  {info} {LM}{p}{N}")

    _sep('Abuse / Contact')
    print(f"  {LC}Abuse Email {N}: {LR}{parsed.get('registrar_abuse_email', DG+'(not found)'+N)}{N}")
    print(f"  {LC}Abuse Phone {N}: {LR}{parsed.get('registrar_abuse_phone', DG+'(not found)'+N)}{N}")
    print(f"  {LC}Admin Email {N}: {W}{parsed.get('admin_email', DG+'(unknown)'+N)}{N}")
    print(f"  {LC}Tech  Email {N}: {W}{parsed.get('tech_email', DG+'(unknown)'+N)}{N}")

    ns = parsed.get('name_servers', [])
    if ns:
        _sep('Name Servers')
        for n in (ns if isinstance(ns, list) else [ns]):
            print(f"  {sukses} {LG}{n}{N}")

    status = parsed.get('status', [])
    if status:
        _sep('Domain Status')
        for s in (status if isinstance(status, list) else [status]):
            code = s.split()[0].lower() if s else ''
            desc = EPPDOMAIN_STATUS.get(code, '')
            color = LG if code == 'ok' else LY if 'prohibited' in code else LR if 'hold' in code or 'pending' in code else W
            print(f"  {star} {color}{s[:60]}{N}")
            if desc:
                print(f"       {DG}→ {desc}{N}")

    dnssec = parsed.get('dnssec', '')
    if dnssec:
        _sep('DNSSEC')
        color = LG if 'signed' in str(dnssec).lower() else LY
        print(f"  {star} {color}{dnssec}{N}")

    print(f"\n{LY}{'═'*65}{N}")

def main():
    print(logo)
    parser = argparse.ArgumentParser(description=LY + "Merlin — WHOIS Deep Lookup")
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('--show-raw',     action='store_true', help='Print raw WHOIS response')
    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if not HAS_WHOIS:
        print(f"{warning} python-whois not installed, using raw socket WHOIS")
        print(f"{note} pip install python-whois --break-system-packages")

    parsed, raw, error = do_whois(domain)
    print_whois(domain, parsed, raw, error)

    if args.show_raw:
        print(f"\n{LY}{'─'*20} RAW WHOIS {'─'*20}{N}")
        print(DG + raw[:3000] + N)

    if SAVE_REPORTS:
        os.makedirs(args.output_dir, exist_ok=True)
        fname = os.path.join(args.output_dir, f"whois_{domain.replace('.','_')}.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump({"domain": domain, "parsed": parsed, "raw_snippet": raw[:2000]},
                      f, indent=4, ensure_ascii=False)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    main()
