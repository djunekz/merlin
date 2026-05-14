import requests
import argparse
import logging
import sys
import re
import json
import os
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from merlinset import *
from merlinlogo import *
from merlinconf import TIMEOUT, USER_AGENT, OUTPUT_DIR, SAVE_REPORTS, VERIFY_SSL

logging.basicConfig(level=logging.INFO,
    format=LC+'['+W+'%(asctime)s'+LC+']'+LG+' %(message)s', datefmt='%H:%M:%S')

def _sep(title=''):
    print(f"\n{LY}{'─'*20} {W}{title} {LY}{'─'*20}{N}" if title else f"{LY}{'─'*65}{N}")

def validate_url(url):
    p = urlparse(url)
    return all([p.scheme, p.netloc])

def _session():
    s = requests.Session()
    s.verify = VERIFY_SSL
    s.headers.update({
        'User-Agent':      USER_AGENT,
        'Accept':          'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    })
    return s

def check_headers(session, url, report):
    _sep('Security Headers')
    try:
        r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        h = r.headers
        checks = {
            'Strict-Transport-Security': (None,              'HSTS protection',             'HIGH'),
            'Content-Security-Policy':   (None,              'XSS / injection protection',  'HIGH'),
            'X-Frame-Options':           (('DENY','SAMEORIGIN'), 'Clickjacking protection', 'HIGH'),
            'X-Content-Type-Options':    ('nosniff',         'MIME sniff protection',        'MEDIUM'),
            'Referrer-Policy':           (None,              'Referrer leakage',             'LOW'),
            'Permissions-Policy':        (None,              'Browser API restrictions',     'LOW'),
            'X-XSS-Protection':          (None,              'Legacy XSS filter',            'LOW'),
        }
        found = {}
        for header, (expected, desc, sev) in checks.items():
            present = header in h
            val     = h.get(header, '')
            ok = present and (expected is None or
                 (isinstance(expected, tuple) and val in expected) or val == expected)
            col = LG if ok else (LR if sev == 'HIGH' else LY)
            mark = sukses if ok else err
            print(f"  {mark} {col}{'OK' if ok else 'MISSING ['+sev+']'}{N}  {LC}{header}{N}")
            if present:
                print(f"       {DG}↳ {val[:80]}{N}")
            else:
                print(f"       {DG}↳ {desc}{N}")
            found[header] = {'present': present, 'value': val, 'ok': ok, 'severity': sev}

        leak = ['Server','X-Powered-By','X-AspNet-Version','X-Generator','X-Runtime']
        lk   = {}
        for lh in leak:
            if lh in h:
                print(f"  {warn} {LY}INFO LEAK{N}  {LC}{lh}{N}: {W}{h[lh]}{N}")
                lk[lh] = h[lh]
        report['headers'] = found
        report['leak_headers'] = lk
    except Exception as e:
        print(f"  {err} {e}")

def check_ssl(session, url, report):
    _sep('SSL / TLS')
    if not url.startswith('https://'):
        print(f"  {err} {LR}Site not using HTTPS — plaintext traffic!{N}")
        report['ssl'] = {'https': False}
        return
    try:
        r = session.get(url, timeout=TIMEOUT)
        print(f"  {sukses} {LG}HTTPS connection OK — Status {r.status_code}{N}")
        http_url = url.replace('https://', 'http://', 1)
        r2 = requests.get(http_url, timeout=8, allow_redirects=True, verify=False)
        if r2.url.startswith('https://'):
            print(f"  {sukses} {LG}HTTP→HTTPS redirect active{N}")
            report['ssl'] = {'https': True, 'redirect': True}
        else:
            print(f"  {warn} {LY}HTTP→HTTPS redirect NOT detected{N}")
            report['ssl'] = {'https': True, 'redirect': False}
    except requests.exceptions.SSLError as e:
        print(f"  {err} {LR}SSL Error: {e}{N}")
        report['ssl'] = {'https': True, 'ssl_error': str(e)}
    except Exception as e:
        print(f"  {warn} {e}")

def check_robots(session, base_url, report):
    _sep('robots.txt')
    url = urljoin(base_url, '/robots.txt')
    try:
        r = session.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            disallows = re.findall(r'Disallow:\s*(\S+)', r.text, re.I)
            sitemaps  = re.findall(r'Sitemap:\s*(\S+)',  r.text, re.I)
            print(f"  {sukses} {LG}Found{N} — {len(disallows)} Disallow, {len(sitemaps)} Sitemap entries")
            for d in disallows[:10]:
                col = LR if any(x in d.lower() for x in ['admin','backup','config','db','.env']) else LY
                print(f"       {col}Disallow: {d}{N}")
            for s in sitemaps:
                print(f"       {LC}Sitemap : {s}{N}")
            report['robots'] = {'found': True, 'disallows': disallows, 'sitemaps': sitemaps}
        else:
            print(f"  {info} robots.txt returned {r.status_code}")
            report['robots'] = {'found': False}
    except Exception as e:
        print(f"  {warn} {e}")

def check_sitemap(session, base_url, report):
    _sep('sitemap.xml')
    for path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemap/sitemap.xml']:
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=TIMEOUT)
            if r.status_code == 200 and ('<?xml' in r.text or '<urlset' in r.text):
                urls_in = re.findall(r'<loc>(.*?)</loc>', r.text)
                print(f"  {sukses} {LG}Found{N} at {path} — {len(urls_in)} URLs")
                report['sitemap'] = {'found': True, 'path': path, 'url_count': len(urls_in)}
                return
        except Exception:
            pass
    print(f"  {info} No sitemap.xml found")
    report['sitemap'] = {'found': False}

def check_directory_listing(session, base_url, report):
    _sep('Directory Listing')
    paths = ['/admin/', '/uploads/', '/backup/', '/test/', '/config/',
             '/logs/', '/.git/', '/wp-content/', '/tmp/', '/private/',
             '/files/', '/data/', '/includes/', '/db/', '/sql/']
    found = []
    for path in paths:
        try:
            r = session.get(urljoin(base_url, path), timeout=6)
            if r.status_code == 200 and ('Index of' in r.text or 'Directory listing' in r.text):
                print(f"  {err} {LR}OPEN listing{N}: {path}")
                found.append(path)
            elif r.status_code == 403:
                print(f"  {sukses} {LG}403 Forbidden{N}: {path}")
            elif r.status_code == 200:
                print(f"  {warn} {LY}200 (no listing detected){N}: {path}")
        except Exception:
            pass
    if not found:
        print(f"  {sukses} {LG}No open directory listings detected{N}")
    report['directory_listing'] = found

def check_cors(session, url, report):
    _sep('CORS Policy')
    try:
        r = session.get(url, timeout=TIMEOUT,
                        headers={'Origin': 'https://evil.com'})
        acao  = r.headers.get('Access-Control-Allow-Origin', '')
        acac  = r.headers.get('Access-Control-Allow-Credentials', '')
        acam  = r.headers.get('Access-Control-Allow-Methods', '')
        issues = []
        if acao == '*':
            print(f"  {err} {LR}Wildcard CORS (*) — any origin allowed{N}")
            issues.append('wildcard')
        elif 'evil.com' in acao:
            print(f"  {err} {LR}CORS reflects arbitrary origin!{N}")
            issues.append('reflects-origin')
        elif acao:
            print(f"  {info} ACAO: {acao}")
        else:
            print(f"  {sukses} {LG}No permissive CORS header{N}")
        if acac.lower() == 'true' and acao == '*':
            print(f"  {err} {LR}CORS wildcard + credentials=true — critical!{N}")
            issues.append('credentials-wildcard')
        report['cors'] = {'acao': acao, 'acac': acac, 'acam': acam, 'issues': issues}
    except Exception as e:
        print(f"  {warn} {e}")

def check_cookies(session, url, report):
    _sep('Cookie Security')
    try:
        r = session.get(url, timeout=TIMEOUT)
        issues = []
        if not r.cookies:
            print(f"  {info} No cookies in response")
            report['cookies'] = []
            return
        for c in r.cookies:
            flags_ok   = []
            flags_miss = []
            if c.secure:                          flags_ok.append('Secure')
            else:                                 flags_miss.append('Secure')
            if c.has_nonstandard_attr('HttpOnly'):flags_ok.append('HttpOnly')
            else:                                 flags_miss.append('HttpOnly')
            if c.has_nonstandard_attr('SameSite'):flags_ok.append('SameSite')
            else:                                 flags_miss.append('SameSite')
            ok_str   = LG  + ' '.join(flags_ok)   + N if flags_ok   else ''
            miss_str = LR  + '⚠missing:' + ','.join(flags_miss) + N if flags_miss else ''
            print(f"  {star} {W}{c.name}{N}  {ok_str}  {miss_str}")
            if flags_miss:
                issues.append({'cookie': c.name, 'missing': flags_miss})
        report['cookies'] = issues
    except Exception as e:
        print(f"  {warn} {e}")

def check_open_redirect(session, url, report):
    _sep('Open Redirect')
    params   = ['redirect','next','url','return','goto','target','dest','redir','continue']
    payloads = ['//evil.com', 'https://evil.com', '///evil.com']
    found    = []
    base     = url.split('?')[0]
    for param in params:
        for payload in payloads:
            test = f"{base}?{param}={payload}"
            try:
                r = session.get(test, timeout=5, allow_redirects=False)
                loc = r.headers.get('Location', '')
                if 'evil.com' in loc:
                    print(f"  {err} {LR}Open Redirect!{N} param={LY}{param}{N} → {loc}")
                    found.append({'param': param, 'payload': payload, 'location': loc})
                time.sleep(0.1)
            except Exception:
                pass
    if not found:
        print(f"  {sukses} {LG}No open redirect detected{N}")
    report['open_redirect'] = found

def check_sensitive_data(session, url, report):
    _sep('Sensitive Data in Source')
    SECRET_PATTERNS = {
        'AWS Access Key':    r'AKIA[0-9A-Z]{16}',
        'Google API Key':    r'AIza[0-9A-Za-z\-_]{35}',
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24,}',
        'GitHub Token':      r'ghp_[A-Za-z0-9]{36}',
        'Private Key':       r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'Password in HTML':  r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
        'DB Connection':     r'(?i)(mysql|postgres|mongodb|redis):\/\/[^\s"\'<>]{8,}',
        'JWT Token':         r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'Basic Auth in URL': r'https?://[^:@\s]+:[^@\s]+@',
        'Slack Token':       r'xox[baprs]-[0-9A-Za-z]{10,48}',
        'SendGrid API Key':  r'SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}',
        'Firebase URL':      r'https?://[a-z0-9-]+\.firebaseio\.com',
        'Internal IP':       r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+',
        'TODO/FIXME secret': r'(?i)(todo|fixme|hack|xxx|secret|password|key)\s*[:=]\s*\S+',
    }
    try:
        r    = session.get(url, timeout=TIMEOUT)
        body = r.text
        found = []
        for label, pattern in SECRET_PATTERNS.items():
            for match in re.findall(pattern, body):
                snippet = match if isinstance(match, str) else ' '.join(match)
                if len(snippet) > 6:
                    print(f"  {err} {LR}{label}{N}: {DG}{snippet[:70]}{N}")
                    found.append({'type': label, 'snippet': snippet[:80]})
        if not found:
            print(f"  {sukses} {LG}No obvious secrets detected in page source{N}")
        report['sensitive_data'] = found
    except Exception as e:
        print(f"  {warn} {e}")

def check_broken_access(session, url, report):
    _sep('Broken Access Control')
    admin_paths = [
        '/admin', '/admin/', '/admin/login', '/admin/dashboard',
        '/wp-admin/', '/administrator/', '/phpmyadmin/',
        '/cpanel/', '/panel/', '/dashboard/',
        '/api/admin', '/api/users', '/api/config',
        '/private/', '/internal/', '/manage/',
        '/superuser/', '/sysadmin/', '/backoffice/',
        '.env', '/config.php', '/settings.php',
    ]
    found = []
    for path in admin_paths:
        test_url = urljoin(url, path)
        try:
            r = session.get(test_url, timeout=5, allow_redirects=True)
            if r.status_code == 200:
                has_form  = '<form' in r.text.lower()
                has_admin = any(x in r.text.lower() for x in
                                ['dashboard','logout','admin panel','manage users'])
                if has_form or has_admin:
                    print(f"  {warn} {LY}Accessible (200){N}: {path} — may require auth check")
                    found.append({'path': path, 'status': 200, 'has_form': has_form})
                else:
                    print(f"  {info} {DG}200 (no admin marker){N}: {path}")
            elif r.status_code == 403:
                print(f"  {sukses} {LG}403 Forbidden{N}: {path}")
            elif r.status_code == 401:
                print(f"  {sukses} {LG}401 Unauthorized{N}: {path}")
            elif r.status_code not in (404, 410):
                print(f"  {info} {DG}{r.status_code}{N}: {path}")
            time.sleep(0.15)
        except Exception:
            pass
    if not found:
        print(f"  {sukses} {LG}No obviously accessible admin paths{N}")
    report['broken_access'] = found

def check_waf(session, url, report):
    _sep('WAF Detection')
    WAF_SIGS = {
        'Cloudflare':   {'header': [r'cf-ray', r'server: cloudflare'], 'body': [r'cloudflare'], 'cookie': [r'cf_clearance',r'__cfduid']},
        'Sucuri':       {'header': [r'x-sucuri-id',r'x-sucuri-cache'], 'body': [r'sucuri'],     'cookie': []},
        'Imperva':      {'header': [r'x-iinfo'],                        'body': [r'incapsula'],  'cookie': [r'incap_ses',r'visid_incap']},
        'ModSecurity':  {'header': [r'mod_security',r'NOYB'],           'body': [r'mod_security',r'not acceptable'], 'cookie': []},
        'AWS WAF':      {'header': [r'x-amzn-requestid',r'x-amz-cf'],  'body': [],              'cookie': []},
        'Akamai':       {'header': [r'x-check-cacheable',r'akamai'],    'body': [],              'cookie': []},
        'F5 BIG-IP':    {'header': [r'x-cnection',r'bigip'],            'body': [r'BigIP'],      'cookie': [r'BIGipServer']},
        'Barracuda':    {'header': [r'barra_counter_session'],           'body': [r'barracuda'],  'cookie': [r'barra_counter_session']},
        'Wordfence':    {'header': [],                                   'body': [r'wordfence',r'This response was blocked by Wordfence'], 'cookie': []},
        'SiteLock':     {'header': [r'x-sitelock'],                     'body': [r'sitelock'],   'cookie': []},
    }
    try:
        probe_url = url + ('&' if '?' in url else '?') + "id=1'+OR+'1'='1"
        r = session.get(probe_url, timeout=TIMEOUT)
        headers_str = ' '.join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_lower  = r.text.lower()
        cookies_str = ' '.join(c.name for c in r.cookies).lower()

        detected = []
        for waf, sigs in WAF_SIGS.items():
            for pat in sigs.get('header', []):
                if re.search(pat, headers_str, re.I):
                    detected.append(waf); break
            if waf not in detected:
                for pat in sigs.get('body', []):
                    if re.search(pat, body_lower, re.I):
                        detected.append(waf); break
            if waf not in detected:
                for pat in sigs.get('cookie', []):
                    if re.search(pat, cookies_str, re.I):
                        detected.append(waf); break

        if detected:
            for w in detected:
                print(f"  {sukses} {LG}WAF detected: {w}{N}")
        else:
            if r.status_code in (403, 406, 429, 503):
                print(f"  {warn} {LY}Possible WAF (status {r.status_code}) but unidentified{N}")
            else:
                print(f"  {info} No WAF signature detected")
        report['waf'] = detected
    except Exception as e:
        print(f"  {warn} {e}")

def check_mixed_content(session, url, report):
    _sep('Mixed Content Check')
    if not url.startswith('https://'):
        print(f"  {info} Not HTTPS — mixed content not applicable")
        report['mixed_content'] = []
        return
    try:
        r    = session.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        mixed = []
        for tag, attr in [('img','src'),('script','src'),('link','href'),
                          ('iframe','src'),('video','src'),('audio','src')]:
            for el in soup.find_all(tag):
                val = el.get(attr, '')
                if val.startswith('http://'):
                    mixed.append({'tag': tag, 'url': val[:120]})
                    print(f"  {warn} {LY}Mixed content{N}: <{tag}> {val[:80]}")
        if not mixed:
            print(f"  {sukses} {LG}No mixed content detected{N}")
        report['mixed_content'] = mixed
    except Exception as e:
        print(f"  {warn} {e}")

def check_sri(session, url, report):
    _sep('Subresource Integrity (SRI)')
    try:
        r    = session.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        missing = []
        for tag, attr in [('script','src'),('link','href')]:
            for el in soup.find_all(tag):
                src = el.get(attr, '')
                if src.startswith('http') and not el.get('integrity'):
                    missing.append({'tag': tag, 'src': src[:100]})
                    print(f"  {warn} {LY}No SRI{N}: <{tag} {attr}=\"{src[:60]}\">{N}")
        if not missing:
            print(f"  {sukses} {LG}All external resources have SRI or none found{N}")
        report['sri_missing'] = missing
    except Exception as e:
        print(f"  {warn} {e}")

def main():
    print(logo)
    parser = argparse.ArgumentParser(description=LG + "Merlin — Web Analyst (Full Suite)")
    parser.add_argument('-u', '--url',          required=True)
    parser.add_argument('-n', '--no-ssl-verify', action='store_true')
    parser.add_argument('-o', '--output',        dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    url = args.url
    if not validate_url(url):
        print(f"{err} Invalid URL — use http:// or https://")
        sys.exit(1)

    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}Web Analyst — Full Suite{N}")
    print(f"{note} Target: {LC}{url}{N}")
    print(f"{LY}{'═'*65}{N}")

    session         = _session()
    session.verify  = not args.no_ssl_verify
    report          = {"target": url}

    try:
        r = session.get(url, timeout=TIMEOUT + 5)
        print(f"{sukses} Reachable — HTTP {r.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"{err} Cannot connect to {url}")
        sys.exit(1)
    except Exception as e:
        print(f"{err} {e}")
        sys.exit(1)

    checks = [
        ("SSL / TLS",            lambda: check_ssl(session, url, report)),
        ("Security Headers",     lambda: check_headers(session, url, report)),
        ("robots.txt",           lambda: check_robots(session, url, report)),
        ("sitemap.xml",          lambda: check_sitemap(session, url, report)),
        ("Directory Listing",    lambda: check_directory_listing(session, url, report)),
        ("CORS Policy",          lambda: check_cors(session, url, report)),
        ("Cookie Security",      lambda: check_cookies(session, url, report)),
        ("Open Redirect",        lambda: check_open_redirect(session, url, report)),
        ("Sensitive Data",       lambda: check_sensitive_data(session, url, report)),
        ("Broken Access Control",lambda: check_broken_access(session, url, report)),
        ("WAF Detection",        lambda: check_waf(session, url, report)),
        ("Mixed Content",        lambda: check_mixed_content(session, url, report)),
        ("SRI Check",            lambda: check_sri(session, url, report)),
    ]

    for label, fn in checks:
        try:
            fn()
        except KeyboardInterrupt:
            print(f"\n{note} Interrupted by user")
            break
        except Exception as e:
            print(f"  {err} [{label}] error: {e}")

    print(f"\n{LY}{'═'*65}{N}")
    print(f"{sukses} {LG}Analysis complete{N}")
    print(f"{LY}{'═'*65}{N}")

    if SAVE_REPORTS:
        os.makedirs(args.output_dir, exist_ok=True)
        domain = urlparse(url).netloc.replace('.', '_')
        fname  = os.path.join(args.output_dir, f"webanalyst_{domain}.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    main()
