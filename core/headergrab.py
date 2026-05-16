import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import argparse
import signal
import json
import os
import re
import time
from urllib.parse import urlparse
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import TIMEOUT, USER_AGENT, OUTPUT_DIR, SAVE_REPORTS, VERIFY_SSL

SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'weight': 10, 'severity': 'HIGH',
        'desc':   'Enforces HTTPS and prevents downgrade attacks (HSTS)',
        'ideal':  'max-age=31536000; includeSubDomains; preload',
        'check':  lambda v: 'max-age' in v.lower(),
    },
    'Content-Security-Policy': {
        'weight': 10, 'severity': 'HIGH',
        'desc':   'Prevents XSS and data injection attacks',
        'ideal':  "default-src 'self'; script-src 'self'",
        'check':  lambda v: 'default-src' in v.lower() or 'script-src' in v.lower(),
    },
    'X-Frame-Options': {
        'weight': 8, 'severity': 'HIGH',
        'desc':   'Prevents clickjacking attacks',
        'ideal':  'DENY or SAMEORIGIN',
        'check':  lambda v: v.upper() in ('DENY', 'SAMEORIGIN'),
    },
    'X-Content-Type-Options': {
        'weight': 6, 'severity': 'MEDIUM',
        'desc':   'Prevents MIME-type sniffing',
        'ideal':  'nosniff',
        'check':  lambda v: v.lower() == 'nosniff',
    },
    'Referrer-Policy': {
        'weight': 4, 'severity': 'MEDIUM',
        'desc':   'Controls referrer information sent with requests',
        'ideal':  'no-referrer or strict-origin-when-cross-origin',
        'check':  lambda v: any(x in v.lower() for x in
                     ['no-referrer','strict-origin','same-origin','no-referrer-when-downgrade']),
    },
    'Permissions-Policy': {
        'weight': 4, 'severity': 'LOW',
        'desc':   'Restricts browser features (camera, mic, location, etc.)',
        'ideal':  'camera=(), microphone=(), geolocation=()',
        'check':  lambda v: len(v) > 5,
    },
    'X-XSS-Protection': {
        'weight': 2, 'severity': 'LOW',
        'desc':   'Legacy XSS filter for older browsers',
        'ideal':  '1; mode=block',
        'check':  lambda v: '1' in v,
    },
    'Cache-Control': {
        'weight': 2, 'severity': 'INFO',
        'desc':   'Controls caching behavior',
        'ideal':  'no-store, no-cache for sensitive pages',
        'check':  lambda v: len(v) > 0,
    },
    'Cross-Origin-Embedder-Policy': {
        'weight': 3, 'severity': 'LOW',
        'desc':   'Prevents cross-origin resource embedding (COEP)',
        'ideal':  'require-corp',
        'check':  lambda v: 'require-corp' in v.lower(),
    },
    'Cross-Origin-Opener-Policy': {
        'weight': 3, 'severity': 'LOW',
        'desc':   'Isolates browsing context from cross-origin windows (COOP)',
        'ideal':  'same-origin',
        'check':  lambda v: 'same-origin' in v.lower(),
    },
    'Cross-Origin-Resource-Policy': {
        'weight': 3, 'severity': 'LOW',
        'desc':   'Restricts cross-origin resource loading (CORP)',
        'ideal':  'same-origin or same-site',
        'check':  lambda v: any(x in v.lower() for x in ['same-origin', 'same-site']),
    },
}

LEAK_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator',
                'X-Runtime', 'X-Application-Context', 'X-Drupal-Cache',
                'X-WordPress-Cache', 'X-Pingback', 'X-Forwarded-For']

def _calc_grade(score, max_score):
    pct = (score / max_score) * 100 if max_score else 0
    if pct >= 90: return 'A+', LG
    if pct >= 80: return 'A',  LG
    if pct >= 70: return 'B',  LG
    if pct >= 60: return 'C',  LY
    if pct >= 50: return 'D',  LY
    return 'F', LR

def _csp_analysis(csp_value):
    issues = []
    if "unsafe-inline" in csp_value:
        issues.append(("unsafe-inline allows inline scripts — XSS risk", "HIGH"))
    if "unsafe-eval" in csp_value:
        issues.append(("unsafe-eval allows eval() — XSS risk", "HIGH"))
    if "'*'" in csp_value or "http:" in csp_value:
        issues.append(("Wildcard or http: source — too permissive", "MEDIUM"))
    if "report-uri" in csp_value or "report-to" in csp_value:
        issues.append(("CSP reporting configured ✓", "INFO"))
    if not issues:
        issues.append(("CSP looks well-configured", "OK"))
    return issues

def _hsts_analysis(hsts_value):
    issues = []
    m = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
    if m:
        age = int(m.group(1))
        if age < 2592000:
            issues.append((f"max-age={age} is less than 30 days (recommended: 1 year)", "MEDIUM"))
        elif age >= 31536000:
            issues.append((f"max-age={age} — good (≥1 year) ✓", "OK"))
    if 'includesubdomains' not in hsts_value.lower():
        issues.append(("includeSubDomains not set — subdomains may bypass HSTS", "LOW"))
    if 'preload' in hsts_value.lower():
        issues.append(("preload directive present ✓", "OK"))
    return issues

def grab_headers(url, follow_redirects=True):
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})
    results = {}
    try:
        resp = session.get(url, timeout=TIMEOUT, verify=VERIFY_SSL,
                           allow_redirects=follow_redirects)
        results['final_url']      = resp.url
        results['status_code']    = resp.status_code
        results['http_version']   = f"HTTP/{resp.raw.version//10}.{resp.raw.version%10}"
        results['response_time']  = f"{resp.elapsed.total_seconds():.3f}s"
        results['content_type']   = resp.headers.get('Content-Type', 'N/A')
        results['content_length'] = resp.headers.get('Content-Length', 'N/A')
        results['all_headers']    = dict(resp.headers)
        results['redirect_chain'] = [r.url for r in resp.history] + [resp.url]
        results['cookies']        = {c.name: {
            'value':    c.value[:40] + '...' if len(c.value) > 40 else c.value,
            'secure':   c.secure,
            'httponly': c.has_nonstandard_attr('HttpOnly'),
            'samesite': c.has_nonstandard_attr('SameSite'),
            'path':     c.path,
            'domain':   c.domain or '',
        } for c in resp.cookies}

        score     = 0
        max_score = sum(h['weight'] for h in SECURITY_HEADERS.values())
        sec       = {}
        for header, meta in SECURITY_HEADERS.items():
            present = header in resp.headers
            value   = resp.headers.get(header, '')
            ok      = present and meta['check'](value)
            if ok:
                score += meta['weight']
            sec[header] = {
                'present':  present,
                'value':    value,
                'ok':       ok,
                'severity': meta['severity'],
                'desc':     meta['desc'],
                'ideal':    meta['ideal'],
            }
        results['security_headers'] = sec
        results['grade_score']      = score
        results['grade_max']        = max_score

        results['leak_headers'] = {h: resp.headers[h]
                                   for h in LEAK_HEADERS if h in resp.headers}

        if 'Content-Security-Policy' in resp.headers:
            results['csp_analysis'] = _csp_analysis(resp.headers['Content-Security-Policy'])
        if 'Strict-Transport-Security' in resp.headers:
            results['hsts_analysis'] = _hsts_analysis(resp.headers['Strict-Transport-Security'])

        return results, None
    except requests.exceptions.SSLError as e:
        return {}, f"SSL Error: {e}"
    except requests.exceptions.ConnectionError as e:
        return {}, f"Connection Error: {e}"
    except requests.exceptions.Timeout:
        return {}, "Request timed out"
    except Exception as e:
        return {}, str(e)

def _sep(title=''):
    print(f"\n{LY}{'─'*20} {W}{title} {LY}{'─'*20}{N}" if title else f"{LY}{'─'*65}{N}")

def print_report(url, results, error):
    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}HTTP Header Report{N} → {LC}{url}{N}")
    print(f"{LY}{'═'*65}{N}")

    if error:
        print(f"  {err} {error}")
        return

    _sep('Response Info')
    print(f"  {LC}Final URL      {N}: {W}{results['final_url']}{N}")
    sc    = results['status_code']
    scol  = LG if sc == 200 else LY if sc < 400 else LR
    print(f"  {LC}Status Code    {N}: {scol}{sc}{N}")
    print(f"  {LC}HTTP Version   {N}: {W}{results['http_version']}{N}")
    print(f"  {LC}Response Time  {N}: {LY}{results['response_time']}{N}")
    print(f"  {LC}Content-Type   {N}: {W}{results['content_type']}{N}")
    print(f"  {LC}Content-Length {N}: {W}{results['content_length']}{N}")

    if len(results['redirect_chain']) > 1:
        _sep('Redirect Chain')
        for step in results['redirect_chain']:
            print(f"  {star} {DG}{step}{N}")

    _sep('Security Header Grade')
    grade, gcol = _calc_grade(results['grade_score'], results['grade_max'])
    print(f"  {LC}Score {N}: {gcol}{results['grade_score']}/{results['grade_max']}{N}  "
          f"Grade: {gcol}{grade}{N}")
    print(f"  {DG}(Graded like securityheaders.com — A+ to F){N}")

    _sep('Security Headers')
    for header, data in results['security_headers'].items():
        if data['present'] and data['ok']:
            print(f"  {sukses} {LG}OK    {N} {LC}{header}{N}")
            print(f"         {DG}↳ {data['value'][:80]}{N}")
        elif data['present'] and not data['ok']:
            print(f"  {warn} {LY}WEAK  {N} {LC}{header}{N}")
            print(f"         {DG}↳ value: {data['value'][:70]}{N}")
            print(f"         {LY}↳ ideal: {data['ideal']}{N}")
        else:
            sev_col = {
                'HIGH':   LR, 'MEDIUM': LY, 'LOW': LM, 'INFO': LC
            }.get(data['severity'], W)
            print(f"  {err} {sev_col}MISSING [{data['severity']}]{N} {LC}{header}{N}")
            print(f"         {DG}↳ {data['desc']}{N}")
            print(f"         {LY}↳ ideal: {data['ideal']}{N}")

    if 'csp_analysis' in results:
        _sep('CSP Deep Analysis')
        for msg, level in results['csp_analysis']:
            col = LR if level == 'HIGH' else LY if level == 'MEDIUM' else LG if level == 'OK' else LC
            print(f"  {star} {col}{msg}{N}")

    if 'hsts_analysis' in results:
        _sep('HSTS Deep Analysis')
        for msg, level in results['hsts_analysis']:
            col = LR if level == 'HIGH' else LY if level in ('MEDIUM','LOW') else LG if level == 'OK' else LC
            print(f"  {star} {col}{msg}{N}")

    if results.get('cookies'):
        _sep('Cookie Security')
        for name, c in results['cookies'].items():
            flags_ok   = []
            flags_miss = []
            if c['secure']:   flags_ok.append('Secure')
            else:             flags_miss.append('Secure')
            if c['httponly']: flags_ok.append('HttpOnly')
            else:             flags_miss.append('HttpOnly')
            if c['samesite']: flags_ok.append('SameSite')
            else:             flags_miss.append('SameSite')
            ok_str   = (LG + ' '.join(flags_ok) + N) if flags_ok else ''
            miss_str = (LR + ' missing:' + ','.join(flags_miss) + N) if flags_miss else ''
            print(f"  {star} {W}{name}{N}  {ok_str}  {miss_str}")

    if results.get('leak_headers'):
        _sep('Information-Leaking Headers')
        for k, v in results['leak_headers'].items():
            print(f"  {warn} {LY}{k}{N}: {W}{v}{N}")

    _sep('All Response Headers')
    for k, v in results.get('all_headers', {}).items():
        print(f"  {star} {LC}{k}{N}: {DG}{v[:90]}{N}")

    print(f"\n{LY}{'═'*65}{N}")

def _compare_http_https(domain):
    http_url  = f"http://{domain}"
    https_url = f"https://{domain}"

    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {W}HTTP vs HTTPS Comparison{N} → {LC}{domain}{N}")
    print(f"{LY}{'═'*65}{N}")

    http_res,  http_err  = grab_headers(http_url,  follow_redirects=True)
    https_res, https_err = grab_headers(https_url, follow_redirects=True)

    def _row(label, hval, sval):
        hc = LG if hval == sval else LY
        sc = LG if hval == sval else LC
        print(f"  {LC}{label:<22}{N}  {hc}{str(hval):<28}{N}  {sc}{str(sval)}{N}")

    print(f"\n  {W}{'Attribute':<22}  {'HTTP':<28}  HTTPS{N}")
    print(f"  {'─'*22}  {'─'*28}  {'─'*20}")

    if http_err:
        print(f"  {err} HTTP  : {http_err}")
    if https_err:
        print(f"  {err} HTTPS : {https_err}")

    if not http_err and not https_err:
        _row("Status Code",    http_res.get('status_code'),    https_res.get('status_code'))
        _row("Final URL",      http_res.get('final_url','')[:28], https_res.get('final_url','')[:28])
        _row("Response Time",  http_res.get('response_time'),  https_res.get('response_time'))
        _row("Content-Type",   http_res.get('content_type','')[:28], https_res.get('content_type','')[:28])
        _row("Grade Score",    f"{http_res.get('grade_score',0)}/{http_res.get('grade_max',0)}",
                               f"{https_res.get('grade_score',0)}/{https_res.get('grade_max',0)}")

        http_chain  = http_res.get('redirect_chain', [])
        https_chain = https_res.get('redirect_chain', [])
        print(f"\n  {LC}HTTP  redirect chain  :{N}")
        for s in http_chain:
            print(f"    {DG}→ {s}{N}")
        print(f"  {LC}HTTPS redirect chain  :{N}")
        for s in https_chain:
            print(f"    {DG}→ {s}{N}")

        print(f"\n  {W}Security Headers — HTTP vs HTTPS{N}")
        print(f"  {'─'*60}")
        all_hdrs = set(SECURITY_HEADERS.keys())
        for h in all_hdrs:
            hp = http_res.get('security_headers', {}).get(h, {}).get('present', False)
            sp = https_res.get('security_headers', {}).get(h, {}).get('present', False)
            hc = LG if hp else LR
            sc = LG if sp else LR
            hl = "PRESENT" if hp else "MISSING"
            sl = "PRESENT" if sp else "MISSING"
            print(f"  {LC}{h:<36}{N}  {hc}{hl:<10}{N}  {sc}{sl}{N}")

    print(f"\n{LY}{'═'*65}{N}")


def main():
    print(logo)
    parser = argparse.ArgumentParser(description=LY + "Merlin — HTTP Header Grabber + Security Grader")
    parser.add_argument('-u', '--url',          required=True)
    parser.add_argument('--no-redirect',        action='store_true')
    parser.add_argument('--compare-http',       action='store_true',
                        help='Compare HTTP vs HTTPS headers side by side')
    parser.add_argument('-o', '--output',       dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    domain = urlparse(url).netloc

    if args.compare_http:
        _compare_http_https(domain)
        return

    results, error = grab_headers(url, follow_redirects=not args.no_redirect)
    print_report(url, results, error)

    if SAVE_REPORTS and not error:
        os.makedirs(args.output_dir, exist_ok=True)
        fname  = os.path.join(args.output_dir, f"headers_{domain.replace('.', '_')}.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump({"target": url, "results": results}, f, indent=4, ensure_ascii=False)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('[1;92m[*][0m Scan interrupted. Returning to menu...[0m')
