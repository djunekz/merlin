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
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from webshakeset import *
from merlinlogo import *
from merlinconf import TIMEOUT, USER_AGENT, OUTPUT_DIR, SAVE_REPORTS, RATE_LIMIT_DELAY

logging.basicConfig(
    level=logging.INFO,
    format=LC + '[' + W + '%(asctime)s' + LC + ']' + LG + ' %(message)s',
    datefmt='%H:%M:%S'
)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

CMS_SIGNATURES = {
    "WordPress":   [r'wp-content', r'wp-includes', r'wp-json', r'WordPress'],
    "Joomla":      [r'/components/com_', r'Joomla!', r'/media/jui/'],
    "Drupal":      [r'Drupal\.settings', r'/sites/default/files/', r'drupal\.js'],
    "Magento":     [r'Mage\.', r'skin/frontend', r'varien/'],
    "Shopify":     [r'cdn\.shopify\.com', r'Shopify\.theme'],
    "PrestaShop":  [r'prestashop', r'/modules/ps_'],
    "OpenCart":    [r'route=common', r'catalog/view/theme'],
    "WHMCS":       [r'whmcs', r'clientarea\.php'],
    "Laravel":     [r'laravel_session', r'XSRF-TOKEN'],
    "Django":      [r'csrfmiddlewaretoken', r'__admin_media_prefix__'],
    "CodeIgniter": [r'ci_session', r'system/core/CodeIgniter'],
    "Symfony":     [r'_symfony_', r'sf_redirect'],
}

SENSITIVE_PATHS = [
    '.env', '.env.backup', '.env.local', '.env.production',
    'config.php', 'wp-config.php', 'config.yml', 'config.yaml',
    'database.yml', 'settings.py', 'local_settings.py',
    'backup.zip', 'backup.tar.gz', 'backup.sql', 'dump.sql',
    'db.sql', 'database.sql', 'site.sql',
    '.git/HEAD', '.git/config', '.svn/entries',
    'phpinfo.php', 'info.php', 'test.php', 'debug.php',
    'admin/config.php', 'includes/config.php',
    'composer.json', 'package.json', 'Gemfile',
    'readme.txt', 'README.md', 'CHANGELOG.md',
    'server-status', 'server-info',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    '.DS_Store', 'Thumbs.db',
    'log.txt', 'error.log', 'debug.log', 'access.log',
    'web.config', '.htaccess', '.htpasswd',
    'id_rsa', 'id_rsa.pub', '.ssh/known_hosts',
    'sftp-config.json', 'ftp.json',
]

SECRET_PATTERNS = {
    'AWS Access Key':       r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key':       r'[0-9a-zA-Z/+]{40}',
    'Google API Key':       r'AIza[0-9A-Za-z\-_]{35}',
    'Stripe Secret Key':    r'sk_live_[0-9a-zA-Z]{24,}',
    'Stripe Public Key':    r'pk_live_[0-9a-zA-Z]{24,}',
    'Mailchimp API Key':    r'[0-9a-f]{32}-us[0-9]{1,2}',
    'Twilio Account SID':   r'AC[a-zA-Z0-9]{32}',
    'Twilio Auth Token':    r'[a-zA-Z0-9]{32}',
    'GitHub Token':         r'ghp_[A-Za-z0-9]{36}',
    'GitHub OAuth':         r'gho_[A-Za-z0-9]{36}',
    'Private Key Block':    r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    'Password in HTML':     r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
    'DB Connection String': r'(?i)(mysql|postgres|mongodb|redis):\/\/[^\s"\'<>]+',
    'JWT Token':            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'Basic Auth in URL':    r'https?://[^:@\s]+:[^@\s]+@',
    'Slack Token':          r'xox[baprs]-[0-9A-Za-z]{10,48}',
    'Telegram Bot Token':   r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
    'Firebase URL':         r'https?://[a-z0-9-]+\.firebaseio\.com',
    'Heroku API Key':       r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'Sendgrid API Key':     r'SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}',
}

class WebCrawler:
    def __init__(self, start_url, max_depth=2, delay=0.3, output_dir=None):
        self.start_url         = self._normalize_url(start_url)
        self.max_depth         = max_depth
        self.delay             = delay
        self.output_dir        = output_dir or OUTPUT_DIR
        self.visited_urls      = set()
        self.internal_links    = set()
        self.external_links    = set()
        self.broken_links      = {}
        self.emails_found      = set()
        self.phones_found      = set()
        self.forms_found       = []
        self.comments_found    = []
        self.scripts_found     = set()
        self.meta_tags         = {}
        self.page_titles       = {}
        self.response_times    = {}
        self.sensitive_exposed = []
        self.secrets_found     = []
        self.cms_detected      = set()
        self.page_hashes       = {}
        self.redirect_chains   = {}
        self.base_domain       = urlparse(self.start_url).netloc
        self.session           = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        logging.info(f"{pss} {LY}Starting{LC} {self.start_url} depth={max_depth}{N}")

    def _normalize_url(self, url):
        if not urlparse(url).scheme:
            return "https://" + url
        return url

    def _is_internal(self, url):
        netloc = urlparse(url).netloc
        return netloc == self.base_domain or netloc == ''

    def _clean_url(self, url):
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl()

    def _page_hash(self, content):
        return hashlib.md5(content.encode('utf-8', errors='replace')).hexdigest()

    def _analyze_page(self, url, response, soup):
        body = response.text

        title_tag = soup.find('title')
        if title_tag:
            self.page_titles[url] = title_tag.get_text(strip=True)

        h = self._page_hash(body)
        self.page_hashes[url] = h

        meta = {}
        for tag in soup.find_all('meta'):
            name    = tag.get('name') or tag.get('property') or tag.get('http-equiv', '')
            content = tag.get('content', '')
            if name and content:
                meta[name.lower()] = content
        if meta:
            self.meta_tags[url] = meta

        for m in re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body):
            if not m.endswith(('.png', '.jpg', '.gif', '.svg')):
                self.emails_found.add(m)

        for m in re.findall(r'(?:\+62|0)[0-9\-\s]{8,15}', body):
            cleaned = re.sub(r'[\s\-]', '', m)
            if len(cleaned) >= 9:
                self.phones_found.add(cleaned)

        for comment in soup.find_all(string=lambda t: isinstance(t, __import__('bs4').Comment)):
            c = str(comment).strip()
            if len(c) > 4:
                self.comments_found.append({'url': url, 'comment': c[:300]})

        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith('http') and self.base_domain not in src:
                self.scripts_found.add(src)

        for form in soup.find_all('form'):
            action  = form.get('action', '')
            method  = form.get('method', 'get').upper()
            enctype = form.get('enctype', '')
            inputs  = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inputs.append({
                    'tag':   inp.name,
                    'name':  inp.get('name', ''),
                    'type':  inp.get('type', 'text'),
                    'value': inp.get('value', ''),
                })
            has_file   = any(i['type'] == 'file' for i in inputs)
            has_passwd = any(i['type'] == 'password' for i in inputs)
            self.forms_found.append({
                'url': url, 'action': action, 'method': method,
                'enctype': enctype, 'inputs': inputs,
                'has_file_upload': has_file, 'has_password_field': has_passwd,
            })

        for cms, patterns in CMS_SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    self.cms_detected.add(cms)
                    break

        for label, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, body)
            for match in matches:
                if len(match) > 8:
                    self.secrets_found.append({
                        'url': url, 'type': label,
                        'snippet': match[:60] + ('...' if len(match) > 60 else '')
                    })

        self.response_times[url] = round(response.elapsed.total_seconds(), 3)

    def check_sensitive_files(self):
        logging.info(f"{pss} {LY}Checking {LC}{len(SENSITIVE_PATHS)}{LY} sensitive paths...{N}")
        for path in SENSITIVE_PATHS:
            test_url = urljoin(self.start_url, '/' + path.lstrip('/'))
            try:
                r = self.session.head(test_url, timeout=6, allow_redirects=True, verify=False)
                if r.status_code in (200, 206):
                    r2 = self.session.get(test_url, timeout=6, verify=False)
                    if r2.status_code == 200 and len(r2.text) > 10:
                        self.sensitive_exposed.append({
                            'url': test_url, 'path': path,
                            'status': r2.status_code,
                            'size': len(r2.content),
                            'preview': r2.text[:120].replace('\n', ' '),
                        })
                        logging.warning(f"{warn} {LR}EXPOSED{N} {test_url}")
                time.sleep(0.15)
            except Exception:
                pass

    def crawl(self, url, depth):
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        logging.info(f"{star}{LY} request{N} [{depth}/{self.max_depth}] {url}")

        try:
            response = self.session.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False)
            time.sleep(self.delay)

            if response.history:
                self.redirect_chains[url] = [r.url for r in response.history] + [response.url]

            if response.status_code != 200:
                self.broken_links[url] = response.status_code
                logging.warning(f"{min_pfx}{LY} {url} → HTTP {response.status_code}")
                return

            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            self._analyze_page(url, response, soup)

            for a_tag in soup.find_all('a', href=True):
                href         = a_tag['href'].strip()
                if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                    continue
                absolute_url = urljoin(url, href)
                clean_url    = self._clean_url(absolute_url)
                if clean_url in self.visited_urls:
                    continue
                if self._is_internal(clean_url):
                    self.internal_links.add(clean_url)
                    self.crawl(clean_url, depth + 1)
                else:
                    self.external_links.add(clean_url)

        except requests.exceptions.Timeout:
            self.broken_links[url] = 'TIMEOUT'
        except requests.exceptions.ConnectionError:
            self.broken_links[url] = 'CONN_ERR'
        except Exception as e:
            self.broken_links[url] = str(e)[:80]

    def start(self):
        print(f"\n{LY}{'═'*65}{N}")
        print(f"{plus} {LY}Starting Web Crawler{N} → {LC}{self.start_url}{N}")
        print(f"{LY}{'═'*65}{N}")
        self.crawl(self.start_url, 0)
        self.check_sensitive_files()
        self._print_report()
        if SAVE_REPORTS:
            self._save_report()

    def _print_report(self):
        print(f"\n{LY}{'═'*65}{N}")
        print(f"{plus} {LR}CRAWL REPORT{N}")
        print(f"{LY}{'═'*65}{N}")
        print(f"  {LC}Domain         {N}: {W}{self.base_domain}{N}")
        print(f"  {LC}URLs Visited   {N}: {LG}{len(self.visited_urls)}{N}")
        print(f"  {LC}Internal Links {N}: {LG}{len(self.internal_links)}{N}")
        print(f"  {LC}External Links {N}: {LG}{len(self.external_links)}{N}")
        print(f"  {LC}Broken Links   {N}: {LR}{len(self.broken_links)}{N}")
        print(f"  {LC}Emails Found   {N}: {LM}{len(self.emails_found)}{N}")
        print(f"  {LC}Phones Found   {N}: {LM}{len(self.phones_found)}{N}")
        print(f"  {LC}Forms Found    {N}: {LY}{len(self.forms_found)}{N}")
        print(f"  {LC}Ext. Scripts   {N}: {LY}{len(self.scripts_found)}{N}")
        print(f"  {LC}HTML Comments  {N}: {DG}{len(self.comments_found)}{N}")

        if self.cms_detected:
            print(f"\n{plus} {LY}CMS Detected{N}: {LG}{', '.join(self.cms_detected)}{N}")

        if self.page_titles:
            print(f"\n{plus} {LY}Page Titles{N}:")
            for url, title in list(self.page_titles.items())[:10]:
                print(f"  {star} {DG}{url}{N}")
                print(f"       {W}↳ {title}{N}")

        if self.emails_found:
            print(f"\n{plus} {LM}Emails Found{N}:")
            for e in sorted(self.emails_found):
                print(f"  {sukses} {LM}{e}{N}")

        if self.phones_found:
            print(f"\n{plus} {LM}Phone Numbers{N}:")
            for p in sorted(self.phones_found):
                print(f"  {sukses} {LM}{p}{N}")

        if self.broken_links:
            print(f"\n{plus} {LR}Broken Links [{len(self.broken_links)}]{N}:")
            for url, reason in self.broken_links.items():
                print(f"  {warn} {LR}{reason}{N} → {DG}{url}{N}")

        if self.sensitive_exposed:
            print(f"\n{plus} {LR}⚠ SENSITIVE FILES EXPOSED [{len(self.sensitive_exposed)}]{N}:")
            for item in self.sensitive_exposed:
                print(f"  {warn} {LR}EXPOSED{N} {W}{item['path']}{N}")
                print(f"       {DG}URL    : {item['url']}{N}")
                print(f"       {DG}Size   : {item['size']} bytes{N}")
                print(f"       {DG}Preview: {item['preview'][:80]}{N}")

        if self.secrets_found:
            print(f"\n{plus} {LR}⚠ POTENTIAL SECRETS IN SOURCE [{len(self.secrets_found)}]{N}:")
            for s in self.secrets_found:
                print(f"  {warn} {LR}{s['type']}{N}")
                print(f"       {DG}URL    : {s['url']}{N}")
                print(f"       {DG}Snippet: {s['snippet']}{N}")

        if self.forms_found:
            print(f"\n{plus} {LY}Forms [{len(self.forms_found)}]{N}:")
            for form in self.forms_found:
                flags = []
                if form['has_file_upload']:  flags.append(LR + 'FILE-UPLOAD' + N)
                if form['has_password_field']: flags.append(LY + 'PASSWORD' + N)
                flag_str = ' '.join(flags) if flags else DG + 'standard' + N
                print(f"  {star} {W}{form['url']}{N}")
                print(f"       method={LC}{form['method']}{N} action={LY}{form['action'] or '(self)'}{N} {flag_str}")

        if self.redirect_chains:
            print(f"\n{plus} {LY}Redirect Chains{N}:")
            for src, chain in self.redirect_chains.items():
                print(f"  {star} {DG}{src}{N}")
                for step in chain:
                    print(f"       {LY}→ {step}{N}")

        if self.scripts_found:
            print(f"\n{plus} {LY}External Scripts [{len(self.scripts_found)}]{N}:")
            for s in sorted(self.scripts_found):
                print(f"  {star} {DG}{s}{N}")

        if self.response_times:
            slowest = sorted(self.response_times.items(), key=lambda x: x[1], reverse=True)[:5]
            print(f"\n{plus} {LY}Slowest Pages{N}:")
            for url, t in slowest:
                color = LR if t > 3 else LY if t > 1 else LG
                print(f"  {star} {color}{t}s{N} → {DG}{url}{N}")

        print(f"\n{LY}{'─'*65}{N}")
        print(f"{sukses} {LG}Crawl Complete{N}")
        print(f"{LY}{'─'*65}{N}")

    def _save_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        report = {
            "target":            self.start_url,
            "domain":            self.base_domain,
            "cms_detected":      list(self.cms_detected),
            "internal_links":    sorted(self.internal_links),
            "external_links":    sorted(self.external_links),
            "broken_links":      self.broken_links,
            "emails_found":      sorted(self.emails_found),
            "phones_found":      sorted(self.phones_found),
            "forms_found":       self.forms_found,
            "comments_found":    self.comments_found,
            "external_scripts":  sorted(self.scripts_found),
            "meta_tags":         self.meta_tags,
            "page_titles":       self.page_titles,
            "sensitive_exposed": self.sensitive_exposed,
            "secrets_found":     self.secrets_found,
            "redirect_chains":   self.redirect_chains,
            "response_times":    self.response_times,
        }
        fname = os.path.join(self.output_dir, f"webshake_{self.base_domain.replace('.','_')}.json")
        try:
            with open(fname, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            print(f"{sukses} Report saved → {LY}{fname}{N}")
        except IOError as e:
            print(f"{min_pfx} Could not save report: {e}")


if __name__ == "__main__":
    try:
        print(logo)
        parser = argparse.ArgumentParser(description=LY + "Merlin — Web Crawler & Analyzer")
        parser.add_argument("-u", "--url",    dest="url",       required=True)
        parser.add_argument("-d", "--depth",  dest="max_depth", type=int, default=2)
        parser.add_argument("--delay",        dest="delay",     type=float, default=RATE_LIMIT_DELAY)
        parser.add_argument("-o", "--output", dest="output_dir",default=OUTPUT_DIR)
        args = parser.parse_args()

        crawler = WebCrawler(args.url, args.max_depth, args.delay, args.output_dir)
        crawler.start()

    except KeyboardInterrupt:
        print('\n\033[1;92m[*]\033[0m Scan interrupted. Returning to menu...\033[0m')
