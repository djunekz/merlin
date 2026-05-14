import requests
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import TIMEOUT, USER_AGENT, OUTPUT_DIR, SAVE_REPORTS, MAX_THREADS, VERIFY_SSL

SENSITIVE_FILES = [
    '.env', '.env.backup', '.env.local', '.env.production', '.env.staging',
    '.env.example', '.env.dev', '.env.test', '.envrc',
    'config.php', 'config.inc.php', 'configuration.php',
    'config.yml', 'config.yaml', 'config.json', 'config.xml',
    'settings.php', 'settings.py', 'settings.yml', 'local_settings.py',
    'database.yml', 'database.php', 'db.php', 'db.yml',
    'app.config', 'web.config', 'appsettings.json',
    'parameters.yml', 'parameters.php',
    'wp-config.php', 'wp-config-sample.php',
    'configuration.php', 'joomla.xml',
    'LocalSettings.php',

    '.git/HEAD', '.git/config', '.git/COMMIT_EDITMSG',
    '.git/description', '.git/FETCH_HEAD',
    '.gitignore', '.gitattributes', '.gitmodules',
    '.svn/entries', '.svn/wc.db', '.hg/hgrc',
    '.bzr/README',

    'backup.zip', 'backup.tar.gz', 'backup.tar', 'backup.tgz',
    'backup.sql', 'backup.sql.gz', 'backup.db',
    'site.zip', 'site.tar.gz', 'website.zip',
    'www.zip', 'html.zip', 'public_html.zip',
    'db.sql', 'database.sql', 'dump.sql', 'data.sql',
    'mysql.sql', 'backup_db.sql',
    'old.zip', 'old_site.zip', 'archive.zip',

    'phpinfo.php', 'info.php', 'php_info.php', 'phptest.php',
    'test.php', 'debug.php', 'check.php', 'status.php',
    'install.php', 'setup.php', 'upgrade.php', 'update.php',
    'readme.php', 'license.php',

    'readme.html', 'readme.txt', 'README.md', 'README.txt',
    'CHANGELOG.md', 'CHANGELOG.txt', 'changelog.php',
    'license.txt', 'LICENSE', 'license.html',
    'install/', 'installation/', 'installer/',
    'upgrade/', 'update/', 'updates/',

    'composer.json', 'composer.lock',
    'package.json', 'package-lock.json', 'yarn.lock',
    'Gemfile', 'Gemfile.lock',
    'requirements.txt', 'Pipfile', 'Pipfile.lock',
    'go.mod', 'go.sum',
    'pom.xml', 'build.gradle',
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.dockerignore',

    'id_rsa', 'id_rsa.pub', 'id_dsa', 'id_ecdsa',
    '.ssh/id_rsa', '.ssh/authorized_keys', '.ssh/known_hosts',
    'private.key', 'private.pem', 'server.key',
    'ssl.key', 'ssl.crt', 'ssl.pem',
    'sftp-config.json', 'ftp.json', '.ftpconfig',
    'credentials', 'credentials.json', '.credentials',

    'error.log', 'error_log', 'php_error.log',
    'access.log', 'access_log',
    'debug.log', 'app.log', 'laravel.log',
    'storage/logs/laravel.log',
    'var/log/nginx/error.log',

    '.htaccess', '.htpasswd', '.htdigest',
    'nginx.conf', 'apache.conf', 'httpd.conf',
    'server-status', 'server-info',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    'security.txt', '.well-known/security.txt',

    'Procfile', '.travis.yml', '.circleci/config.yml',
    'appveyor.yml', '.gitlab-ci.yml', 'Jenkinsfile',
    'terraform.tfvars', 'terraform.tfstate',
    'ansible.cfg', 'inventory',

    'sitemap.xml', 'sitemap_index.xml',
    '.DS_Store', 'Thumbs.db',
    'phpMyAdmin/', 'phpmyadmin/', 'pma/', 'mysql/',
    'adminer.php', 'adminer/', 'filemanager/',
    'webadmin/', 'sysadmin/',
]

COMMON_DIRS = [
    'admin', 'administrator', 'administration',
    'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes',
    'backend', 'dashboard', 'panel', 'controlpanel', 'cpanel',
    'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'graphql',
    'login', 'logout', 'auth', 'authentication', 'oauth',
    'register', 'signup', 'account', 'profile', 'user', 'users',
    'upload', 'uploads', 'files', 'media', 'images', 'img',
    'static', 'assets', 'public', 'resources',
    'backup', 'backups', 'bak', 'old', 'archive',
    'test', 'testing', 'dev', 'development', 'staging',
    'temp', 'tmp', 'cache', 'logs', 'log',
    'config', 'conf', 'configuration', 'settings',
    'include', 'includes', 'inc', 'lib', 'library',
    'src', 'source', 'app', 'application',
    'private', 'secret', 'hidden', 'secure',
    'database', 'db', 'sql', 'data',
    'cron', 'scripts', 'shell', 'bin',
    'phpmyadmin', 'adminer', 'webmail', 'mail',
    'server-status', 'server-info',
    'actuator', 'health', 'metrics', 'status', 'info',
    '.git', '.svn', '.hg',
    'console', 'debug', 'trace',
    'vendor', 'node_modules', '.npm',
    'git', 'svn', 'repo', 'repository',
]

class ContentDiscovery:
    def __init__(self, base_url, threads=MAX_THREADS, output_dir=OUTPUT_DIR,
                 delay=0.1, extensions=None):
        if not base_url.endswith('/'):
            base_url += '/'
        self.base_url   = base_url
        self.threads    = threads
        self.output_dir = output_dir
        self.delay      = delay
        self.extensions = extensions or ['', '.php', '.html', '.htm', '.txt',
                                          '.bak', '.old', '.orig', '.backup']
        self.session    = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.session.verify = VERIFY_SSL
        self.found_files = []
        self.found_dirs  = []
        self.errors      = []

    def _check_path(self, path):
        url = urljoin(self.base_url, path.lstrip('/'))
        try:
            r = self.session.head(url, timeout=6, allow_redirects=True)
            if r.status_code in (200, 206):
                r2 = self.session.get(url, timeout=6, allow_redirects=True)
                if r2.status_code == 200 and len(r2.content) > 20:
                    return url, r2.status_code, len(r2.content), r2.text[:150]
            elif r.status_code in (301, 302, 307, 308):
                return url, r.status_code, 0, r.headers.get('Location','')
            elif r.status_code == 403:
                return url, 403, 0, 'Forbidden (exists but restricted)'
        except Exception:
            pass
        return None, None, None, None

    def scan_files(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}Scanning {LC}{len(SENSITIVE_FILES)}{LY} sensitive file paths...{N}")
        print(f"{LY}{'─'*65}{N}")

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._check_path, p): p for p in SENSITIVE_FILES}
            for future in as_completed(futures):
                url, status, size, preview = future.result()
                if url is None:
                    continue
                path = futures[future]
                if status == 200:
                    print(f"  {warn} {LR}FOUND{N}   [{LG}{status}{N}] {W}{path}{N}")
                    if size:
                        print(f"         size={LY}{size}{N}b  preview={DG}{str(preview)[:80].strip()}{N}")
                    self.found_files.append({
                        'path': path, 'url': url, 'status': status,
                        'size': size, 'preview': str(preview)[:120] if preview else '',
                    })
                elif status == 403:
                    print(f"  {star} {LY}EXISTS {N} [{LY}{status}{N}] {DG}{path}{N}  (forbidden)")
                    self.found_files.append({
                        'path': path, 'url': url, 'status': 403,
                        'size': 0, 'preview': 'Forbidden',
                    })
                elif status in (301, 302, 307, 308):
                    print(f"  {star} {LM}REDIR  {N} [{LM}{status}{N}] {DG}{path}{N} → {preview}")
                time.sleep(self.delay)

    def scan_dirs(self):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}Scanning {LC}{len(COMMON_DIRS)}{LY} directories...{N}")
        print(f"{LY}{'─'*65}{N}")

        paths = [d + '/' for d in COMMON_DIRS]
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._check_path, p): p for p in paths}
            for future in as_completed(futures):
                url, status, size, preview = future.result()
                if url is None:
                    continue
                path = futures[future]
                if status in (200, 403):
                    col  = LR if status == 200 else LY
                    mark = warn if status == 200 else star
                    print(f"  {mark} {col}[{status}]{N} {W}{path}{N}")
                    if status == 200 and 'Index of /' in str(preview):
                        print(f"         {LR}⚠ Directory listing OPEN!{N}")
                    self.found_dirs.append({
                        'path': path, 'url': url, 'status': status,
                    })
                time.sleep(self.delay)

    def scan_with_extensions(self, wordlist):
        print(f"\n{LY}{'─'*65}{N}")
        print(f"{plus} {LY}Custom wordlist scan ({len(wordlist)} words × {len(self.extensions)} ext)...{N}")
        print(f"{LY}{'─'*65}{N}")
        paths = []
        for word in wordlist:
            for ext in self.extensions:
                paths.append(word + ext)

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._check_path, p): p for p in paths}
            for future in as_completed(futures):
                url, status, size, preview = future.result()
                if url is None:
                    continue
                path = futures[future]
                if status in (200, 403):
                    col = LR if status == 200 else LY
                    print(f"  {warn} {col}[{status}]{N} {W}{path}{N}")
                    self.found_files.append({
                        'path': path, 'url': url, 'status': status,
                        'size': size or 0, 'preview': str(preview)[:80] if preview else '',
                    })
                time.sleep(self.delay)

    def print_summary(self):
        print(f"\n{LY}{'═'*65}{N}")
        print(f"{plus} {LY}Content Discovery Summary{N}")
        print(f"{LY}{'═'*65}{N}")

        critical = [f for f in self.found_files if f['status'] == 200]
        forbidden = [f for f in self.found_files if f['status'] == 403]

        print(f"  {LC}Files found (200)    {N}: {LR if critical else LG}{len(critical)}{N}")
        print(f"  {LC}Files exist (403)    {N}: {LY}{len(forbidden)}{N}")
        print(f"  {LC}Directories found    {N}: {LY}{len(self.found_dirs)}{N}")

        if critical:
            print(f"\n{LR}  ⚠ CRITICAL — Exposed Files:{N}")
            for item in critical:
                risk = LR + 'HIGH' + N
                for kw in ['backup','sql','dump','config','.env','key','credential','log']:
                    if kw in item['path'].lower():
                        risk = LR + 'CRITICAL' + N
                        break
                print(f"    {warn} [{risk}] {W}{item['path']}{N}")
                print(f"         URL: {DG}{item['url']}{N}")

        print(f"\n{LY}{'═'*65}{N}")

    def save_report(self):
        os.makedirs(self.output_dir, exist_ok=True)
        domain = urlparse(self.base_url).netloc.replace('.', '_')
        fname  = os.path.join(self.output_dir, f"content_{domain}.json")
        report = {
            'target':       self.base_url,
            'found_files':  self.found_files,
            'found_dirs':   self.found_dirs,
        }
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

def main():
    print(logo)
    parser = argparse.ArgumentParser(
        description=LY + "Merlin — Content Discovery & Sensitive File Scanner")
    parser.add_argument('-u', '--url',        required=True)
    parser.add_argument('-t', '--threads',    type=int, default=MAX_THREADS)
    parser.add_argument('--delay',            type=float, default=0.1)
    parser.add_argument('--dirs-only',        action='store_true')
    parser.add_argument('--files-only',       action='store_true')
    parser.add_argument('-w', '--wordlist',   dest='wordlist', default=None,
                        help='Custom wordlist file (one path per line)')
    parser.add_argument('-o', '--output',     dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}Content Discovery{N} → {LC}{url}{N}")
    print(f"{LY}{'═'*65}{N}")

    scanner = ContentDiscovery(url, threads=args.threads,
                               output_dir=args.output_dir, delay=args.delay)

    if args.wordlist:
        try:
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                words = [l.strip() for l in f if l.strip()]
            scanner.scan_with_extensions(words)
        except IOError as e:
            print(f"{err} Cannot read wordlist: {e}")

    if not args.dirs_only:
        scanner.scan_files()
    if not args.files_only:
        scanner.scan_dirs()

    scanner.print_summary()

    if SAVE_REPORTS:
        scanner.save_report()

if __name__ == '__main__':
    main()
