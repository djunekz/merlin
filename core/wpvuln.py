import requests
from bs4 import BeautifulSoup
import re
import argparse
import json
import time
import os
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from merlinlogo import *
from merlinset import *
from merlinconf import TIMEOUT, USER_AGENT, OUTPUT_DIR, SAVE_REPORTS, VERIFY_SSL, MAX_RETRIES

console = Console()

class WPAdminVulnerabilityScanner:

    def __init__(self, target_url, output_file=None, timeout=TIMEOUT, user_agent=USER_AGENT):
        if not target_url.endswith('/'):
            target_url += '/'
        self.target_url    = target_url
        self.wp_admin_url  = urljoin(self.target_url, 'wp-admin/')
        self.login_page_url = urljoin(self.wp_admin_url, 'wp-login.php')
        self.wp_json_url   = urljoin(self.target_url, 'wp-json/wp/v2/')
        self.session       = requests.Session()
        self.timeout       = timeout
        self.output_file   = output_file
        self.vulnerabilities_found = []
        self.info_gathered = {}
        self.start_time    = datetime.now()
        self.user_agent    = user_agent
        self.session.headers.update({'User-Agent': self.user_agent})
        console.print(f"[bold blue]Initialising scanner for:[/bold blue] [bold green]{self.target_url}[/bold green]")

    def _make_request(self, url, method='GET', data=None, allow_redirects=True, retries=MAX_RETRIES):
        for attempt in range(retries):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, timeout=self.timeout,
                                                allow_redirects=allow_redirects, verify=VERIFY_SSL)
                elif method.upper() == 'POST':
                    response = self.session.post(url, data=data, timeout=self.timeout,
                                                 allow_redirects=allow_redirects, verify=VERIFY_SSL)
                return response
            except requests.exceptions.Timeout:
                if attempt < retries - 1:
                    time.sleep(1)
                else:
                    console.print(f"[yellow]Timeout accessing {url}[/yellow]")
                    return None
            except requests.exceptions.RequestException as e:
                console.print(f"[bold red]ERROR:[/bold red] {url}: {e}", style="dim")
                return None
        return None

    def _add_vulnerability(self, name, description, severity, recommended_action, details=None):
        vuln = {
            "name": name,
            "description": description,
            "severity": severity,
            "recommended_action": recommended_action,
            "url": self.wp_admin_url,
            "details": details if details else {}
        }
        self.vulnerabilities_found.append(vuln)
        console.print(f"\n[bold yellow]VULNERABILITY:[/bold yellow] [red]{name}[/red] (Severity: {severity})")
        console.print(f"  [italic]{description}[/italic]")

    def check_wp_admin_access(self):
        console.print("\n[bold blue]1. Checking wp-admin access...[/bold blue]")
        response = self._make_request(self.wp_admin_url)
        if response:
            if response.status_code in (401, 403):
                console.print(f"  [green]wp-admin access denied ({response.status_code}). Good.[/green]")
            elif response.status_code == 200:
                if "wp-login.php" in response.url or "wp-admin" in response.url:
                    console.print(f"  [yellow]wp-admin accessible (200). Login page exposed.[/yellow]")
                    self._add_vulnerability(
                        "wp-admin Exposed",
                        "The wp-admin login page is publicly accessible.",
                        "LOW",
                        "Consider IP-restricting /wp-admin/ in .htaccess or Nginx config."
                    )
                else:
                    console.print(f"  [yellow]200 but not a standard login page. Investigate manually.[/yellow]")
            else:
                console.print(f"  [yellow]Unexpected status: {response.status_code}.[/yellow]")
        else:
            console.print(f"  [bold red]No response from {self.wp_admin_url}.[/bold red]")

    def check_login_page_exposure(self):
        console.print("\n[bold blue]2. Checking login page exposure...[/bold blue]")
        response = self._make_request(self.login_page_url)
        if response and response.status_code == 200:
            console.print(f"  [yellow]wp-login.php is publicly accessible.[/yellow]")
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find('form'):
                console.print("  [yellow]Login form found on the page.[/yellow]")
        elif response:
            console.print(f"  [green]wp-login.php returned {response.status_code} — may be protected.[/green]")
        else:
            console.print("  [dim]Could not access wp-login.php.[/dim]")

    def check_login_form_security(self):
        console.print("\n[bold blue]3. Checking login form security...[/bold blue]")
        response = self._make_request(self.login_page_url)
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            form = soup.find('form')
            if form:
                if form.get('action', '').startswith('https'):
                    console.print("  [green]Form action uses HTTPS.[/green]")
                else:
                    console.print("  [yellow]Form action does not explicitly use HTTPS.[/yellow]")
                if not form.find('input', {'name': '_wpnonce'}):
                    self._add_vulnerability(
                        "Missing CSRF Nonce on Login Form",
                        "The login form does not have a nonce field visible, which may indicate CSRF protection is absent.",
                        "MEDIUM",
                        "Ensure WordPress nonce is generated on the login form."
                    )
                    console.print("  [red]No _wpnonce field found in login form.[/red]")
                else:
                    console.print("  [green]CSRF nonce field detected.[/green]")
        else:
            console.print("  [dim]Login page not accessible for form analysis.[/dim]")

    def check_error_messages(self):
        console.print("\n[bold blue]4. Checking login error message verbosity...[/bold blue]")
        test_data = {'log': 'nonexistent_user_xyz', 'pwd': 'wrong_pass', 'wp-submit': 'Log In', 'redirect_to': '', 'testcookie': '1'}
        self.session.cookies.set('wordpress_test_cookie', 'WP Cookie check')
        response = self._make_request(self.login_page_url, method='POST', data=test_data)
        if response and response.status_code == 200:
            if "The password you entered for the username" in response.text or \
               "Invalid username" in response.text:
                self._add_vulnerability(
                    "Verbose Login Error Messages",
                    "Login errors reveal whether the username or password is wrong, aiding enumeration.",
                    "LOW",
                    "Use a generic error message like 'Invalid credentials'."
                )
                console.print("  [yellow]Verbose error messages detected.[/yellow]")
            else:
                console.print("  [green]No username enumeration detected in error messages.[/green]")
        else:
            console.print("  [dim]Could not test error messages.[/dim]")

    def check_robots_txt_wp_admin(self):
        console.print("\n[bold blue]5. Checking robots.txt for wp-admin entries...[/bold blue]")
        robots_url = urljoin(self.target_url, '/robots.txt')
        response = self._make_request(robots_url)
        if response and response.status_code == 200:
            if 'wp-admin' in response.text.lower() or 'wp-login.php' in response.text.lower():
                console.print("  [green]robots.txt has entries for wp-admin / wp-login.php.[/green]")
            else:
                self._add_vulnerability(
                    "wp-login.php Not Disallowed in robots.txt",
                    "robots.txt does not disallow /wp-login.php, making it easier for bots to find.",
                    "INFORMATIONAL",
                    "Add 'Disallow: /wp-login.php' to robots.txt."
                )
                console.print("  [yellow]robots.txt does NOT restrict wp-login.php.[/yellow]")
        else:
            console.print("  [dim]robots.txt not accessible.[/dim]")

    def check_directory_listing(self):
        console.print("\n[bold blue]6. Checking directory listing in wp-admin...[/bold blue]")
        for subdir in ['css/', 'js/', 'images/', 'includes/']:
            test_url = urljoin(self.wp_admin_url, subdir)
            response = self._make_request(test_url)
            if response:
                if response.status_code == 200 and "Index of /" in response.text:
                    self._add_vulnerability("Directory Listing Enabled",
                        f"Directory listing is open at {test_url}.",
                        "MEDIUM",
                        "Add 'Options -Indexes' to .htaccess.")
                    console.print(f"  [bold red]Directory listing at: {test_url}[/bold red]")
                elif response.status_code == 403:
                    console.print(f"  [green]Access denied (403): {test_url}[/green]")
                else:
                    console.print(f"  [dim]{test_url} → {response.status_code}[/dim]")

    def check_xml_rpc(self):
        console.print("\n[bold blue]7. Checking xmlrpc.php exposure...[/bold blue]")
        xmlrpc_url = urljoin(self.target_url, 'xmlrpc.php')
        response = self._make_request(xmlrpc_url)
        if response and response.status_code == 200:
            if 'XML-RPC server accepts POST requests only' in response.text or 'xmlrpc' in response.text.lower():
                self._add_vulnerability(
                    "xmlrpc.php Exposed",
                    "xmlrpc.php is accessible and can be abused for brute-force or DDoS amplification attacks.",
                    "MEDIUM",
                    "Disable XML-RPC if not needed: add 'add_filter(\"xmlrpc_enabled\", \"__return_false\");' to functions.php or block via .htaccess."
                )
                console.print("  [yellow]xmlrpc.php is publicly accessible.[/yellow]")
            else:
                console.print(f"  [green]xmlrpc.php returned {response.status_code} — may be protected.[/green]")
        elif response:
            console.print(f"  [green]xmlrpc.php → {response.status_code} (likely protected).[/green]")
        else:
            console.print("  [dim]Could not check xmlrpc.php.[/dim]")

    def check_wp_json_user_enum(self):
        console.print("\n[bold blue]8. Checking WP REST API user enumeration...[/bold blue]")
        users_url = urljoin(self.wp_json_url, 'users')
        response = self._make_request(users_url)
        if response and response.status_code == 200:
            try:
                users = response.json()
                if isinstance(users, list) and users:
                    names = [u.get('name', '?') for u in users[:5]]
                    self._add_vulnerability(
                        "User Enumeration via REST API",
                        f"WP REST API /wp-json/wp/v2/users exposes usernames: {names}",
                        "MEDIUM",
                        "Disable user endpoint: add 'add_filter(\"rest_endpoints\", function($e){ unset($e[\"/wp/v2/users\"]); return $e; });' to functions.php."
                    )
                    console.print(f"  [yellow]Users exposed via REST API: {names}[/yellow]")
                else:
                    console.print("  [green]REST API users endpoint returned empty or restricted.[/green]")
            except Exception:
                console.print("  [dim]Could not parse REST API user response.[/dim]")
        elif response:
            console.print(f"  [green]/wp-json/wp/v2/users → {response.status_code} (restricted).[/green]")
        else:
            console.print("  [dim]Could not reach WP REST API.[/dim]")

    def check_wp_version_disclosure(self):
        console.print("\n[bold blue]9. Checking WordPress version disclosure...[/bold blue]")
        response = self._make_request(self.target_url)
        if response:
            match = re.search(r'<meta name=["\']generator["\'] content=["\']WordPress ([0-9.]+)["\']', response.text)
            if match:
                version = match.group(1)
                self._add_vulnerability(
                    "WordPress Version Disclosed",
                    f"WordPress version {version} is revealed in the generator meta tag.",
                    "LOW",
                    "Remove the generator meta tag by adding 'remove_action(\"wp_head\", \"wp_generator\");' to functions.php."
                )
                console.print(f"  [yellow]WP version disclosed: {version}[/yellow]")
            else:
                console.print("  [green]No WordPress version found in page source.[/green]")
            readme_url = urljoin(self.target_url, 'readme.html')
            readme_resp = self._make_request(readme_url)
            if readme_resp and readme_resp.status_code == 200:
                self._add_vulnerability(
                    "readme.html Publicly Accessible",
                    "readme.html reveals the WP version and is unnecessary for public access.",
                    "LOW",
                    "Delete or block access to readme.html."
                )
                console.print("  [yellow]readme.html is accessible — discloses WP info.[/yellow]")

    def run_scan(self):
        console.print(f"\n[bold magenta]Starting WP vulnerability scan for {self.target_url}...[/bold magenta]")

        checks = [
            ("Checking wp-admin access...",          self.check_wp_admin_access),
            ("Checking login page exposure...",      self.check_login_page_exposure),
            ("Checking login form security...",      self.check_login_form_security),
            ("Checking error messages...",           self.check_error_messages),
            ("Checking robots.txt...",               self.check_robots_txt_wp_admin),
            ("Checking directory listing...",        self.check_directory_listing),
            ("Checking xmlrpc.php...",               self.check_xml_rpc),
            ("Checking REST API user enum...",       self.check_wp_json_user_enum),
            ("Checking WP version disclosure...",    self.check_wp_version_disclosure),
        ]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      transient=True, console=console) as progress:
            for label, fn in checks:
                task = progress.add_task(f"[cyan]{label}", total=1)
                fn()
                progress.update(task, completed=1)

        console.print(f"\n[bold magenta]Scan complete![/bold magenta]")
        self.generate_report()

    def generate_report(self):
        end_time = datetime.now()
        duration = end_time - self.start_time

        console.print("\n" + "=" * 74, style="bold blue")
        console.print("[bold blue]WP-ADMIN VULNERABILITY REPORT[/bold blue]", justify="center")
        console.print("=" * 74, style="bold blue")
        console.print(f"Target URL   : [green]{self.target_url}[/green]")
        console.print(f"Scan Started : [yellow]{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
        console.print(f"Scan Ended   : [yellow]{end_time.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
        console.print(f"Duration     : [yellow]{duration}[/yellow]")
        console.print(f"Vulnerabilities Found: [red]{len(self.vulnerabilities_found)}[/red]\n")

        if not self.vulnerabilities_found:
            console.print("[bold green]No significant vulnerabilities detected.[/bold green]")
            console.print("[italic dim]This is not a full security guarantee. Always test manually too.[/italic dim]")
        else:
            table = Table(title="Vulnerabilities Found", show_lines=True)
            table.add_column("Name",            style="cyan",    justify="left")
            table.add_column("Severity",        style="magenta", justify="center")
            table.add_column("Description",     style="white",   justify="left")
            table.add_column("Recommendation",  style="green",   justify="left")

            sev_colors = {"INFORMATIONAL": "blue", "LOW": "yellow", "MEDIUM": "orange3", "HIGH": "red"}
            for vuln in self.vulnerabilities_found:
                color = sev_colors.get(vuln["severity"], "white")
                table.add_row(
                    vuln["name"],
                    f"[{color}]{vuln['severity']}[/{color}]",
                    vuln["description"],
                    vuln["recommended_action"]
                )
            console.print(table)

        if self.output_file or SAVE_REPORTS:
            report_path = self.output_file
            if not report_path:
                os.makedirs(OUTPUT_DIR, exist_ok=True)
                domain     = urlparse(self.target_url).netloc.replace('.', '_')
                report_path = os.path.join(OUTPUT_DIR, f"wpvuln_{domain}.json")

            report_data = {
                "scan_summary": {
                    "target_url": self.target_url,
                    "start_time": str(self.start_time),
                    "end_time":   str(end_time),
                    "duration":   str(duration),
                    "vulnerabilities_count": len(self.vulnerabilities_found)
                },
                "vulnerabilities_found": self.vulnerabilities_found
            }
            try:
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=4, ensure_ascii=False)
                console.print(f"\n[bold green]JSON report saved to:[/bold green] [cyan]{report_path}[/cyan]")
            except IOError as e:
                console.print(f"[bold red]ERROR:[/bold red] Could not write report: {e}")

        console.print("\n" + "=" * 74, style="bold blue")
        console.print("[bold blue]DISCLAIMER:[/bold blue]", justify="center")
        console.print("=" * 74, style="bold blue")
        console.print("[italic]Only scan websites you own or have explicit written permission to test.[/italic]")
        console.print("=" * 74, style="bold blue")


def main():
    parser = argparse.ArgumentParser(
        description="Merlin — WordPress Admin Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-u', '--url',     type=str, required=True,
                        help="Target WordPress site URL (e.g. https://example.com)")
    parser.add_argument('-o', '--output',  type=str, default=None,
                        help="File to save JSON report")
    parser.add_argument('-t', '--timeout', type=int, default=TIMEOUT,
                        help=f"Request timeout in seconds (default: {TIMEOUT})")
    parser.add_argument('--user-agent',    type=str, default=USER_AGENT,
                        help="Custom User-Agent string")
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help="Disable SSL certificate verification")

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        console.print("[bold red]ERROR:[/bold red] URL must start with http:// or https://")
        sys.exit(1)

    if args.no_verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        console.print("[bold yellow]WARNING:[/bold yellow] SSL verification disabled.")

    scanner = WPAdminVulnerabilityScanner(
        target_url=args.url,
        output_file=args.output,
        timeout=args.timeout,
        user_agent=args.user_agent,
    )
    scanner.session.verify = not args.no_verify_ssl

    try:
        scanner.run_scan()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user.[/bold red]")
        scanner.generate_report()
    except Exception as e:
        console.print(f"[bold red]Fatal error:[/bold red] {e}")


if __name__ == "__main__":
    print(logo)
    main()
