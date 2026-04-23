import requests
from bs4 import BeautifulSoup
import re
import argparse
from urllib.parse import urljoin, urlparse
import json
import time
from datetime import datetime
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from merlinlogo import *
from merlinset import *
from merlinconf import *

console = Console()

class WPAdminVulnerabilityScanner:

    def __init__(self, target_url, output_file=None, timeout=10, user_agent=None):
        if not target_url.endswith('/'):
            target_url += '/'
        self.target_url = target_url
        self.wp_admin_url = urljoin(self.target_url, 'wp-admin/')
        self.login_page_url = urljoin(self.wp_admin_url, 'wp-login.php')
        self.session = requests.Session()
        self.timeout = timeout
        self.output_file = output_file
        self.vulnerabilities_found = []
        self.start_time = datetime.now()
        self.user_agent = user_agent if user_agent else "WP-Admin-Vulnerability-Scanner/1.0 (Python Security Tool)"
        self.session.headers.update({'User-Agent': self.user_agent})
        console.print(f"[bold blue]Inisialisasi Pemindai untuk:[/bold blue] [bold green]{self.target_url}[/bold green]")
        console.print(f"[bold blue]Halaman wp-admin:[/bold blue] [cyan]{self.wp_admin_url}[/cyan]")

    def _make_request(self, url, method='GET', data=None, allow_redirects=True, verify_ssl=True):
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=self.timeout, allow_redirects=allow_redirects, verify=verify_ssl)
            elif method.upper() == 'POST':
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=allow_redirects, verify=verify_ssl)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            console.print(f"[bold red]ERROR:[/bold red] Gagal mengakses [cyan]{url}[/cyan]: {e}", style="dim")
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
        console.print(f"\n[bold yellow]KERENTANAN DITEMUKAN:[/bold yellow] [red]{name}[/red] (Severity: {severity})")
        console.print(f"  [italic]{description}[/italic]")

    def check_wp_admin_access(self):
        console.print("\n[bold blue]1. Memeriksa Akses wp-admin...[/bold blue]")
        response = self._make_request(self.wp_admin_url)
        if response:
            if response.status_code == 200:
                if "wp-login.php" in response.url or "wp-admin" in response.url:
                    console.print(f"  [green]Akses ke {self.wp_admin_url} berhasil (Status: {response.status_code}).[/green]")
                    if "form_login" in response.text or "username" in response.text:
                         console.print(f"  [green]Kemungkinan halaman login wp-admin ditemukan.[/green]")
                    else:
                        console.print(f"  [yellow]Meskipun status 200, tampaknya bukan halaman login wp-admin standar atau ada redireksi.[/yellow]")
                else:
                     console.print(f"  [red]Redireksi tidak ke halaman wp-login.php atau wp-admin. Status: {response.status_code}. Ini mungkin indikasi konfigurasi non-standar atau blokir.[/red]")
            elif response.status_code == 401 or response.status_code == 403:
                console.print(f"  [green]Akses ke {self.wp_admin_url} ditolak (Status: {response.status_code}). Ini adalah hal yang baik.[/green]")
            elif response.status_code == 301 or response.status_code == 302:
                console.print(f"  [yellow]Redireksi ditemukan dari {self.wp_admin_url}. Status: {response.status_code}. Lokasi: {response.headers.get('Location')}[/yellow]")
                redirect_response = self._make_request(response.headers.get('Location'))
                if redirect_response and redirect_response.status_code == 200 and "wp-login.php" in redirect_response.url:
                    console.print(f"  [green]Redireksi mengarah ke halaman login wp-admin yang valid.[/green]")
                else:
                     console.print(f"  [yellow]Redireksi mengarah ke halaman yang tidak terduga atau error.[/yellow]")
            else:
                console.print(f"  [yellow]Akses ke {self.wp_admin_url} menghasilkan status {response.status_code}. Perlu pemeriksaan manual.[/yellow]")
                if response.status_code == 200:
                    self._add_vulnerability(
                        "Potensi Akses wp-admin Langsung",
                        f"Direktori wp-admin dapat diakses langsung dengan status {response.status_code}. Meskipun seringkali mengarah ke halaman login, ini bisa menjadi masalah jika ada file sensitif yang tidak dilindungi.",
                        "LOW",
                        "Pastikan tidak ada file yang tidak seharusnya diakses publik di direktori wp-admin. Pastikan hanya halaman login yang bisa diakses."
                    )
        else:
            console.print(f"  [bold red]Gagal mendapatkan respons dari {self.wp_admin_url}.[/bold red]")


    def check_login_page_exposure(self):
        console.print("\n[bold blue]2. Memeriksa Paparan Halaman Login (wp-login.php)...[/bold blue]")
        response = self._make_request(self.login_page_url)
        if response:
            if response.status_code == 200:
                console.print(f"  [green]Halaman login wp-login.php dapat diakses (Status: {response.status_code}).[/green]")
                self._add_vulnerability(
                    "Paparan Halaman Login wp-login.php",
                    f"Halaman login WordPress (`wp-login.php`) dapat diakses secara publik. Meskipun ini normal, ini juga merupakan titik awal untuk serangan brute-force atau credential stuffing.",
                    "INFORMATIONAL",
                    "Pertimbangkan untuk melindungi halaman login dengan autentikasi dua faktor (2FA), membatasi upaya login, atau mengubah URL login secara drastis jika memungkinkan."
                )
            else:
                console.print(f"  [yellow]Halaman login wp-login.php tidak mengembalikan status 200 (Status: {response.status_code}). Ini bisa berarti dilindungi atau tidak ada.[/yellow]")
        else:
            console.print(f"  [bold red]Gagal mendapatkan respons dari {self.login_page_url}.[/bold red]")

    def check_login_form_security(self):
        console.print("\n[bold blue]3. Memeriksa Keamanan Formulir Login...[/bold blue]")
        parsed_url = urlparse(self.login_page_url)
        if parsed_url.scheme != 'https':
            self._add_vulnerability(
                "Login Form Over HTTP (Tidak Terenkripsi)",
                f"Halaman login (`{self.login_page_url}`) diakses menggunakan HTTP (tidak terenkripsi). Ini membuat kredensial rentan terhadap eavesdropping.",
                "HIGH",
                "Segera terapkan HTTPS (SSL/TLS) di seluruh situs web, terutama untuk halaman login. Dapatkan sertifikat SSL dari CA terpercaya."
            )
            console.print(f"  [bold red]Halaman login diakses melalui HTTP, bukan HTTPS![/bold red]")
        else:
            console.print(f"  [green]Halaman login diakses melalui HTTPS. [bold](Bagus!)[/bold][/green]")

        response = self._make_request(self.login_page_url)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form', {'name': 'loginform'}) or soup.find('form', {'id': 'loginform'})
            if login_form:
                action_url = login_form.get('action')
                if action_url and not action_url.startswith('https://') and parsed_url.scheme == 'https':
                    self._add_vulnerability(
                        "Form Action Menggunakan HTTP di Halaman HTTPS",
                        f"Meskipun halaman login adalah HTTPS, URL 'action' formulir login ({action_url}) menggunakan HTTP. Ini dapat menyebabkan pengiriman kredensial tidak terenkripsi.",
                        "HIGH",
                        "Pastikan atribut 'action' dari formulir login juga menggunakan HTTPS."
                    )
                    console.print(f"  [bold red]URL 'action' form login menggunakan HTTP, padahal halaman adalah HTTPS![/bold red]")
                else:
                    console.print(f"  [green]URL 'action' form login tampaknya konsisten dengan HTTPS.[/green]")
            else:
                console.print(f"  [yellow]Formulir login tidak ditemukan dengan atribut 'name' atau 'id' standar.[/yellow]")

    def check_error_messages(self):
        console.print("\n[bold blue]4. Memeriksa Pesan Kesalahan Login...[/bold blue]")
        test_username = "nonexistentuser"
        test_password = "wrongpassword123"
        login_data = {
            'log': test_username,
            'pwd': test_password,
            'wp-submit': 'Log In',
            'redirect_to': self.wp_admin_url
        }

        response = self._make_request(self.login_page_url, method='POST', data=login_data, allow_redirects=False)

        if response and response.status_code == 200:
            if "invalid username" in response.text.lower() or "username is not registered" in response.text.lower():
                self._add_vulnerability(
                    "Pesan Kesalahan 'Username Tidak Ada' yang Terlalu Informatif",
                    f"Halaman login mengungkapkan apakah nama pengguna itu ada atau tidak. Ini membantu penyerang mengidentifikasi username yang valid untuk serangan brute-force.",
                    "MEDIUM",
                    "Konfigurasi WordPress atau plugin keamanan untuk memberikan pesan kesalahan login yang generik (misalnya, 'Kombinasi nama pengguna/kata sandi salah')."
                )
                console.print(f"  [bold red]Mendeteksi pesan kesalahan yang mengungkapkan keberadaan username (mis: 'username tidak ada').[/bold red]")
            elif "incorrect password" in response.text.lower() or "the password you entered for the username" in response.text.lower():
                 self._add_vulnerability(
                    "Pesan Kesalahan 'Kata Sandi Salah' yang Terlalu Informatif",
                    f"Halaman login mengungkapkan bahwa kata sandi salah setelah username ditemukan valid. Ini juga membantu penyerang.",
                    "MEDIUM",
                    "Konfigurasi WordPress atau plugin keamanan untuk memberikan pesan kesalahan login yang generik."
                )
                 console.print(f"  [bold red]Mendeteksi pesan kesalahan yang mengungkapkan bahwa password salah setelah username ditemukan valid.[/bold red]")
            else:
                console.print(f"  [green]Pesan kesalahan login tampaknya tidak terlalu informatif.[/green]")
        else:
            console.print(f"  [yellow]Tidak dapat menguji pesan kesalahan login secara efektif (status: {response.status_code if response else 'N/A'}).[/yellow]")


    def check_robots_txt_wp_admin(self):
        console.print("\n[bold blue]5. Memeriksa robots.txt untuk wp-admin...[/bold blue]")
        robots_url = urljoin(self.target_url, 'robots.txt')
        response = self._make_request(robots_url)
        if response and response.status_code == 200:
            content = response.text
            disallow_rules = re.findall(r'Disallow:\s*(.*)', content, re.IGNORECASE)

            admin_disallowed = False
            login_disallowed = False

            for rule in disallow_rules:
                if 'wp-admin' in rule.lower():
                    admin_disallowed = True
                if 'wp-login.php' in rule.lower():
                    login_disallowed = True

            if admin_disallowed:
                console.print(f"  [green]robots.txt melarang crawling wp-admin. [bold](Bagus!)[/bold][/green]")
            else:
                self._add_vulnerability(
                    "wp-admin Tidak Dilarang di robots.txt",
                    f"Direktori wp-admin tidak dilarang untuk di-crawl oleh mesin pencari dalam robots.txt. Ini dapat membuat URL admin lebih mudah ditemukan oleh penyerang melalui pencarian mesin.",
                    "LOW",
                    "Tambahkan 'Disallow: /wp-admin/' ke file robots.txt Anda."
                )
                console.print(f"  [yellow]robots.txt TIDAK melarang crawling wp-admin. Perhatian![/yellow]")

            if login_disallowed:
                console.print(f"  [green]robots.txt melarang crawling wp-login.php. [bold](Bagus!)[/bold][/green]")
            else:
                self._add_vulnerability(
                    "wp-login.php Tidak Dilarang di robots.txt",
                    f"Halaman wp-login.php tidak dilarang untuk di-crawl oleh mesin pencari dalam robots.txt. Meskipun tidak secara langsung menimbulkan kerentanan, ini memudahkan enumerasi halaman login.",
                    "INFORMATIONAL",
                    "Pertimbangkan untuk menambahkan 'Disallow: /wp-login.php' ke file robots.txt Anda."
                )
                console.print(f"  [yellow]robots.txt TIDAK melarang crawling wp-login.php. Perhatian![/yellow]")
        else:
            console.print(f"  [yellow]Tidak dapat mengakses robots.txt (status: {response.status_code if response else 'N/A'}) atau tidak ada.[/yellow]")
            console.print(f"  [italic dim]Tidak adanya robots.txt bukan kerentanan, tetapi tidak ada informasi Disallow.[/italic dim]")

    def check_directory_listing(self):
        console.print("\n[bold blue]6. Memeriksa Directory Listing di Subdirektori wp-admin...[/bold blue]")
        common_subdirs = ['css/', 'js/', 'images/', 'includes/', 'maint/', 'network/', 'options-general.php']

        for subdir in common_subdirs:
            test_url = urljoin(self.wp_admin_url, subdir)
            response = self._make_request(test_url)
            if response:
                if response.status_code == 200 and ("Index of /" in response.text or "<title>Index of" in response.text):
                    self._add_vulnerability(
                        "Directory Listing Diaktifkan",
                        f"Directory listing diaktifkan untuk '{test_url}'. Ini memungkinkan penyerang melihat daftar semua file dan direktori, yang dapat mengungkap informasi sensitif.",
                        "MEDIUM",
                        "Nonaktifkan directory listing di server web Anda (misalnya, dengan menambahkan `Options -Indexes` di `.htaccess` untuk Apache atau konfigurasi serupa untuk Nginx)."
                    )
                    console.print(f"  [bold red]Directory Listing ditemukan di: {test_url}[/bold red]")
                elif response.status_code == 403:
                    console.print(f"  [green]Akses ke {test_url} ditolak (Status 403). [bold](Bagus!)[/bold][/green]")
                else:
                    console.print(f"  [dim]Akses ke {test_url} menghasilkan status {response.status_code}. Tidak ada directory listing terlihat.[/dim]")
            else:
                console.print(f"  [dim]Gagal mengakses {test_url}.[/dim]")

    def run_scan(self):
        console.print(f"\n[bold magenta]Memulai Pemindaian Kerentanan wp-admin untuk {self.target_url}...[/bold magenta]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            task1 = progress.add_task("[cyan]Memeriksa Akses wp-admin...", total=1)
            self.check_wp_admin_access()
            progress.update(task1, completed=1)

            task2 = progress.add_task("[cyan]Memeriksa Paparan Halaman Login...", total=1)
            self.check_login_page_exposure()
            progress.update(task2, completed=1)

            task3 = progress.add_task("[cyan]Memeriksa Keamanan Formulir Login...", total=1)
            self.check_login_form_security()
            progress.update(task3, completed=1)

            task4 = progress.add_task("[cyan]Memeriksa Pesan Kesalahan Login...", total=1)
            self.check_error_messages()
            progress.update(task4, completed=1)

            task5 = progress.add_task("[cyan]Memeriksa robots.txt...", total=1)
            self.check_robots_txt_wp_admin()
            progress.update(task5, completed=1)

            task6 = progress.add_task("[cyan]Memeriksa Directory Listing...", total=1)
            self.check_directory_listing()
            progress.update(task6, completed=1)

        console.print(f"\n[bold magenta]Pemindaian Selesai![/bold magenta]")
        self.generate_report()

    def generate_report(self):
        end_time = datetime.now()
        duration = end_time - self.start_time

        console.print("\n" + "="*74, style="bold blue")
        console.print("[bold blue]RINGKASAN LAPORAN ANALISIS KERENTANAN WP-ADMIN[/bold blue]", justify="center")
        console.print("="*74, style="bold blue")
        console.print(f"Target URL: [green]{self.target_url}[/green]")
        console.print(f"Waktu Mulai: [yellow]{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
        console.print(f"Waktu Selesai: [yellow]{end_time.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
        console.print(f"Durasi Pemindaian: [yellow]{duration}[/yellow]")
        console.print(f"Kerentanan Ditemukan: [red]{len(self.vulnerabilities_found)}[/red]\n")

        if not self.vulnerabilities_found:
            console.print("[bold green]Tidak ada kerentanan signifikan yang terdeteksi dengan pemindaian ini.[/bold green]")
            console.print("[italic dim]Penting: Ini bukan jaminan keamanan penuh. Lakukan pengujian lebih lanjut.[/italic dim]")
        else:
            table = Table(title="Daftar Kerentanan Ditemukan", show_lines=True)
            table.add_column("Nama Kerentanan", style="cyan", justify="left")
            table.add_column("Tingkat Keparahan", style="magenta", justify="center")
            table.add_column("Deskripsi", style="white", justify="left")
            table.add_column("Rekomendasi Tindakan", style="green", justify="left")

            for vuln in self.vulnerabilities_found:
                severity_color = "green"
                if vuln["severity"] == "LOW":
                    severity_color = "yellow"
                elif vuln["severity"] == "MEDIUM":
                    severity_color = "orange3"
                elif vuln["severity"] == "HIGH":
                    severity_color = "red"

                table.add_row(
                    vuln["name"],
                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                    vuln["description"],
                    vuln["recommended_action"]
                )
            console.print(table)

            if self.output_file:
                report_data = {
                    "scan_summary": {
                        "target_url": self.target_url,
                        "start_time": str(self.start_time),
                        "end_time": str(end_time),
                        "duration": str(duration),
                        "vulnerabilities_count": len(self.vulnerabilities_found)
                    },
                    "vulnerabilities_found": self.vulnerabilities_found
                }
                try:
                    with open(self.output_file, 'w', encoding='utf-8') as f:
                        json.dump(report_data, f, indent=4, ensure_ascii=False)
                    console.print(f"\n[bold green]Laporan JSON berhasil disimpan ke:[/bold green] [cyan]{self.output_file}[/cyan]")
                except IOError as e:
                    console.print(f"[bold red]ERROR:[/bold red] Gagal menulis laporan ke file {self.output_file}: {e}")

        console.print("\n" + "="*74, style="bold blue")
        console.print("[bold blue]DISCLAIMER PENTING:[/bold blue]", justify="center")
        console.print("="*74, style="bold blue")
        console.print("[italic]Alat ini hanya melakukan pemindaian. Tidak ada jaminan keamanan penuh. Selalu lakukan pengujian penetrasi manual dan gunakan alat keamanan profesional untuk evaluasi yang komprehensif.[/italic]")
        console.print("[italic]Pastikan Anda memiliki izin eksplisit untuk menguji situs web apa pun. Penggunaan tanpa izin adalah ilegal dan tidak etis.[/italic]")
        console.print("="*74, style="bold blue")


def main():
        parser = argparse.ArgumentParser(
            description="Skrip Python Profesional untuk Analisis Kerentanan Dasar wp-admin.",
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument(
            '-u', '--url',
            type=str,
            required=True,
            help="URL situs web target (misal: https://example.com)"
        )
        parser.add_argument(
            '-o', '--output',
            type=str,
            help="Nama file untuk menyimpan laporan dalam format JSON (misal: report.json)"
        )
        parser.add_argument(
            '-t', '--timeout',
            type=int,
            default=15,
            help="Batas waktu untuk permintaan HTTP dalam detik (default: 15)"
        )
        parser.add_argument(
            '--user-agent',
            type=str,
            default="WP-Admin-Vulnerability-Scanner/1.0 (Python Security Tool - https://github.com/your-repo-link)", # Ganti dengan link repo Anda jika ada
            help="User-Agent kustom untuk permintaan HTTP"
        )
        parser.add_argument(
            '--no-verify-ssl',
            action='store_true',
            help="Nonaktifkan verifikasi sertifikat SSL (Tidak direkomendasikan untuk produksi!)"
        )

        args = parser.parse_args()

        if not args.url.startswith('http://') and not args.url.startswith('https://'):
            console.print("[bold red]ERROR:[/bold red] URL harus dimulai dengan 'http://' atau 'https://'.")
            sys.exit(1)

        scanner = WPAdminVulnerabilityScanner(
            target_url=args.url,
            output_file=args.output,
            timeout=args.timeout,
            user_agent=args.user_agent
        )

        scanner.session.verify = not args.no_verify_ssl
        if args.no_verify_ssl:
            console.print("[bold yellow]PERINGATAN:[/bold yellow] Verifikasi SSL dinonaktifkan. Ini TIDAK direkomendasikan untuk lingkungan produksi atau pengujian yang sensitif.")
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        try:
            scanner.run_scan()
        except KeyboardInterrupt:
            console.print("\n[bold red]Pemindaian dihentikan oleh pengguna.[/bold red]")
            scanner.generate_report()
        except Exception as e:
            console.print(f"[bold red]Terjadi kesalahan fatal:[/bold red] {e}")
            console.print("[dim]Coba lagi atau periksa URL target dan koneksi internet Anda.[/dim]")

if __name__ == "__main__":
     print(logo)
     main()
