import requests
import argparse
import logging
import sys
import re
from urllib.parse import urljoin, urlparse
import ssl
from merlinset import *
from merlinlogo import *

try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    class Fore:
        BLACK = WHITE = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = RESET = ''
    class Style:
        DIM = NORMAL = BRIGHT = RESET_ALL = ''

INFO = Fore.CYAN + Style.BRIGHT
SUCCESS = Fore.GREEN + Style.BRIGHT
WARNING = Fore.YELLOW + Style.BRIGHT
ERROR = Fore.RED + Style.BRIGHT
RESET = Style.RESET_ALL

logging.basicConfig(level=logging.INFO, format=LC + '[' + W + '%(asctime)s' + LC + ']' + LG + ' %(message)s', datefmt='%H:%M:%S')

def print_banner():
    print(f"{INFO}{'='*50}")
    print(f"{INFO}{' ' * 10}WEB VULN ANALYZER{' ' * 10}")
    print(f"{INFO}{'='*50}{RESET}")
    print(f"{INFO}Created by [Djunekz] [Anonymous] [RedHh] [MrxXx]{RESET}\n")

def print_status(message, status_type="INFO"):
    if status_type == "INFO":
        logging.info(f"{INFO}[INFO]{RESET} {message}")
    elif status_type == "SUCCESS":
        logging.warning(f"{INFO}[{SUCCESS}SUKSES{INFO}]{RESET} {message}")
    elif status_type == "WARNING":
        logging.warning(f"{INFO}[{WARNING}PERINGATAN{INFO}]{RESET} {message}")
    elif status_type == "ERROR":
        logging.error(f"{INFO}[{ERROR}ERROR{INFO}]{RESET} {message}")
    else:
        print(message)

def validate_url(url):
    parsed = urlparse(url)
    return all([parsed.scheme, parsed.netloc])


def check_headers(session, url):
    print_status(f"Memeriksa header keamanan untuk: {url}", "INFO")
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        if 'X-Content-Type-Options' in headers and headers['X-Content-Type-Options'] == 'nosniff':
            print_status(f"request{SUCCESS} X-Content-Type-Options: nosniff ditemukan. Baik!", "SUCCESS")
        else:
            print_status(f"info{WARNING} X-Content-Type-Options: nosniff tidak ditemukan atau salah. Potensi MIME-sniffing.", "WARNING")

        if 'X-Frame-Options' in headers and (headers['X-Frame-Options'] == 'DENY' or headers['X-Frame-Options'] == 'SAMEORIGIN'):
            print_status(f"status{SUCCESS} X-Frame-Options: {headers['X-Frame-Options']} ditemukan. Melindungi dari Clickjacking.", "SUCCESS")
        else:
            print_status(f"info{WARNING} X-Frame-Options: tidak ditemukan atau tidak memadai. Potensi Clickjacking.", "WARNING")

        if 'Strict-Transport-Security' in headers:
            print_status(f"status{SUCCESS} Strict-Transport-Security (HSTS) ditemukan. Mendorong koneksi HTTPS.", "SUCCESS")
        else:
            print_status(f"status{WARNING} Strict-Transport-Security (HSTS) tidak ditemukan. Rentan terhadap serangan downgrade HTTPS.", "WARNING")

        if 'Content-Security-Policy' in headers:
            print_status(f"info{SUCCESS} Content-Security-Policy (CSP) ditemukan. Melindungi dari XSS dan injeksi data.", "SUCCESS")
        else:
            print_status(f"check{WARNING} Content-Security-Policy (CSP) tidak ditemukan. Rentan terhadap XSS dan injeksi data.", "WARNING")

        if 'Referrer-Policy' in headers:
            print_status(f"check{SUCCESS} Referrer-Policy ditemukan: {headers['Referrer-Policy']}. Baik untuk privasi.", "SUCCESS")
        else:
            print_status(f"check{WARNING} Referrer-Policy tidak ditemukan. Potensi kebocoran informasi referer.", "WARNING")

        print_status("-" * 40)

    except requests.exceptions.RequestException as e:
        print_status(f"info{ERROR} Gagal memeriksa header: {e}", "ERROR")

def check_robots_txt(session, base_url):
    print_status(f"Memeriksa robots.txt untuk: {base_url}", "INFO")
    robots_url = urljoin(base_url, '/robots.txt')
    try:
        response = session.get(robots_url, timeout=5)
        if response.status_code == 200:
            print_status(f"{INFO}robots.txt ditemukan di: {robots_url}", "SUCCESS")
            disallows = re.findall(r"Disallow:\s*(.*)", response.text, re.IGNORECASE)
            if disallows:
                print_status(f"info{WARNING} Path '{RESET}Disallow{WARNING}' ditemukan. Periksa manual untuk potensi informasi sensitif:", "WARNING")
                for path in disallows:
                    print(f"    - {SUCCESS}{path}")
            else:
                print_status(f"info{ERROR} Tidak ada path '{RESET}Disallow{ERROR}' yang eksplisit ditemukan dalam robots.txt.", "INFO")
        elif response.status_code == 404:
            print_status(f"{INFO}robots.txt tidak ditemukan (404 Not Found).", "INFO")
        else:
            print_status(f"status{WARNING} robots.txt mengembalikan status {response.status_code}.", "WARNING")
        print_status("-" * 40)
    except requests.exceptions.RequestException as e:
        print_status(f"info{ERROR} Gagal memeriksa robots.txt: {e}", "ERROR")

def check_sitemap_xml(session, base_url):
    print_status(f"Memeriksa sitemap.xml untuk: {base_url}", "INFO")
    sitemap_url = urljoin(base_url, '/sitemap.xml')
    try:
        response = session.get(sitemap_url, timeout=5)
        if response.status_code == 200 and '<?xml' in response.text:
            print_status(f"request{SUCCESS} sitemap.xml ditemukan di: {sitemap_url}", "SUCCESS")
            print_status(f"{INFO} Periksa sitemap.xml secara manual untuk mengungkap struktur URL.", "INFO")
        elif response.status_code == 404:
            print_status(f"request{INFO} sitemap.xml tidak ditemukan (404 Not Found).", "INFO")
        else:
            print_status(f"status{WARNING} sitemap.xml mengembalikan status {response.status_code} atau bukan XML yang valid.", "WARNING")
        print_status("-" * 40)
    except requests.exceptions.RequestException as e:
        print_status(f"status{ERROR} Gagal memeriksa sitemap.xml: {e}", "ERROR")

def check_directory_listing(session, base_url, common_dirs=['/admin/', '/uploads/', '/backup/', '/test/']):
    print_status(f"Mencoba mencari directory listing pada direktori umum di: {base_url}", "INFO")
    found_vulnerability = False
    for path in common_dirs:
        test_url = urljoin(base_url, path)
        try:
            response = session.get(test_url, timeout=5)
            if response.status_code == 200 and "Index of /" in response.text:
                print_status(f"Check{ERROR} Potensi Directory Listing ditemukan di: {test_url}", "ERROR")
                found_vulnerability = True
            elif response.status_code == 403:
                print_status(f"info Akses ditolak (403 Forbidden) untuk {test_url}. Mungkin dilindungi.", "INFO")
            elif response.status_code == 404:
                print_status(f"response {ERROR}{test_url}{RESET} tidak ditemukan (404).", "INFO")
                pass
            else:
                print_status(f"response {ERROR}{test_url}{RESET} mengembalikan status {SUCCESS}{response.status_code}.", "INFO") # Terlalu verbose
                pass
        except requests.exceptions.RequestException as e:
            print_status(f"request{WARNING} Gagal mengakses {test_url}: {e}", "WARNING")
            pass
    if not found_vulnerability:
        print_status(f"info{WARNING} Tidak ada directory listing yang jelas ditemukan pada direktori umum yang diuji.", "INFO")
    print_status("-" * 40)

def check_ssl_tls(session, url):
    print_status(f"Memeriksa konfigurasi SSL/TLS untuk: {url}", "INFO")
    if not url.startswith("https://"):
        print_status(f"check{WARNING} Website tidak menggunakan HTTPS. Sangat rentan terhadap penyadapan.", "WARNING")
        print_status("-" * 40)
        return

    try:
        response = session.get(url, timeout=10)
        if response.ok:
            print_status(f"info{SUCCESS} Website menggunakan HTTPS. Koneksi terenkripsi.", "SUCCESS")
        else:
            print_status(f"info{ERROR} Gagal mengakses URL HTTPS. Mungkin ada masalah sertifikat.", "ERROR")
    except requests.exceptions.SSLError:
        print_status(f"check{ERROR} Kesalahan SSL/TLS saat mencoba mengakses {url}. Periksa sertifikat.", "ERROR")
    except requests.exceptions.RequestException as e:
        print_status(f"status{ERROR} Gagal memeriksa SSL/TLS: {e}", "ERROR")
    print_status("-" * 40)

def main():
    print(logo)
    parser = argparse.ArgumentParser(description=f"{INFO}Alat analisis kerentanan website.{RESET}")
    parser.add_argument('-u', '--url', type=str, required=True,
                        help='URL target website (contoh: https://example.com)')
    parser.add_argument('-n', '--no-ssl-verify', action='store_true',
                        help='Nonaktifkan verifikasi SSL (tidak disarankan untuk produksi).')

    args = parser.parse_args()

    target_url = args.url
    verify_ssl = not args.no_ssl_verify

    if not validate_url(target_url):
        print_status(f"URL tidak valid: {target_url}. Harap masukkan URL lengkap dengan skema (http:// atau https://).", "ERROR")
        sys.exit(1)

    print_status(f"Memulai analisis untuk: {target_url}", "INFO")
    print_status(f"Verifikasi SSL: {'Aktif' if verify_ssl else 'Nonaktif (TIDAK DISARANKAN)'}", "INFO")
    print("\n" + "=" * 50 + "\n")

    session = requests.Session()
    session.verify = verify_ssl
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    })

    try:
        print_status(f"Mencoba koneksi awal ke {target_url}...", "INFO")
        response = session.get(target_url, timeout=15)
        if response.status_code == 200:
            print_status(f"Website dapat dijangkau (Status: {response.status_code}).", "SUCCESS")
        else:
            print_status(f"Website mengembalikan status: {response.status_code}. Mungkin tidak dapat diakses normal.", "WARNING")
            if response.status_code >= 400:
                pass
        print("\n" + "=" * 50 + "\n")

        check_ssl_tls(session, target_url)
        check_headers(session, target_url)
        check_robots_txt(session, target_url)
        check_sitemap_xml(session, target_url)
        check_directory_listing(session, target_url)

    except requests.exceptions.ConnectionError:
        print_status(f"Tidak dapat terhubung ke {target_url}. Periksa URL atau koneksi internet Anda.", "ERROR")
    except requests.exceptions.Timeout:
        print_status(f"Permintaan ke {target_url} waktu habis (timeout).", "ERROR")
    except requests.exceptions.RequestException as e:
        print_status(f"Terjadi kesalahan permintaan: {e}", "ERROR")
    except Exception as e:
        print_status(f"Terjadi kesalahan tidak terduga: {e}", "ERROR")
    finally:
        print(f"\n{INFO}{'='*50}")
        print(f"{INFO}Analisis Selesai.{RESET}")
        print(f"{INFO}PENTING: Alat ini hanya melakukan pemeriksaan. Hasil tidak mutlak.{RESET}")
        print(f"{INFO}Selalu lakukan pengujian manual yang menyeluruh sebelum memindai website.{RESET}")
        print(f"{INFO}{'='*50}{RESET}")

if __name__ == "__main__":
    main()
