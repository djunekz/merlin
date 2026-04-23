import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import argparse
import logging
import time
import sys
from webshakeset import *
from merlinlogo import *

#logging.basicConfig(level=logging.INFO, format=LC + '[' + W + '%(asctime)s' + LC + ']' + LG + ' - ' + LC + '%(levelname)s ' + LG + '- ' + LB + '%(message)s', datefmt='%H:%M:%S')
logging.basicConfig(level=logging.INFO, format=LC + '[' + W + '%(asctime)s' + LC + ']' + LG + ' %(message)s', datefmt='%H:%M:%S')

class WebCrawler:
    def __init__(self, start_url, max_depth=2):
        self.start_url = self._normalize_url(start_url)
        self.max_depth = max_depth
        self.visited_urls = set()
        self.internal_links = set()
        self.external_links = set()
        self.base_domain = urlparse(self.start_url).netloc
        logging.info(f"{pss} {LY}starting {LC}{self.start_url} with depth {max_depth}{N}")

    def _normalize_url(self, url):
        if not urlparse(url).scheme:
            return "https://" + url
        return url

    def _is_internal(self, url):
        return urlparse(url).netloc == self.base_domain

    def crawl(self, url, depth):
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        logging.info(f"{star}{LY} request{N} {url}")

        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code != 200:
                logging.warning(f"{min}{LY} status{LR} Failed GET parameters{LY} {url} {N}-{LG} Status{N}:{W} {response.status_code}")
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                absolute_url = urljoin(url, href)

                parsed_absolute_url = urlparse(absolute_url)
                clean_url = parsed_absolute_url._replace(fragment="").geturl()

                if clean_url in self.visited_urls:
                    continue

                if self._is_internal(clean_url):
                    self.internal_links.add(clean_url)
                    self.crawl(clean_url, depth + 1)
                else:
                    self.external_links.add(clean_url)

        except requests.exceptions.RequestException as e:
            logging.error(f"{min}{LY} status{LR} Request Time Out {LY}{url}{LG}:{W} {e}{N}")
            logging.warning(f"{min}{LY} reject{LR} Error GET parameters {sss}")
            sys.exit()
        except Exception as e:
            logging.error(f"{min}{LY} check{LR} Request Time Out {LY}{url}{LG}: {W}{e}{N}")
            logging.warning(f"{min}{LY} reject{LR} Error GET parameters {sss}")
            sys.exit()

    def start(self):
        print(f"\n--- {LG}Memulai Web Analyzer{LY} : {LC}{self.start_url}{N} ---")
        self.crawl(self.start_url, 0)

        print(f"\n{plus} {LR}{BG}Check Crawl Analyst{N} {LY}:")
        print(f"{W}Domain Target{W}:{LY} {self.base_domain}{N}")
        print(f"\n{plus} {LR}{BG}Search Link Internal{N}{W} - [{LG}CHECKING{W}]{LY} :")
        for link in sorted(list(self.internal_links)):
            print(f"  {sukses} Internal Found {N}- {LY}INFO {N}- {link}")

        print(f"\n{plus} {LR}{BG}Search Link External{N}{W} - [{LG}CHECKING{W}]{LY} :")
        for link in sorted(list(self.external_links)):
            print(f"  {sukses} External Found {N}- {LY}INFO {N}- {link}")

        print(LY + "\n ----- " + LG + "Analyst Successful" + LY + " -----" + N)
        print(f"\n{sukses} {U}Total Link Internal Found{N}{W} - [{LG}{len(self.internal_links)} Links{W}]{LY}")
        print(f"{sukses} {U}Total Link External Found{N}{W} - [{LG}{len(self.external_links)} Links{W}]{LY}\n")

if __name__ == "__main__":
    print(logo)
    parser = argparse.ArgumentParser(description=LY + "How to use WebShake Information help tool." + LG)
    parser.add_argument("-u", "--url", dest="url", help="URL awal untuk crawling " + LY + "(" + W + "contoh: http://example.com" + LY + ")" + LG, required=True)
    parser.add_argument("-d", "--depth", dest="max_depth", type=int, default=2, 
                        help="Kedalaman maksimum " + LY + "(" + W + "default: 2" + LY + ")" + LG)
    args = parser.parse_args()

    crawler = WebCrawler(args.url, args.max_depth)
    crawler.start()
