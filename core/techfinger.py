import requests
import argparse
import json
import os
import re
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import TIMEOUT, USER_AGENT, OUTPUT_DIR, SAVE_REPORTS, VERIFY_SSL

TECH_SIGNATURES = {
    "WordPress":        {"header":[], "body":[r'wp-content',r'wp-includes',r'wp-json',r'/wp-login\.php'], "meta":[r'WordPress'], "cookie":[]},
    "Joomla":           {"header":[], "body":[r'Joomla!',r'/components/com_',r'/media/jui/'], "meta":[], "cookie":[r'joomla_session']},
    "Drupal":           {"header":[r'X-Generator: Drupal',r'X-Drupal-Cache'], "body":[r'Drupal\.settings',r'/sites/default/files/'], "meta":[r'Drupal'], "cookie":[r'SESS[a-f0-9]+']},
    "Magento":          {"header":[], "body":[r'Mage\.',r'skin/frontend',r'varien/js'], "meta":[], "cookie":[r'frontend=']},
    "Shopify":          {"header":[], "body":[r'cdn\.shopify\.com',r'Shopify\.theme',r'myshopify\.com'], "meta":[], "cookie":[r'_shopify_']},
    "Wix":              {"header":[], "body":[r'static\.wixstatic\.com',r'wixsite\.com'], "meta":[], "cookie":[]},
    "Squarespace":      {"header":[], "body":[r'squarespace\.com',r'sqspcdn\.com'], "meta":[], "cookie":[r'ss-session']},
    "PrestaShop":       {"header":[r'X-Powered-By: PrestaShop'], "body":[r'prestashop',r'/modules/ps_'], "meta":[], "cookie":[r'PrestaShop']},
    "OpenCart":         {"header":[], "body":[r'route=common',r'catalog/view/theme'], "meta":[], "cookie":[r'OCSESSID']},
    "WHMCS":            {"header":[], "body":[r'whmcs',r'clientarea\.php'], "meta":[], "cookie":[]},
    "Ghost":            {"header":[], "body":[r'ghost-sdk',r'content\.ghost\.org'], "meta":[r'Ghost'], "cookie":[]},
    "Webflow":          {"header":[], "body":[r'webflow\.com',r'js\.webflow\.com'], "meta":[], "cookie":[]},
    "Blogger":          {"header":[], "body":[r'blogger\.com',r'blogspot\.com'], "meta":[], "cookie":[]},
    "Medium":           {"header":[], "body":[r'medium\.com/_/api',r'miro\.medium\.com'], "meta":[], "cookie":[]},

    "Laravel":          {"header":[], "body":[r'laravel_session',r'XSRF-TOKEN'], "meta":[], "cookie":[r'laravel_session',r'XSRF-TOKEN']},
    "Django":           {"header":[], "body":[r'csrfmiddlewaretoken',r'__admin_media_prefix__'], "meta":[], "cookie":[r'csrftoken',r'sessionid']},
    "Flask":            {"header":[], "body":[r'Werkzeug',r'flask'], "meta":[], "cookie":[r'session=']},
    "Ruby on Rails":    {"header":[r'X-Runtime'], "body":[r'authenticity_token',r'rails-ujs'], "meta":[], "cookie":[r'_session_id']},
    "ASP.NET":          {"header":[r'X-AspNet-Version',r'X-Powered-By: ASP'], "body":[r'__VIEWSTATE',r'__EVENTVALIDATION',r'__doPostBack'], "meta":[], "cookie":[r'ASP\.NET_SessionId']},
    "ASP.NET Core":     {"header":[r'X-Powered-By: ASP\.NET'], "body":[r'asp-validation',r'asp-for='], "meta":[], "cookie":[]},
    "PHP":              {"header":[r'X-Powered-By: PHP'], "body":[r'\.php'], "meta":[], "cookie":[r'PHPSESSID']},
    "Node.js":          {"header":[r'X-Powered-By: Express'], "body":[], "meta":[], "cookie":[]},
    "CodeIgniter":      {"header":[], "body":[r'ci_session'], "meta":[], "cookie":[r'ci_session']},
    "Symfony":          {"header":[], "body":[r'_symfony_',r'sf_redirect'], "meta":[], "cookie":[r'PHPSESSID',r'sf2_session']},
    "Spring Boot":      {"header":[r'X-Application-Context'], "body":[r'spring',r'org\.springframework'], "meta":[], "cookie":[r'JSESSIONID']},
    "CakePHP":          {"header":[], "body":[r'cakephp',r'/cake/'], "meta":[], "cookie":[r'CAKEPHP']},
    "Yii":              {"header":[], "body":[r'yii\.js'], "meta":[], "cookie":[r'YII_CSRF_TOKEN']},
    "Next.js":          {"header":[r'X-Powered-By: Next\.js'], "body":[r'__NEXT_DATA__',r'/_next/'], "meta":[], "cookie":[]},
    "Nuxt.js":          {"header":[], "body":[r'__nuxt',r'/_nuxt/'], "meta":[], "cookie":[]},
    "SvelteKit":        {"header":[], "body":[r'__sveltekit',r'_app/immutable'], "meta":[], "cookie":[]},

    "Apache":           {"header":[r'Server: Apache'], "body":[], "meta":[], "cookie":[]},
    "Nginx":            {"header":[r'Server: nginx'], "body":[], "meta":[], "cookie":[]},
    "IIS":              {"header":[r'Server: Microsoft-IIS'], "body":[], "meta":[], "cookie":[]},
    "LiteSpeed":        {"header":[r'Server: LiteSpeed',r'X-Powered-By: LiteSpeed'], "body":[], "meta":[], "cookie":[]},
    "Caddy":            {"header":[r'Server: Caddy'], "body":[], "meta":[], "cookie":[]},
    "OpenResty":        {"header":[r'Server: openresty'], "body":[], "meta":[], "cookie":[]},
    "Tomcat":           {"header":[r'Server: Apache-Coyote',r'X-Powered-By: Tomcat'], "body":[r'Apache Tomcat'], "meta":[], "cookie":[r'JSESSIONID']},

    "Cloudflare":       {"header":[r'CF-Ray',r'Server: cloudflare',r'cf-cache-status'], "body":[], "meta":[], "cookie":[r'__cfduid',r'cf_clearance']},
    "Fastly":           {"header":[r'X-Served-By.*fastly',r'Fastly-Debug-Digest'], "body":[], "meta":[], "cookie":[]},
    "AWS CloudFront":   {"header":[r'X-Cache.*CloudFront',r'Via.*CloudFront'], "body":[], "meta":[], "cookie":[]},
    "Varnish":          {"header":[r'X-Varnish',r'Via.*varnish'], "body":[], "meta":[], "cookie":[]},
    "Akamai":           {"header":[r'X-Check-Cacheable',r'X-Akamai-'],  "body":[], "meta":[], "cookie":[]},
    "Sucuri":           {"header":[r'X-Sucuri-ID',r'X-Sucuri-Cache'], "body":[], "meta":[], "cookie":[]},
    "Imperva":          {"header":[r'X-Iinfo',r'incap_ses'], "body":[], "meta":[], "cookie":[r'incap_ses',r'visid_incap']},

    "Google Analytics": {"header":[], "body":[r'google-analytics\.com/analytics\.js',r'gtag\(',r'UA-[0-9]+-[0-9]+',r'G-[A-Z0-9]+'], "meta":[], "cookie":[r'_ga',r'_gid']},
    "Google Tag Manager":{"header":[], "body":[r'googletagmanager\.com/gtm\.js',r'GTM-[A-Z0-9]+'], "meta":[], "cookie":[]},
    "Facebook Pixel":   {"header":[], "body":[r'connect\.facebook\.net/.*fbevents\.js',r'fbq\('], "meta":[], "cookie":[r'_fbp']},
    "Hotjar":           {"header":[], "body":[r'hotjar\.com',r'hj\('], "meta":[], "cookie":[r'_hjid']},
    "HubSpot":          {"header":[], "body":[r'js\.hs-scripts\.com',r'hubspot\.com/hubspot\.js'], "meta":[], "cookie":[r'hubspotutk']},
    "Intercom":         {"header":[], "body":[r'widget\.intercom\.io',r'intercomSettings'], "meta":[], "cookie":[r'intercom-']},
    "Mixpanel":         {"header":[], "body":[r'cdn\.mxpnl\.com',r'mixpanel\.track'], "meta":[], "cookie":[r'mp_']},
    "Segment":          {"header":[], "body":[r'cdn\.segment\.com',r'analytics\.identify'], "meta":[], "cookie":[]},
    "Crisp":            {"header":[], "body":[r'client\.crisp\.chat'], "meta":[], "cookie":[r'crisp-client']},
    "Tawk.to":          {"header":[], "body":[r'tawk\.to'], "meta":[], "cookie":[]},
    "Zendesk":          {"header":[], "body":[r'zendesk\.com/embeddables',r'zE\('], "meta":[], "cookie":[r'_zd_']},

    "React":            {"header":[], "body":[r'react-dom',r'__reactFiber',r'react\.development\.js'], "meta":[], "cookie":[]},
    "Vue.js":           {"header":[], "body":[r'vue\.runtime',r'__vue__',r'v-bind:',r'@click='], "meta":[], "cookie":[]},
    "Angular":          {"header":[], "body":[r'ng-version',r'ng-app',r'angular\.min\.js'], "meta":[], "cookie":[]},
    "jQuery":           {"header":[], "body":[r'jquery(\.min)?\.js',r'jQuery\.fn\.jquery',r'\$\.ajax'], "meta":[], "cookie":[]},
    "Bootstrap":        {"header":[], "body":[r'bootstrap(\.min)?\.css',r'bootstrap(\.min)?\.js'], "meta":[], "cookie":[]},
    "Tailwind CSS":     {"header":[], "body":[r'tailwindcss',r'tw-',r'class="[^"]*\bflex\b'], "meta":[], "cookie":[]},
    "Alpine.js":        {"header":[], "body":[r'x-data=',r'alpinejs'], "meta":[], "cookie":[]},
    "HTMX":             {"header":[], "body":[r'hx-get=',r'hx-post=',r'htmx\.min\.js'], "meta":[], "cookie":[]},
    "Ember.js":         {"header":[], "body":[r'Ember\.',r'ember-view',r'ember\.min\.js'], "meta":[], "cookie":[]},
    "Backbone.js":      {"header":[], "body":[r'Backbone\.',r'backbone(\.min)?\.js'], "meta":[], "cookie":[]},

    "Stripe":           {"header":[], "body":[r'js\.stripe\.com',r'Stripe\('], "meta":[], "cookie":[]},
    "PayPal":           {"header":[], "body":[r'paypal\.com/sdk/js',r'paypal\.Buttons'], "meta":[], "cookie":[]},
    "Midtrans":         {"header":[], "body":[r'midtrans\.com',r'MidtransNew3ds'], "meta":[], "cookie":[]},
    "Xendit":           {"header":[], "body":[r'xendit\.co',r'Xendit\.card'], "meta":[], "cookie":[]},

    "Vercel":           {"header":[r'X-Vercel-Id',r'Server: Vercel'], "body":[], "meta":[], "cookie":[]},
    "Netlify":          {"header":[r'X-Nf-Request-Id',r'Server: Netlify'], "body":[], "meta":[], "cookie":[]},
    "GitHub Pages":     {"header":[r'Server: GitHub\.com'], "body":[], "meta":[], "cookie":[]},
    "Heroku":           {"header":[r'Via.*heroku'], "body":[], "meta":[], "cookie":[r'heroku-session']},
    "Render":           {"header":[r'X-Render-Origin-Server'], "body":[], "meta":[], "cookie":[]},
    "Firebase Hosting": {"header":[r'X-Firebase-Appcheck',r'Server: Firebase'], "body":[r'firebaseapp\.com'], "meta":[], "cookie":[]},
}

VERSION_PATTERNS = {
    "WordPress":    r'(?:wp-includes/js/wp-emoji-release\.min\.js\?ver=|meta name=["\']generator["\'] content=["\']WordPress\s+)([0-9.]+)',
    "jQuery":       r'jQuery v([0-9.]+)',
    "Bootstrap":    r'Bootstrap v([0-9.]+)',
    "React":        r'react@([0-9.]+)',
    "Vue.js":       r'Vue\.version\s*=\s*["\']([0-9.]+)',
    "Angular":      r'ng-version=["\']([0-9.]+)',
    "PHP":          r'X-Powered-By: PHP/([0-9.]+)',
    "Apache":       r'Server: Apache/([0-9.]+)',
    "Nginx":        r'Server: nginx/([0-9.]+)',
}

def detect_technologies(url):
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})

    try:
        resp = session.get(url, timeout=TIMEOUT, verify=VERIFY_SSL, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {}, {}, {}, str(e)

    headers_raw = '\n'.join(f"{k}: {v}" for k, v in resp.headers.items())
    body        = resp.text
    cookies_raw = '; '.join(f"{c.name}={c.value}" for c in resp.cookies)

    soup         = BeautifulSoup(body, 'html.parser')
    meta_content = ' '.join(tag.get('content', '') for tag in soup.find_all('meta'))

    detected = {}
    for tech, sigs in TECH_SIGNATURES.items():
        matches = []
        for pat in sigs.get('header', []):
            if re.search(pat, headers_raw, re.IGNORECASE):
                matches.append(f"header:{pat[:30]}")
        for pat in sigs.get('body', []):
            if re.search(pat, body, re.IGNORECASE):
                matches.append(f"body:{pat[:30]}")
        for pat in sigs.get('meta', []):
            if re.search(pat, meta_content, re.IGNORECASE):
                matches.append(f"meta:{pat[:30]}")
        for pat in sigs.get('cookie', []):
            if re.search(pat, cookies_raw, re.IGNORECASE):
                matches.append(f"cookie:{pat[:30]}")
        if matches:
            detected[tech] = list(set(matches))

    versions = {}
    combined = headers_raw + '\n' + body
    for tech, pat in VERSION_PATTERNS.items():
        if tech in detected:
            m = re.search(pat, combined, re.IGNORECASE)
            if m:
                versions[tech] = m.group(1)

    leak_headers = {}
    for h in ['Server', 'X-Powered-By', 'X-Generator', 'X-AspNet-Version',
               'X-Runtime', 'X-Application-Context', 'Via', 'CF-Ray']:
        if h in resp.headers:
            leak_headers[h] = resp.headers[h]

    return detected, versions, leak_headers, None

CATEGORIES = {
    'CMS':        ['WordPress','Joomla','Drupal','Magento','Shopify','Wix','Squarespace',
                   'PrestaShop','OpenCart','WHMCS','Ghost','Webflow','Blogger','Medium'],
    'Framework':  ['Laravel','Django','Flask','Ruby on Rails','ASP.NET','ASP.NET Core',
                   'PHP','Node.js','CodeIgniter','Symfony','Spring Boot','CakePHP',
                   'Yii','Next.js','Nuxt.js','SvelteKit'],
    'Web Server': ['Apache','Nginx','IIS','LiteSpeed','Caddy','OpenResty','Tomcat'],
    'CDN/Proxy':  ['Cloudflare','Fastly','AWS CloudFront','Varnish','Akamai','Sucuri','Imperva'],
    'Analytics':  ['Google Analytics','Google Tag Manager','Facebook Pixel','Hotjar',
                   'HubSpot','Intercom','Mixpanel','Segment','Crisp','Tawk.to','Zendesk'],
    'JS Library': ['React','Vue.js','Angular','jQuery','Bootstrap','Tailwind CSS',
                   'Alpine.js','HTMX','Ember.js','Backbone.js'],
    'Payment':    ['Stripe','PayPal','Midtrans','Xendit'],
    'Hosting':    ['Vercel','Netlify','GitHub Pages','Heroku','Render',
                   'Firebase Hosting'],
}

def print_results(url, detected, versions, leak_headers, error):
    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}Tech Fingerprint{N} → {LC}{url}{N}")
    print(f"{LY}{'═'*65}{N}")

    if error:
        print(f"  {err} {error}")
        return

    if not detected:
        print(f"  {DG}No known technologies detected.{N}")
        return

    for cat, techs in CATEGORIES.items():
        found = {t: detected[t] for t in techs if t in detected}
        if found:
            print(f"\n  {LC}── {cat} ──{N}")
            for tech, matches in found.items():
                ver = LY + ' v' + versions[tech] + N if tech in versions else ''
                print(f"    {sukses} {LG}{tech}{ver}{N}  {DG}({', '.join(matches[:2])}){N}")

    others = {t: v for t, v in detected.items()
              if not any(t in tlist for tlist in CATEGORIES.values())}
    if others:
        print(f"\n  {LC}── Other ──{N}")
        for tech, matches in others.items():
            ver = LY + ' v' + versions[tech] + N if tech in versions else ''
            print(f"    {sukses} {LG}{tech}{ver}{N}  {DG}({', '.join(matches[:2])}){N}")

    if leak_headers:
        print(f"\n  {LC}── Server Info Headers (potential leak) ──{N}")
        for k, v in leak_headers.items():
            print(f"    {warn} {LY}{k}{N}: {W}{v}{N}")

    print(f"\n  {LC}Total detected: {LG}{len(detected)}{N} technologies")
    print(f"{LY}{'═'*65}{N}")

def main():
    print(logo)
    parser = argparse.ArgumentParser(description=LY + "Merlin — Technology Fingerprinter (70+ sigs)")
    parser.add_argument('-u', '--url',    required=True)
    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    detected, versions, leak_headers, error = detect_technologies(url)
    print_results(url, detected, versions, leak_headers, error)

    if SAVE_REPORTS and not error:
        os.makedirs(args.output_dir, exist_ok=True)
        domain = urlparse(url).netloc.replace('.', '_')
        fname  = os.path.join(args.output_dir, f"techfinger_{domain}.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump({
                "target": url, "technologies": detected,
                "versions": versions, "leak_headers": leak_headers,
            }, f, indent=4, ensure_ascii=False)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    main()
