import os, re, sys, time
from urllib.parse import urlsplit
from merlinset import *
from merlincolor import *
from merlinconf import *
from merlinlogo import *
from merlinup import check_update
from merlinconf import edit_config

def _prompt(ctx='merlin'):
    try:
        return input(
            LY + ' ┌──[' + LG + 'termux@localhost' + LY + ']─[' +
            W + '~/merlin/' + ctx + LY + ']\n └─' + LG + '$ ' + W
        )
    except (EOFError, KeyboardInterrupt):
        return ''

_HOST_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$|^\[[0-9A-Fa-f:.]+\]$')

def _valid_host(host):
    return bool(host) and bool(_HOST_RE.match(host))

def _valid_url(url):
    if not url or any(c.isspace() or ord(c) < 32 or c in '`"\'\\<>|;$' for c in url):
        return False
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError on a bad port
    except ValueError:
        return False
    host = parts.hostname or ''
    ipv6 = ':' in host and re.fullmatch(r'[0-9A-Fa-f:.]+', host) is not None
    return parts.scheme in ('http', 'https') and (ipv6 or _valid_host(host))

def _get_url(ctx='scan'):
    print(note + ' Enter target URL (http:// or https://):')
    url = _prompt(ctx).strip()
    if not url:
        print(err + ' No URL entered.')
        return None
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url
    if not _valid_url(url):
        print(err + ' Invalid target URL (illegal characters or malformed host).')
        return None
    return url

def _get_domain(ctx='lookup'):
    print(note + ' Enter domain (e.g. example.com):\n')
    domain = _prompt(ctx).strip()
    if not domain:
        return None
    if not _valid_host(domain):
        print(err + ' Invalid domain.')
        return None
    return domain

def _run(script, args=None):
    import subprocess, signal
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script)
    cmd = [sys.executable, path] + [str(a) for a in (args or [])]
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print(f'\n{note} Scan interrupted. Returning to menu...{N}')
    finally:
        signal.signal(signal.SIGINT, signal.default_int_handler)

def _pause():
    print('')
    try:
        input(LY + ' Press Enter to return to menu...' + N)
    except (EOFError, KeyboardInterrupt):
        pass

def run_wpvuln():
    url = _get_url('wp_vuln')
    if not url:
        return
    print(note + f' Output dir [{OUTPUT_DIR}]: \n', end='')
    out = _prompt('wp_output').strip() or OUTPUT_DIR
    _run('wpvuln.py', ['-u', url, '-o', out])

def run_sqli():
    url = _get_url('sqli_xss')
    if not url:
        return
    print(note + ' Deep scan? [y/N]: \n', end='')
    deep = '--deep' if _prompt('sqli_deep').strip().lower() in ('y','yes') else ''
    _run('websqli.py', ['-u', url] + ([deep] if deep else []))

def run_webshake():
    url = _get_url('crawler')
    if not url:
        return
    print(note + f' Crawl depth [default 2]: \n', end='')
    depth = _prompt('depth').strip()
    depth = depth if depth.isdigit() else '2'
    _run('webshake.py', ['-u', url, '-d', depth])

def run_webanalyst():
    url = _get_url('analyzer')
    if not url:
        return
    print(note + ' Quick mode (skip slow checks)? [y/N]: \n', end='')
    quick = '--quick' if _prompt('quick').strip().lower() in ('y','yes') else ''
    _run('webanalyst.py', ['-u', url] + ([quick] if quick else []))

def run_portscan():
    url = _get_url('portscan')
    if not url:
        return
    print(note + ' Port preset [common/web/db/mail/remote/full] or range (e.g. 1-1024):')
    ports = _prompt('ports').strip() or 'common'
    if not re.fullmatch(r'[A-Za-z]+|[0-9]+([-,][0-9]+)*', ports):
        print(err + ' Invalid port preset/range.')
        return
    print(note + ' Banner grab? [y/N]: \n', end='')
    grab = '--grab-banners' if _prompt('grab').strip().lower() in ('y','yes') else ''
    print(note + ' HTTP probe on web ports? [y/N]: \n', end='')
    http = '--http-probe' if _prompt('http').strip().lower() in ('y','yes') else ''
    _run('portscan.py', ['-u', url, '-p', ports] + [f for f in (grab, http) if f])

def run_dns():
    domain = _get_domain('dns')
    if not domain:
        return
    print(note + ' Run all checks? (zone transfer, subdomains, email sec) [Y/n]: \n', end='')
    a = _prompt('dns_mode').strip().lower()
    flag = '--all' if a in ('', 'y', 'yes') else ''
    _run('dnslookup.py', ['-d', domain] + ([flag] if flag else []))

def run_whois():
    domain = _get_domain('whois')
    if not domain:
        return
    _run('whoislookup.py', ['-d', domain])

def run_techfinger():
    url = _get_url('techfinger')
    if not url:
        return
    _run('techfinger.py', ['-u', url])

def run_headergrab():
    url = _get_url('headers')
    if not url:
        return
    print(note + ' Compare HTTP vs HTTPS redirect? [y/N]: \n', end='')
    cmp = '--compare-http' if _prompt('cmp').strip().lower() in ('y','yes') else ''
    _run('headergrab.py', ['-u', url] + ([cmp] if cmp else []))

def run_sslaudit():
    url = _get_url('ssl_audit')
    if not url:
        return
    _run('sslaudit.py', ['-u', url, '--check-protocols'])

def run_contentdiscovery():
    url = _get_url('content_disc')
    if not url:
        return
    print(note + ' Custom wordlist file path? (leave blank for built-in): \n', end='')
    wl = _prompt('wordlist').strip()
    print(note + ' Threads [default 10]: \n', end='')
    t = _prompt('threads').strip()
    t = t if t.isdigit() else '10'
    _run('contentdiscovery.py', ['-u', url, '-t', t] + (['-w', wl] if wl else []))

def run_hibp():
    print(f"""
  {LC}HIBP Credential Checker sub-modes:{N}
  {G}[{W}1{G}]{LY} Check single password
  {G}[{W}2{G}]{LY} Check password list from file
  {G}[{W}3{G}]{LY} Check email for breaches (requires API key)
  {G}[{W}x{G}]{LR} Back
""")
    sub = _prompt('hibp').strip()
    if sub == '1':
        _run('hibpcheck.py', ['password'])
    elif sub == '2':
        print(note + ' Path to password list file: ', end='')
        fp = _prompt('hibp_file').strip()
        if fp:
            _run('hibpcheck.py', ['file', '-f', fp])
    elif sub == '3':
        print(note + ' Email address: ', end='')
        email = _prompt('hibp_email').strip()
        if not email:
            return
        print(note + ' HIBP API key (get at haveibeenpwned.com/API/Key): \n', end='')
        key = _prompt('hibp_key').strip()
        if email and key:
            _run('hibpcheck.py', ['email', '-e', email, '-k', key])
        elif email:
            _run('hibpcheck.py', ['email', '-e', email])

def run_correlate():
    domain = _get_domain('correlate')
    if not domain:
        return
    print(note + f' Reports dir [{OUTPUT_DIR}]: \n', end='')
    out = _prompt('correlate_output').strip() or OUTPUT_DIR
    _run('correlate.py', ['-d', domain, '-o', out])

def run_risktimeline():
    domain = _get_domain('timeline')
    if not domain:
        return
    print(note + ' Show saved history instead of taking a new snapshot? [y/N]: \n', end='')
    show = '--show' if _prompt('timeline_show').strip().lower() in ('y', 'yes') else ''
    print(note + f' Reports dir [{OUTPUT_DIR}]: \n', end='')
    out = _prompt('timeline_output').strip() or OUTPUT_DIR
    _run('risktimeline.py', ['-d', domain, '-o', out] + ([show] if show else []))

def run_storyreport():
    domain = _get_domain('story')
    if not domain:
        return
    print(note + f' Reports dir [{OUTPUT_DIR}]: \n', end='')
    out = _prompt('story_output').strip() or OUTPUT_DIR
    _run('storyreport.py', ['-d', domain, '-o', out])

def run_policycheck():
    domain = _get_domain('policy')
    if not domain:
        return
    print(note + ' Policy file [auto-detect .merlinpolicy.yml/.yaml/.json]: \n', end='')
    policy = _prompt('policy_path').strip()
    print(note + f' Reports dir [{OUTPUT_DIR}]: \n', end='')
    out = _prompt('policy_output').strip() or OUTPUT_DIR
    _run('policycheck.py', ['-d', domain, '-o', out] + (['-p', policy] if policy else []))

MENU_ITEMS = [
    ('1',  'WP Vulnerability Scan',         run_wpvuln),
    ('2',  'SQLi / XSS / SSTI Scanner',     run_sqli),
    ('3',  'WebShake — Crawler & Recon',    run_webshake),
    ('4',  'Web Security Analyzer',         run_webanalyst),
    ('5',  'Port Scanner + Fingerprint',    run_portscan),
    ('6',  'DNS Deep Lookup & Recon',       run_dns),
    ('7',  'WHOIS Deep Lookup',             run_whois),
    ('8',  'Technology Fingerprint',        run_techfinger),
    ('9',  'HTTP Header Analyzer',          run_headergrab),
    ('10', 'SSL/TLS Auditor',               run_sslaudit),
    ('11', 'Content Discovery',             run_contentdiscovery),
    ('12', 'HIBP Credential Checker',       run_hibp),
    ('13', 'Correlation Engine (Risk Chains)', run_correlate),
    ('14', 'Risk Timeline (Drift Tracking)', run_risktimeline),
    ('15', 'Exposure Story Report',         run_storyreport),
    ('16', 'Policy Gate (CI/CD Check)',     run_policycheck),
    ('0',  'Settings / Config',             edit_config),
    ('u',  'Check Update',                  check_update),
]

def _print_menu():
    print(logo)
    print(f"{LY}{'═'*65}{N}")
    print(f"  {W}MERLIN — Web Security Toolkit{N}")
    print(f"{LY}{'═'*65}{N}\n")

    rows = [item for item in MENU_ITEMS if item[0] not in ('0','u')]
    mid  = (len(rows) + 1) // 2
    left = rows[:mid]
    right = rows[mid:]

    for i in range(max(len(left), len(right))):
        litem = left[i]  if i < len(left)  else None
        ritem = right[i] if i < len(right) else None

        def _fmt(item):
            if item is None:
                return ' ' * 35
            key, label, _ = item
            return f"  {G}[{W}{key:>2}{G}]{LY} {label:<26}{N}"

        print(_fmt(litem) + '  ' + _fmt(ritem))

    print('')
    print(f"  {G}[{W} 0{G}]{LY} Settings / Config{N}"
          f"             {G}[{W} u{G}]{LY} Check Update{N}")
    print(f"  {G}[{R} x{G}]{LR} Exit{N}")
    print(f"\n{LY}{'═'*65}{N}")

def main():
    dispatch = {item[0]: item[2] for item in MENU_ITEMS}
    for k in list(dispatch.keys()):
        if k.isdigit() and len(k) == 1:
            dispatch['0' + k] = dispatch[k]

    while True:
        _print_menu()

        try:
            choice = input(
                LG + '┌──[' + LY + 'termux@localhost' + LG + ']─[' +
                W + '~/choose_menu' + LG + ']\n└─' + LY + '$ ' + W
            ).strip()
        except (EOFError, KeyboardInterrupt):
            choice = 'x'

        if not choice:
            continue

        if choice.lower() in ('x', 'exit', 'quit', 'q'):
            for msg in [
                note + ' Close session...done',
                note + ' End process...done',
                note + ' Clear cache tool...done',
            ]:
                print(msg)
                time.sleep(0.4)
            print(LY + '\n----- ' + LG + 'Goodbye' + LY + ' -----' + N)
            time.sleep(0.5)
            sys.exit(0)

        if choice in dispatch:
            print('')
            dispatch[choice]()
            _pause()
        else:
            print(f"\n{err} Unknown command: {W}{choice}{N}")
            time.sleep(0.8)

if __name__ == '__main__':
    main()
