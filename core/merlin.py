import os, sys, time
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

def _get_url(ctx='scan'):
    print(note + ' Enter target URL (http:// or https://):')
    url = _prompt(ctx)
    if not url:
        print(err + ' No URL entered.')
        return None
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url
    return url

def _get_domain(ctx='lookup'):
    print(note + ' Enter domain (e.g. example.com):\n')
    domain = _prompt(ctx)
    return domain.strip() if domain else None

def _run(script, args=''):
    import subprocess, signal
    cmd = f'python {script} {args}' if args else f'python {script}'
    try:
        subprocess.run(cmd, shell=True)
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
    _run('wpvuln.py', f'-u "{url}" -o "{out}"')

def run_sqli():
    url = _get_url('sqli_xss')
    if not url:
        return
    print(note + ' Deep scan? [y/N]: \n', end='')
    deep = '--deep' if _prompt('sqli_deep').strip().lower() in ('y','yes') else ''
    _run('websqli.py', f'-u "{url}" {deep}')

def run_webshake():
    url = _get_url('crawler')
    if not url:
        return
    print(note + f' Crawl depth [default 2]: \n', end='')
    depth = _prompt('depth').strip()
    depth = depth if depth.isdigit() else '2'
    _run('webshake.py', f'-u "{url}" -d {depth}')

def run_webanalyst():
    url = _get_url('analyzer')
    if not url:
        return
    print(note + ' Quick mode (skip slow checks)? [y/N]: \n', end='')
    quick = '--quick' if _prompt('quick').strip().lower() in ('y','yes') else ''
    _run('webanalyst.py', f'-u "{url}" {quick}')

def run_portscan():
    url = _get_url('portscan')
    if not url:
        return
    print(note + ' Port preset [common/web/db/mail/remote/full] or range (e.g. 1-1024):')
    ports = _prompt('ports').strip() or 'common'
    print(note + ' Banner grab? [y/N]: \n', end='')
    grab = '--grab-banners' if _prompt('grab').strip().lower() in ('y','yes') else ''
    print(note + ' HTTP probe on web ports? [y/N]: \n', end='')
    http = '--http-probe' if _prompt('http').strip().lower() in ('y','yes') else ''
    _run('portscan.py', f'-u "{url}" -p {ports} {grab} {http}')

def run_dns():
    domain = _get_domain('dns')
    if not domain:
        return
    print(note + ' Run all checks? (zone transfer, subdomains, email sec) [Y/n]: \n', end='')
    a = _prompt('dns_mode').strip().lower()
    flag = '--all' if a in ('', 'y', 'yes') else ''
    _run('dnslookup.py', f'-d "{domain}" {flag}')

def run_whois():
    domain = _get_domain('whois')
    if not domain:
        return
    _run('whoislookup.py', f'-d "{domain}"')

def run_techfinger():
    url = _get_url('techfinger')
    if not url:
        return
    _run('techfinger.py', f'-u "{url}"')

def run_headergrab():
    url = _get_url('headers')
    if not url:
        return
    print(note + ' Compare HTTP vs HTTPS redirect? [y/N]: \n', end='')
    cmp = '--compare-http' if _prompt('cmp').strip().lower() in ('y','yes') else ''
    _run('headergrab.py', f'-u "{url}" {cmp}')

def run_sslaudit():
    url = _get_url('ssl_audit')
    if not url:
        return
    _run('sslaudit.py', f'-u "{url}" --check-protocols')

def run_contentdiscovery():
    url = _get_url('content_disc')
    if not url:
        return
    print(note + ' Custom wordlist file path? (leave blank for built-in): \n', end='')
    wl = _prompt('wordlist').strip()
    wl_flag = f'-w "{wl}"' if wl else ''
    print(note + ' Threads [default 10]: \n', end='')
    t = _prompt('threads').strip()
    t = t if t.isdigit() else '10'
    _run('contentdiscovery.py', f'-u "{url}" -t {t} {wl_flag}')

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
        _run('hibpcheck.py', 'password')
    elif sub == '2':
        print(note + ' Path to password list file: ', end='')
        fp = _prompt('hibp_file').strip()
        if fp:
            _run('hibpcheck.py', f'file -f "{fp}"')
    elif sub == '3':
        print(note + ' Email address: ', end='')
        email = _prompt('hibp_email').strip()
        if not email:
            return
        print(note + ' HIBP API key (get at haveibeenpwned.com/API/Key): \n', end='')
        key = _prompt('hibp_key').strip()
        if email and key:
            _run('hibpcheck.py', f'email -e "{email}" -k "{key}"')
        elif email:
            _run('hibpcheck.py', f'email -e "{email}"')

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
