import hashlib
import argparse
import json
import os
import sys
import time
import re
import getpass
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR, SAVE_REPORTS

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    HAS_REQUESTS = False

HIBP_PWNED_URL    = "https://api.pwnedpasswords.com/range/{}"
HIBP_BREACH_URL   = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PASTE_URL    = "https://haveibeenpwned.com/api/v3/pasteaccount/{}"
HIBP_BREACH_DB    = "https://haveibeenpwned.com/api/v3/breaches"

def check_password_pwned(password):
    sha1   = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        if HAS_REQUESTS:
            r = requests.get(HIBP_PWNED_URL.format(prefix),
                             timeout=10, headers={'User-Agent': 'Merlin-Security-Tool'})
            data = r.text
        else:
            req  = urllib.request.Request(
                HIBP_PWNED_URL.format(prefix),
                headers={'User-Agent': 'Merlin-Security-Tool'}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read().decode('utf-8')

        for line in data.splitlines():
            parts = line.split(':')
            if len(parts) == 2:
                returned_suffix, count = parts
                if returned_suffix.upper() == suffix:
                    return int(count), sha1
        return 0, sha1

    except Exception as e:
        return -1, sha1

def check_password_strength(password):
    score  = 0
    issues = []

    if len(password) >= 8:  score += 1
    else: issues.append("Too short (< 8 chars)")

    if len(password) >= 12: score += 1
    else: issues.append("Recommended: >= 12 chars")

    if len(password) >= 16: score += 1

    if re.search(r'[A-Z]', password): score += 1
    else: issues.append("No uppercase letters")

    if re.search(r'[a-z]', password): score += 1
    else: issues.append("No lowercase letters")

    if re.search(r'[0-9]', password): score += 1
    else: issues.append("No numbers")

    if re.search(r'[^A-Za-z0-9]', password): score += 1
    else: issues.append("No special characters")

    common_patterns = [
        r'^[0-9]+$',
        r'^[a-zA-Z]+$',
        r'(.)\1{3,}',
        r'(012|123|234|345|456|567|678|789|890)',
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij)',
        r'(?i)(password|passwd|pass|qwerty|admin|login|welcome)',
    ]
    for pat in common_patterns:
        if re.search(pat, password):
            issues.append("Contains common/predictable pattern")
            score -= 1
            break

    score = max(0, min(score, 7))
    if score <= 2:   strength = LR + 'VERY WEAK'  + N
    elif score <= 3: strength = LR + 'WEAK'        + N
    elif score <= 4: strength = LY + 'FAIR'        + N
    elif score <= 5: strength = LY + 'GOOD'        + N
    elif score <= 6: strength = LG + 'STRONG'      + N
    else:            strength = LG + 'VERY STRONG' + N

    return score, strength, issues

def check_email_breach(email, api_key=None):
    if not api_key:
        return None, "HIBP v3 API key required for email breach check. Get one at https://haveibeenpwned.com/API/Key"

    if not HAS_REQUESTS:
        return None, "requests library required"

    try:
        headers = {
            'hibp-api-key': api_key,
            'User-Agent':   'Merlin-Security-Tool',
        }
        r = requests.get(
            HIBP_BREACH_URL.format(email),
            headers=headers, timeout=10
        )
        if r.status_code == 200:
            return r.json(), None
        elif r.status_code == 404:
            return [], None
        elif r.status_code == 401:
            return None, "Invalid API key"
        elif r.status_code == 429:
            retry = r.headers.get('retry-after', '60')
            return None, f"Rate limited — retry after {retry}s"
        else:
            return None, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)

def check_password_list(filepath):
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except IOError as e:
        print(f"{err} Cannot read file: {e}")
        return []

    print(f"\n{note} Checking {LY}{len(passwords)}{N} passwords...")
    print(f"{DG}(Passwords are hashed locally, only first 5 chars of SHA1 sent){N}\n")

    for i, pwd in enumerate(passwords, 1):
        count, sha1 = check_password_pwned(pwd)
        score, strength, issues = check_password_strength(pwd)
        masked = pwd[:2] + '*' * (len(pwd)-4) + pwd[-2:] if len(pwd) >= 5 else '***'

        if count > 0:
            print(f"  {warn} {LR}PWNED{N}    [{count:>8,}x] {DG}{masked}{N}  strength={strength}")
        elif count == 0:
            print(f"  {sukses} {LG}CLEAN{N}           {DG}{masked}{N}  strength={strength}")
        else:
            print(f"  {star} {LY}API ERR{N}         {DG}{masked}{N}")

        results.append({
            'password_masked': masked,
            'sha1_prefix':     sha1[:5],
            'pwned_count':     count,
            'strength_score':  score,
            'strength_issues': issues,
        })
        time.sleep(1.6)

    return results

def _sep(title=''):
    if title:
        print(f"\n{LY}{'─'*20} {W}{title} {LY}{'─'*20}{N}")
    else:
        print(f"{LY}{'─'*65}{N}")

def print_password_result(pwd_display, count, score, strength, issues, sha1):
    _sep()
    print(f"  {LC}Password (masked){N}: {DG}{pwd_display}{N}")
    print(f"  {LC}SHA1 Prefix sent  {N}: {DG}{sha1[:5]}*****{N}")
    print(f"  {LC}Strength          {N}: {strength}  ({score}/7)")

    if issues:
        print(f"  {LC}Weakness          {N}:")
        for iss in issues:
            print(f"    {warn} {LY}{iss}{N}")

    if count < 0:
        print(f"  {LC}HIBP Result       {N}: {LY}API error (check connection){N}")
    elif count == 0:
        print(f"  {LC}HIBP Result       {N}: {LG}✓ Not found in known breaches{N}")
    else:
        print(f"  {LC}HIBP Result       {N}: {LR}⚠ FOUND {count:,} times in data breaches!{N}")
        print(f"  {LR}This password has been exposed — DO NOT USE IT.{N}")

    _sep()

def print_breach_results(email, breaches):
    _sep('Email Breach Check')
    print(f"  {LC}Email{N}: {W}{email}{N}")
    if breaches is None:
        print(f"  {err} Could not check (API error)")
        return
    if not breaches:
        print(f"  {sukses} {LG}No breaches found for this email{N}")
        return
    print(f"  {warn} {LR}Found in {len(breaches)} breach(es):{N}")
    for b in breaches:
        print(f"\n    {LR}■ {b.get('Name','?')}{N} ({b.get('BreachDate','?')})")
        print(f"      {DG}Domain     : {b.get('Domain','?')}{N}")
        pwned_data = ', '.join(b.get('DataClasses', []))
        print(f"      {DG}Leaked data: {pwned_data[:80]}{N}")
        print(f"      {DG}Affected   : {b.get('PwnCount', 0):,} accounts{N}")

def main():
    print(logo)
    parser = argparse.ArgumentParser(
        description=LY + "Merlin — HaveIBeenPwned Credential Checker",
        formatter_class=argparse.RawTextHelpFormatter
    )
    mode = parser.add_subparsers(dest='mode')

    pw = mode.add_parser('password', help='Check a single password')
    pw.add_argument('-p', '--password', dest='password', default=None,
                   help='Password to check (leave blank for secure prompt)')
    pw.add_argument('--show', action='store_true',
                   help='Show password as typed (default: hidden)')

    fm = mode.add_parser('file', help='Check passwords from a file (one per line)')
    fm.add_argument('-f', '--file', required=True, dest='filepath')

    em = mode.add_parser('email', help='Check if email was in known breaches')
    em.add_argument('-e', '--email',   required=True)
    em.add_argument('-k', '--api-key', dest='api_key', default=None,
                   help='HIBP API key (required for email check)')

    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    report  = {}
    results = []

    if args.mode == 'password' or args.mode is None:
        if args.mode is None or not hasattr(args, 'password') or args.password is None:
            print(f"\n{note} Enter password to check (input is hidden):")
            try:
                if hasattr(args, 'show') and args.show:
                    pwd = input(LG + '└─$ ' + W)
                else:
                    pwd = getpass.getpass(LG + '└─$ (hidden) ' + W)
            except (EOFError, KeyboardInterrupt):
                print(f"\n{note} Cancelled.")
                return
        else:
            pwd = args.password

        if not pwd:
            print(f"{err} Empty password.")
            return

        masked = pwd[:2] + '*' * max(1, len(pwd)-4) + pwd[-2:] if len(pwd) >= 5 else '***'
        count, sha1 = check_password_pwned(pwd)
        score, strength, issues = check_password_strength(pwd)
        print_password_result(masked, count, score, strength, issues, sha1)
        report = {'mode':'password', 'pwned_count': count, 'strength_score': score}

    elif args.mode == 'file':
        results = check_password_list(args.filepath)
        pwned   = sum(1 for r in results if r['pwned_count'] > 0)
        clean   = sum(1 for r in results if r['pwned_count'] == 0)
        print(f"\n{plus} {LY}Summary:{N}")
        print(f"  {warn} Pwned  : {LR}{pwned}{N}")
        print(f"  {sukses} Clean  : {LG}{clean}{N}")
        report  = {'mode':'file', 'total': len(results), 'pwned': pwned, 'results': results}

    elif args.mode == 'email':
        breaches, err_msg = check_email_breach(args.email, args.api_key)
        if err_msg:
            print(f"\n{warn} {LY}{err_msg}{N}")
        else:
            print_breach_results(args.email, breaches)
        report = {'mode':'email', 'email': args.email,
                  'breaches': breaches if breaches else []}

    if SAVE_REPORTS and report:
        os.makedirs(args.output_dir, exist_ok=True)
        fname = os.path.join(args.output_dir, "hibp_check.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    main()
