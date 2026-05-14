import ssl
import socket
import argparse
import json
import os
import sys
import time
import re
from datetime import datetime
from urllib.parse import urlparse
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR, SAVE_REPORTS, TIMEOUT

WEAK_CIPHERS = [
    'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5',
    'ADH', 'AECDH', 'PSK', 'SRP', 'DSS',
    'RC2', 'IDEA', 'SEED', 'CAMELLIA',
]

WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
STRONG_PROTOCOLS = ['TLSv1.2', 'TLSv1.3']

def _sep(title=''):
    if title:
        print(f"\n{LY}{'─'*20} {W}{title} {LY}{'─'*20}{N}")
    else:
        print(f"{LY}{'─'*65}{N}")

def get_cert_info(host, port=443, timeout=TIMEOUT):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert        = ssock.getpeercert()
                cipher      = ssock.cipher()
                version     = ssock.version()
                return cert, cipher, version, None
    except ssl.SSLCertVerificationError as e:
        context2 = ssl.create_default_context()
        context2.check_hostname = False
        context2.verify_mode    = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context2.wrap_socket(sock, server_hostname=host) as ssock:
                    cert    = ssock.getpeercert(binary_form=False)
                    cipher  = ssock.cipher()
                    version = ssock.version()
                    return cert, cipher, version, f"Verification failed: {e}"
        except Exception as e2:
            return None, None, None, str(e2)
    except Exception as e:
        return None, None, None, str(e)

def analyze_cert(cert, host):
    result = {}
    issues = []

    if not cert:
        return {}, ['Could not retrieve certificate']

    subject = dict(x[0] for x in cert.get('subject', []))
    issuer  = dict(x[0] for x in cert.get('issuer', []))
    result['subject_cn']   = subject.get('commonName', '')
    result['subject_org']  = subject.get('organizationName', '')
    result['issuer_cn']    = issuer.get('commonName', '')
    result['issuer_org']   = issuer.get('organizationName', '')
    result['serial']       = str(cert.get('serialNumber', ''))
    result['version']      = cert.get('version', '')

    sans = []
    for stype, sval in cert.get('subjectAltName', []):
        sans.append(f"{stype}:{sval}")
    result['san'] = sans

    not_before_str = cert.get('notBefore', '')
    not_after_str  = cert.get('notAfter',  '')
    try:
        not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
        not_after  = datetime.strptime(not_after_str,  '%b %d %H:%M:%S %Y %Z')
        now        = datetime.utcnow()
        days_left  = (not_after - now).days
        result['not_before']  = not_before.strftime('%Y-%m-%d')
        result['not_after']   = not_after.strftime('%Y-%m-%d')
        result['days_left']   = days_left
        result['expired']     = days_left < 0

        if days_left < 0:
            issues.append(f"EXPIRED {abs(days_left)} days ago!")
        elif days_left <= 7:
            issues.append(f"CRITICAL: expires in {days_left} days")
        elif days_left <= 30:
            issues.append(f"WARNING: expires in {days_left} days")
    except Exception:
        result['not_before'] = not_before_str
        result['not_after']  = not_after_str
        result['days_left']  = None

    hostname_match = False
    cn = result['subject_cn']
    if cn == host or (cn.startswith('*.') and host.endswith(cn[1:])):
        hostname_match = True
    for san in sans:
        if ':' in san:
            _, val = san.split(':', 1)
            if val == host or (val.startswith('*.') and host.endswith(val[1:])):
                hostname_match = True
    result['hostname_match'] = hostname_match
    if not hostname_match:
        issues.append(f"Hostname mismatch: cert CN={cn}, host={host}")

    if result['subject_cn'] == result['issuer_cn']:
        issues.append("Self-signed certificate (not trusted by browsers)")
        result['self_signed'] = True
    else:
        result['self_signed'] = False

    result['ocsp_uris'] = cert.get('OCSP', [])
    result['ca_issuers'] = cert.get('caIssuers', [])
    result['crl_uris']   = cert.get('cRLDistributionPoints', [])

    result['issues'] = issues
    return result, issues

def check_protocol(host, port, protocol_version):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        if protocol_version == 'TLSv1':
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif protocol_version == 'TLSv1.1':
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        elif protocol_version == 'TLSv1.2':
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif protocol_version == 'TLSv1.3':
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        else:
            return False, 'unsupported'

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ssock.version()
    except ssl.SSLError:
        return False, 'rejected'
    except AttributeError:
        return False, 'not_supported_by_python'
    except Exception as e:
        return False, str(e)[:40]

def get_supported_ciphers(host, port=443):
    supported = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    supported.append({
                        'name':     cipher[0],
                        'protocol': cipher[1],
                        'bits':     cipher[2],
                        'weak':     any(w in cipher[0] for w in WEAK_CIPHERS),
                    })
    except Exception:
        pass
    return supported

def check_hsts_preload(host):
    try:
        import requests as req
        r = req.get(f"https://hstspreload.org/api/v2/status?domain={host}",
                    timeout=8)
        data = r.json()
        return data.get('status', 'unknown')
    except Exception:
        return 'unknown'

def _grade_ssl(cert_info, cipher_info, version, protocol_results, issues):
    score = 100
    if cert_info.get('expired'): score -= 40
    if cert_info.get('self_signed'): score -= 30
    if not cert_info.get('hostname_match'): score -= 25
    if cert_info.get('days_left', 365) <= 30: score -= 10
    if version in WEAK_PROTOCOLS: score -= 30
    for proto, (supported, _) in protocol_results.items():
        if proto in WEAK_PROTOCOLS and supported: score -= 15
    if cipher_info and any(w in cipher_info[0] for w in WEAK_CIPHERS): score -= 20
    for issue in issues:
        if 'expired' in issue.lower(): score -= 10
    score = max(0, score)
    if score >= 90: return 'A+', LG
    if score >= 75: return 'A',  LG
    if score >= 60: return 'B',  LY
    if score >= 45: return 'C',  LY
    if score >= 30: return 'D',  LR
    return 'F', LR

def print_report(host, port, cert_info, cert_issues, cipher_info,
                 version, protocol_results, ciphers, report):
    grade, gcol = _grade_ssl(cert_info, cipher_info, version, protocol_results, cert_issues)
    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}SSL/TLS Audit{N} → {LC}{host}:{port}{N}")
    print(f"  {LC}Grade{N}: {gcol}{grade}{N}")
    print(f"{LY}{'═'*65}{N}")

    _sep('Certificate Info')
    days = cert_info.get('days_left')
    if days is not None:
        dcol = LR if days < 0 else LR if days <= 14 else LY if days <= 30 else LG
        print(f"  {LC}Expires       {N}: {W}{cert_info.get('not_after','')}{N}  {dcol}({days} days){N}")
    print(f"  {LC}Common Name   {N}: {W}{cert_info.get('subject_cn','')}{N}")
    print(f"  {LC}Organization  {N}: {W}{cert_info.get('subject_org','')}{N}")
    print(f"  {LC}Issuer CN     {N}: {W}{cert_info.get('issuer_cn','')}{N}")
    print(f"  {LC}Issuer Org    {N}: {W}{cert_info.get('issuer_org','')}{N}")
    hm_col = LG if cert_info.get('hostname_match') else LR
    ss_col = LR if cert_info.get('self_signed') else LG
    print(f"  {LC}Hostname Match{N}: {hm_col}{'YES' if cert_info.get('hostname_match') else 'NO'}{N}")
    print(f"  {LC}Self-Signed   {N}: {ss_col}{'YES (untrusted)' if cert_info.get('self_signed') else 'NO'}{N}")
    print(f"  {LC}Not Before    {N}: {DG}{cert_info.get('not_before','')}{N}")
    print(f"  {LC}Serial        {N}: {DG}{cert_info.get('serial','')[:20]}{N}")

    if cert_info.get('san'):
        _sep('Subject Alternative Names')
        for san in cert_info['san'][:10]:
            print(f"  {sukses} {W}{san}{N}")

    _sep('TLS/SSL Protocol Support')
    for proto in ['TLSv1.3','TLSv1.2','TLSv1.1','TLSv1']:
        supported, detail = protocol_results.get(proto, (False, 'not tested'))
        if supported:
            col   = LG if proto in STRONG_PROTOCOLS else LR
            label = LG + 'SUPPORTED' if proto in STRONG_PROTOCOLS else LR + 'SUPPORTED (WEAK!)'
            print(f"  {sukses if proto in STRONG_PROTOCOLS else warn} {col}{proto:<10}{N}: {label}{N}")
        else:
            col = LG if proto in WEAK_PROTOCOLS else DG
            print(f"  {sukses if proto in WEAK_PROTOCOLS else star} {col}{proto:<10}{N}: {DG}not supported / rejected{N}")

    _sep('Active Cipher Suite')
    if cipher_info:
        cname = cipher_info[0]
        is_weak = any(w in cname for w in WEAK_CIPHERS)
        col = LR if is_weak else LG
        print(f"  {warn if is_weak else sukses} {col}{cname}{N} ({cipher_info[1]}, {cipher_info[2]} bits)")
        if is_weak:
            print(f"       {LR}⚠ Weak cipher — should be disabled{N}")

    if cert_issues:
        _sep('Issues Found')
        for issue in cert_issues:
            print(f"  {warn} {LR}{issue}{N}")
    else:
        _sep()
        print(f"  {sukses} {LG}No certificate issues found{N}")

    print(f"\n{LY}{'═'*65}{N}")
    report['grade']    = grade
    report['cert']     = cert_info
    report['cipher']   = {'name': cipher_info[0] if cipher_info else '', 'bits': cipher_info[2] if cipher_info else 0}
    report['version']  = version
    report['protocols']= {k: v[0] for k, v in protocol_results.items()}
    report['issues']   = cert_issues

def main():
    print(logo)
    parser = argparse.ArgumentParser(description=LY + "Merlin — SSL/TLS Deep Auditor")
    parser.add_argument('-u', '--url',  required=True,
                        help='Target URL or host (e.g. https://example.com)')
    parser.add_argument('-p', '--port', type=int, default=443)
    parser.add_argument('--check-protocols', action='store_true', default=True,
                        help='Check TLS protocol version support (default: on)')
    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    parsed = urlparse(args.url if '://' in args.url else 'https://' + args.url)
    host   = parsed.hostname
    port   = parsed.port or args.port

    print(f"\n{note} Auditing SSL/TLS for {LY}{host}:{port}{N}...")

    cert, cipher, version, error = get_cert_info(host, port)
    if error and not cert:
        print(f"{err} Could not connect: {error}")
        sys.exit(1)
    if error:
        print(f"{warn} {LY}{error}{N}")

    cert_info, cert_issues = analyze_cert(cert, host) if cert else ({}, [error or 'No cert'])

    protocol_results = {}
    if args.check_protocols:
        print(f"{note} Probing protocol support...")
        for proto in ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1']:
            supported, detail = check_protocol(host, port, proto)
            protocol_results[proto] = (supported, detail)
            time.sleep(0.3)
    else:
        protocol_results = {p: (False, 'not checked') for p in ['TLSv1.3','TLSv1.2','TLSv1.1','TLSv1']}

    ciphers = get_supported_ciphers(host, port)
    report  = {'target': host, 'port': port}
    print_report(host, port, cert_info, cert_issues, cipher,
                 version, protocol_results, ciphers, report)

    if SAVE_REPORTS:
        os.makedirs(args.output_dir, exist_ok=True)
        fname = os.path.join(args.output_dir, f"ssl_{host.replace('.','_')}.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    main()
