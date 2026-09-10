#
# Correlation Engine : Tools Merlin
# Cross-references the JSON reports already produced by other Merlin
# modules (headergrab, sslaudit, techfinger, portscan, wpvuln, dnslookup,
# whoislookup, contentdiscovery, webanalyst, hibpcheck, websqli, webshake)
# and surfaces "risk chains" — combinations of individually-minor findings
# that become serious together. This module does not scan or exploit
# anything itself; it only reads reports that were already saved to disk.
#

import os, sys, json, argparse, time

from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR, SAVE_REPORTS

SEVERITY_ORDER  = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
SEVERITY_WEIGHT = {'CRITICAL': 40, 'HIGH': 25, 'MEDIUM': 12, 'LOW': 5, 'INFO': 1}
SEVERITY_COLOR  = {'CRITICAL': LR, 'HIGH': LR, 'MEDIUM': LY, 'LOW': LC, 'INFO': DG}

# per-domain report filenames written by other modules
MODULE_PATTERNS = {
    'headers':    'headers_{d}.json',
    'ssl':        'ssl_{d}.json',
    'techfinger': 'techfinger_{d}.json',
    'portscan':   'portscan_{d}.json',
    'wpvuln':     'wpvuln_{d}.json',
    'dns':        'dns_{d}.json',
    'whois':      'whois_{d}.json',
    'content':    'content_{d}.json',
    'webanalyst': 'webanalyst_{d}.json',
    'vuln':       'vuln_{d}.json',
    'webshake':   'webshake_{d}.json',
}
# global (non-per-domain) reports
GLOBAL_PATTERNS = {
    'hibp': 'hibp_check.json',
}


def _norm(domain):
    return domain.replace('://', '_').replace('/', '_').replace('.', '_').replace(':', '_')


def load_reports(output_dir, domain):
    d = _norm(domain)
    reports, missing = {}, []

    for name, pattern in MODULE_PATTERNS.items():
        path = os.path.join(output_dir, pattern.format(d=d))
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    reports[name] = json.load(f)
                continue
            except (json.JSONDecodeError, IOError):
                pass
        missing.append(name)

    for name, pattern in GLOBAL_PATTERNS.items():
        path = os.path.join(output_dir, pattern)
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    reports[name] = json.load(f)
                continue
            except (json.JSONDecodeError, IOError):
                pass
        missing.append(name)

    return reports, missing


class Finding:
    def __init__(self, id, title, severity, narrative, sources, evidence=None, recommendation=''):
        self.id             = id
        self.title          = title
        self.severity       = severity
        self.narrative      = narrative
        self.sources        = sources
        self.evidence       = evidence or {}
        self.recommendation = recommendation

    def to_dict(self):
        return {
            'id': self.id, 'title': self.title, 'severity': self.severity,
            'narrative': self.narrative, 'sources': self.sources,
            'evidence': self.evidence, 'recommendation': self.recommendation,
        }


# ---------------------------------------------------------------------------
# Correlation rules — each takes the loaded reports dict and returns a
# Finding, or None if the combination of signals it looks for isn't present.
# Every rule degrades gracefully when one side of the combination is missing.
# ---------------------------------------------------------------------------

def rule_tls_downgrade_surface(r):
    headers = r.get('headers', {}).get('results', {})
    ssl     = r.get('ssl', {})
    if not headers or not ssl:
        return None
    hsts         = headers.get('security_headers', {}).get('Strict-Transport-Security', {})
    hsts_missing = not hsts.get('ok', False)
    weak_proto   = [p for p, ok in ssl.get('protocols', {}).items() if ok and p in ('TLSv1', 'TLSv1.1')]
    grade        = ssl.get('grade', '')
    if hsts_missing and (weak_proto or grade in ('D', 'E', 'F')):
        return Finding(
            id='tls-downgrade-surface',
            title='TLS Downgrade & Interception Surface',
            severity='HIGH',
            narrative=(
                "No HSTS header means the browser will trust a plaintext HTTP "
                "connection on first visit, and the server still accepts "
                + (', '.join(weak_proto) if weak_proto else f"a weak TLS grade ({grade})")
                + ". Together these let a network-position attacker downgrade or "
                "strip the connection instead of having to break TLS outright."
            ),
            sources=['headers', 'ssl'],
            evidence={'hsts': hsts, 'weak_protocols': weak_proto, 'ssl_grade': grade},
            recommendation='Enable HSTS (with preload) and disable TLSv1/TLSv1.1 at the server or load balancer.',
        )
    return None


def rule_xss_blast_radius(r):
    headers = r.get('headers', {}).get('results', {})
    vuln    = r.get('vuln', {}).get('results', {})
    if not headers or not isinstance(vuln, dict):
        return None
    csp         = headers.get('security_headers', {}).get('Content-Security-Policy', {})
    csp_missing = not csp.get('ok', False)
    reflected   = []
    for key, items in vuln.items():
        if isinstance(items, list):
            for it in items:
                t = str(it.get('type', '')).lower()
                if 'reflect' in t:
                    reflected.append(it)
    if csp_missing and reflected:
        return Finding(
            id='xss-blast-radius',
            title='Reflected Input With No Compensating Control',
            severity='CRITICAL',
            narrative=(
                f"{len(reflected)} reflected-input finding(s) were recorded, and "
                "there is no Content-Security-Policy to contain script execution if "
                "one of them turns out to be exploitable. A single missed encoding "
                "case becomes a full page takeover instead of a contained bug."
            ),
            sources=['headers', 'vuln'],
            evidence={'reflected_count': len(reflected), 'csp': csp},
            recommendation='Ship a strict CSP (script-src with no unsafe-inline) as defense-in-depth alongside output-encoding fixes.',
        )
    return None


def rule_outdated_cms_direct_db(r):
    wpvuln   = r.get('wpvuln', {})
    portscan = r.get('portscan', {})
    if not wpvuln or not portscan:
        return None
    vulns      = wpvuln.get('vulnerabilities_found', [])
    open_ports = portscan.get('open_ports', {})
    db_ports   = {'3306': 'MySQL', '5432': 'PostgreSQL', '1433': 'MSSQL', '27017': 'MongoDB', '6379': 'Redis'}
    exposed_db = [f"{p}/{svc}" for p, svc in db_ports.items() if p in open_ports]
    if vulns and exposed_db:
        return Finding(
            id='cms-vuln-plus-exposed-db',
            title='Vulnerable CMS With a Database Directly Reachable',
            severity='CRITICAL',
            narrative=(
                f"{len(vulns)} WordPress issue(s) were flagged, and database port(s) "
                f"{', '.join(exposed_db)} are reachable from outside the app. A CMS "
                "issue that would normally only leak through the application becomes "
                "a direct path to the database if credentials are weak or reused."
            ),
            sources=['wpvuln', 'portscan'],
            evidence={'vuln_count': len(vulns), 'exposed_db_ports': exposed_db},
            recommendation='Firewall database ports to application-server IPs only; patch the flagged CMS components.',
        )
    return None


def rule_recon_trivial(r):
    dns = r.get('dns', {})
    if not dns:
        return None
    zt    = dns.get('zone_transfer')
    zt_ok = bool(zt) and (zt.get('success', True) if isinstance(zt, dict) else True)
    subs  = dns.get('subdomains', [])
    if zt_ok and subs:
        return Finding(
            id='zone-transfer-recon',
            title='Zone Transfer Turns Recon Into a Ready-Made Sitemap',
            severity='HIGH',
            narrative=(
                f"DNS zone transfer succeeded and returned records covering "
                f"{len(subs)} subdomain(s) of infrastructure in a single request — "
                "work that would otherwise take an attacker hours of brute-forcing."
            ),
            sources=['dns'],
            evidence={'subdomain_count': len(subs)},
            recommendation='Restrict AXFR/zone transfers to known secondary nameservers only.',
        )
    return None


def rule_weak_transport_login_paths(r):
    ssl     = r.get('ssl', {})
    content = r.get('content', {})
    if not ssl or not content:
        return None
    grade = ssl.get('grade', '')
    weak  = grade in ('D', 'E', 'F')
    paths = content.get('found_files', []) + content.get('found_dirs', [])
    login_paths = [p for p in paths
                   if any(k in str(p.get('path', '')).lower() for k in ('login', 'admin', 'wp-admin', 'signin', 'auth'))]
    if weak and login_paths:
        first = login_paths[0].get('path', '')
        return Finding(
            id='weak-tls-login-exposed',
            title='Weak Transport Security on a Discoverable Login Surface',
            severity='HIGH',
            narrative=(
                f"A login-related path was discovered ({first}"
                f"{' and others' if len(login_paths) > 1 else ''}) on a host with a "
                f"{grade} TLS grade. Credentials submitted here are more exposed to "
                "interception than they would be with a modern TLS configuration."
            ),
            sources=['ssl', 'content'],
            evidence={'grade': grade, 'login_paths': [p.get('path') for p in login_paths[:5]]},
            recommendation='Harden TLS configuration to at least grade B before anything on this host handles credentials.',
        )
    return None


def rule_fingerprint_confirms_cve(r):
    tech   = r.get('techfinger', {})
    wpvuln = r.get('wpvuln', {})
    if not tech or not wpvuln:
        return None
    versions = tech.get('versions', {})
    vulns    = wpvuln.get('vulnerabilities_found', [])
    if versions and vulns:
        sample = ', '.join(f'{k} {v}' for k, v in list(versions.items())[:3])
        return Finding(
            id='version-confirms-exploitability',
            title='Fingerprinted Versions Line Up With Known Vulnerabilities',
            severity='MEDIUM',
            narrative=(
                f"Technology fingerprinting pinned exact version(s) ({sample}) while "
                f"the WordPress scanner separately flagged {len(vulns)} issue(s). "
                "Exact version disclosure removes the guesswork an attacker would "
                "otherwise need before deciding what to try."
            ),
            sources=['techfinger', 'wpvuln'],
            evidence={'versions': versions, 'vuln_count': len(vulns)},
            recommendation='Suppress version banners (Server, X-Powered-By, generator meta tags) even after patching.',
        )
    return None


def rule_leaky_fingerprint_headers(r):
    headers = r.get('headers', {}).get('results', {})
    tech    = r.get('techfinger', {})
    if not headers and not tech:
        return None
    leak1 = headers.get('leak_headers', {}) if headers else {}
    leak2 = tech.get('leak_headers', {}) if tech else {}
    combined = {**leak1, **leak2}
    if combined:
        return Finding(
            id='leaky-headers-fingerprint',
            title='Server Actively Announces Its Stack',
            severity='LOW',
            narrative=(
                f"{len(combined)} header(s) leak implementation details "
                f"({', '.join(list(combined.keys())[:4])}). On their own these are "
                "informational, but they shorten every other reconnaissance step."
            ),
            sources=['headers', 'techfinger'],
            evidence={'leaked_headers': combined},
            recommendation='Strip or generalize Server/X-Powered-By/X-Generator headers at the reverse proxy.',
        )
    return None


def rule_open_redirect_phishing(r):
    webanalyst = r.get('webanalyst', {})
    headers    = r.get('headers', {}).get('results', {})
    if not webanalyst:
        return None
    open_redirect = webanalyst.get('open_redirect', [])
    csp           = headers.get('security_headers', {}).get('Content-Security-Policy', {}) if headers else {}
    csp_missing   = not csp.get('ok', False)
    if open_redirect and csp_missing:
        return Finding(
            id='open-redirect-phishing-pivot',
            title='Open Redirect Usable as a Trusted-Domain Phishing Pivot',
            severity='MEDIUM',
            narrative=(
                f"{len(open_redirect)} open-redirect parameter(s) exist on a domain "
                "with no CSP restricting where they can point. This combination is "
                "commonly abused to craft phishing links that appear to originate "
                "from this domain."
            ),
            sources=['webanalyst', 'headers'],
            evidence={'redirect_count': len(open_redirect)},
            recommendation='Allow-list redirect targets server-side and add CSP form-action restrictions.',
        )
    return None


def rule_crawler_found_secrets(r):
    webshake = r.get('webshake', {})
    if not webshake:
        return None
    secrets   = webshake.get('secrets_found', [])
    sensitive = webshake.get('sensitive_exposed', [])
    if secrets or sensitive:
        return Finding(
            id='crawler-secrets-exposed',
            title='Passive Crawl Recovered Secrets or Sensitive Data',
            severity='CRITICAL',
            narrative=(
                f"Passive crawling alone surfaced {len(secrets)} potential secret(s) "
                f"and {len(sensitive)} sensitive data exposure(s), with no active "
                "exploitation involved. This is the cheapest possible finding for an "
                "attacker to get and among the most damaging if any secret is live."
            ),
            sources=['webshake'],
            evidence={'secrets_count': len(secrets), 'sensitive_count': len(sensitive)},
            recommendation='Rotate any exposed credentials immediately and remove secrets from client-reachable paths.',
        )
    return None


def rule_risky_ports_plus_app_vuln(r):
    portscan     = r.get('portscan', {})
    vuln         = r.get('vuln', {}).get('results', {})
    wpvuln_list  = r.get('wpvuln', {}).get('vulnerabilities_found', [])
    if not portscan:
        return None
    open_ports  = portscan.get('open_ports', {})
    risky_ports = [p for p, v in open_ports.items() if isinstance(v, dict) and v.get('risk')]
    app_vuln_count = 0
    if isinstance(vuln, dict):
        app_vuln_count += sum(len(v) for v in vuln.values() if isinstance(v, list))
    app_vuln_count += len(wpvuln_list)
    if risky_ports and app_vuln_count:
        return Finding(
            id='risky-ports-plus-app-vuln',
            title='Risky Open Services Alongside a Vulnerable Web App',
            severity='HIGH',
            narrative=(
                f"Port(s) {', '.join(risky_ports)} are open and flagged as risky, and "
                f"{app_vuln_count} separate application-level issue(s) exist on the "
                "same host. Either finding alone might be a low priority; together "
                "they give an attacker both a foothold and a lateral path."
            ),
            sources=['portscan', 'vuln', 'wpvuln'],
            evidence={'risky_ports': risky_ports, 'app_vuln_count': app_vuln_count},
            recommendation='Close unneeded services first — that removes the lateral-movement half of this chain immediately.',
        )
    return None


def rule_breach_data_credential_stuffing(r):
    hibp     = r.get('hibp', {})
    webshake = r.get('webshake', {})
    if not hibp:
        return None
    pwned  = hibp.get('pwned') or hibp.get('pwned_count') or 0
    emails = webshake.get('emails_found', []) if webshake else []
    if pwned and emails:
        return Finding(
            id='breach-data-credential-stuffing',
            title='Known-Breached Credentials Plus Harvestable Emails',
            severity='MEDIUM',
            narrative=(
                f"HIBP returned {pwned} pwned result(s), and the crawler separately "
                f"harvested {len(emails)} email address(es) from this site. Overlap "
                "between the two lists is a ready-made input for credential-stuffing "
                "attempts."
            ),
            sources=['hibp', 'webshake'],
            evidence={'pwned': pwned, 'email_count': len(emails)},
            recommendation='Enforce MFA and breached-password screening for accounts matching these addresses.',
        )
    return None


def rule_backup_files_exposed(r):
    content    = r.get('content', {})
    webanalyst = r.get('webanalyst', {})
    if not content:
        return None
    found_files = content.get('found_files', [])
    critical_kw = ('backup', 'sql', 'dump', 'config', '.env', 'key', 'credential', '.log')
    exposed     = [f for f in found_files if any(k in str(f.get('path', '')).lower() for k in critical_kw)]
    dir_listing = bool(webanalyst.get('directory_listing')) if webanalyst else False
    if exposed:
        sev = 'CRITICAL' if dir_listing else 'HIGH'
        return Finding(
            id='backup-files-exposed',
            title='Backup / Config File Directly Downloadable',
            severity=sev,
            narrative=(
                f"{len(exposed)} file(s) matching backup/config/credential naming "
                "patterns returned HTTP 200 directly" +
                (", and directory listing is also enabled, making them trivial to find." if dir_listing else ".")
            ),
            sources=['content'] + (['webanalyst'] if dir_listing else []),
            evidence={'exposed_files': [f.get('path') for f in exposed[:10]], 'directory_listing': dir_listing},
            recommendation='Remove these files from the web root immediately and rotate any credentials they contained.',
        )
    return None


RULES = [
    rule_tls_downgrade_surface,
    rule_xss_blast_radius,
    rule_outdated_cms_direct_db,
    rule_recon_trivial,
    rule_weak_transport_login_paths,
    rule_fingerprint_confirms_cve,
    rule_leaky_fingerprint_headers,
    rule_open_redirect_phishing,
    rule_crawler_found_secrets,
    rule_risky_ports_plus_app_vuln,
    rule_breach_data_credential_stuffing,
    rule_backup_files_exposed,
]


def run_rules(reports):
    findings = []
    for rule in RULES:
        try:
            result = rule(reports)
        except Exception:
            result = None
        if result:
            findings.append(result)
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return findings


def compute_score(findings):
    raw   = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    score = min(100, raw)
    if score >= 70:
        grade = 'F'
    elif score >= 45:
        grade = 'D'
    elif score >= 25:
        grade = 'C'
    elif score >= 10:
        grade = 'B'
    else:
        grade = 'A'
    return score, grade


def print_report(domain, reports, missing, findings, score, grade):
    print(logo)
    print(f"{LY}{'═'*65}{N}")
    print(f"  {W}MERLIN — Correlation Engine (Combined Risk Analysis){N}")
    print(f"{LY}{'═'*65}{N}\n")
    print(f"  {LC}Target{N}              : {W}{domain}{N}")
    print(f"  {LC}Modules loaded{N}      : {LG}{len(reports)}{N} / {len(reports) + len(missing)}")
    if missing:
        print(f"  {LC}Missing reports{N}     : {DG}{', '.join(missing)}{N}")
    print(f"  {LC}Correlated risks{N}    : {LR if findings else LG}{len(findings)}{N}")
    grade_color = {'A': LG, 'B': LG, 'C': LY, 'D': LR, 'F': LR}[grade]
    print(f"  {LC}Combined risk score{N} : {W}{score}/100{N}  Grade {grade_color}{grade}{N}")
    print(f"\n{LY}{'-'*65}{N}")

    if not findings:
        print(f"\n  {sukses} No cross-module risk chains detected from the reports on hand.")
        if len(missing) > 6:
            print(f"  {note} Run more Merlin modules against this target first — the "
                  f"correlation engine needs at least two reports to find a chain.")
    else:
        for f in findings:
            c = SEVERITY_COLOR[f.severity]
            print(f"\n  {c}[{f.severity}]{N} {W}{f.title}{N}")
            print(f"  {DG}sources: {', '.join(f.sources)}{N}")
            print(f"  {f.narrative}")
            print(f"  {LC}-> Fix:{N} {f.recommendation}")

    print(f"\n{LY}{'═'*65}{N}")


def save_report(output_dir, domain, findings, score, grade, missing):
    os.makedirs(output_dir, exist_ok=True)
    fname = os.path.join(output_dir, f"correlate_{_norm(domain)}.json")
    data = {
        'target':               domain,
        'combined_risk_score':  score,
        'combined_risk_grade':  grade,
        'findings':             [f.to_dict() for f in findings],
        'missing_modules':      missing,
        'generated_at':         time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"{sukses} Correlated report saved -> {LY}{fname}{N}")
    return fname


def main():
    parser = argparse.ArgumentParser(description=LY + "Merlin -- Correlation Engine")
    parser.add_argument('-d', '--domain', required=True,
                         help='Domain/host the other Merlin modules were run against (e.g. example.com)')
    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR,
                         help='Directory containing prior Merlin JSON reports')
    args = parser.parse_args()

    reports, missing = load_reports(args.output_dir, args.domain)
    if not reports:
        print(f"{err} No Merlin reports found for {W}{args.domain}{N} in {args.output_dir}.")
        print(f"{note} Run some scans first (headergrab, sslaudit, techfinger, portscan, "
              f"wpvuln, dnslookup, ...) with save_reports enabled, then re-run this.")
        sys.exit(1)

    findings      = run_rules(reports)
    score, grade  = compute_score(findings)
    print_report(args.domain, reports, missing, findings, score, grade)

    if SAVE_REPORTS:
        save_report(args.output_dir, args.domain, findings, score, grade, missing)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\033[1;92m[*]\033[0m Correlation interrupted. Returning to menu...\033[0m')
