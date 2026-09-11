#
# Policy Gate : Tools Merlin
# Enforces a security policy (.merlinpolicy.yml / .yaml / .json) against the
# JSON reports other Merlin modules have already saved, and exits non-zero
# on violation. Built to be dropped into a CI/CD pipeline as a build gate:
# "fail the deploy if this target regresses below policy." Reads reports
# already on disk; does not scan or exploit anything itself.
#

import os, sys, json, argparse, time

from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR

from correlate import load_reports, _norm, run_rules, compute_score

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

DEFAULT_POLICY_NAMES = ['.merlinpolicy.yml', '.merlinpolicy.yaml', '.merlinpolicy.json']


def find_policy_file(explicit_path):
    if explicit_path:
        return explicit_path if os.path.exists(explicit_path) else None
    for name in DEFAULT_POLICY_NAMES:
        if os.path.exists(name):
            return name
    return None


def load_policy(path):
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    if path.endswith(('.yml', '.yaml')):
        if not HAS_YAML:
            raise RuntimeError("PyYAML is not installed. Run: pip install pyyaml  (or use a .merlinpolicy.json file instead)")
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return data.get('policy', data) if isinstance(data, dict) else {}


class Violation:
    def __init__(self, rule, expected, actual, message):
        self.rule     = rule
        self.expected = expected
        self.actual   = actual
        self.message  = message

    def to_dict(self):
        return {'rule': self.rule, 'expected': self.expected, 'actual': self.actual, 'message': self.message}


# ---------------------------------------------------------------------------
# Individual policy checks — each returns a list of Violation
# ---------------------------------------------------------------------------

def check_headers(policy, reports):
    violations = []
    cfg = policy.get('headers')
    if not cfg:
        return violations
    required = cfg.get('require', [])
    headers = reports.get('headers', {}).get('results', {}).get('security_headers', {})
    if not headers and required:
        violations.append(Violation('headers.require', required, 'no header report found',
                                     "Header policy is set but no headers_{domain}.json report exists -- run the Header Analyzer first."))
        return violations
    for h in required:
        ok = headers.get(h, {}).get('ok', False)
        if not ok:
            violations.append(Violation(f'headers.require[{h}]', 'present & ok', 'missing or misconfigured',
                                         f"Required security header '{h}' is missing or not correctly configured."))
    return violations


def check_ssl(policy, reports):
    violations = []
    cfg = policy.get('ssl')
    if not cfg:
        return violations
    ssl = reports.get('ssl', {})
    if not ssl:
        violations.append(Violation('ssl', 'ssl report present', 'no ssl report found',
                                     "SSL policy is set but no ssl_{domain}.json report exists -- run the SSL Auditor first."))
        return violations

    order = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5}
    min_grade = cfg.get('min_grade')
    if min_grade:
        actual = ssl.get('grade', 'F')
        if order.get(actual, 99) > order.get(min_grade, 0):
            violations.append(Violation('ssl.min_grade', min_grade, actual,
                                         f"TLS grade {actual} does not meet the minimum required grade {min_grade}."))

    disallow_proto = cfg.get('disallow_protocols', [])
    active_proto = [p for p, ok in ssl.get('protocols', {}).items() if ok and p in disallow_proto]
    if active_proto:
        violations.append(Violation('ssl.disallow_protocols', f"none of {disallow_proto}", active_proto,
                                     f"Disallowed TLS protocol(s) still enabled: {', '.join(active_proto)}."))

    min_days = cfg.get('min_cert_days_left')
    if min_days is not None:
        days = ssl.get('cert', {}).get('days_left')
        if isinstance(days, int) and days < min_days:
            violations.append(Violation('ssl.min_cert_days_left', f">= {min_days} days", f"{days} days",
                                         f"Certificate has only {days} day(s) left, below the required minimum of {min_days}."))
    return violations


def check_wpvuln(policy, reports):
    violations = []
    cfg = policy.get('wpvuln')
    if not cfg:
        return violations
    wpvuln = reports.get('wpvuln', {})
    vulns = wpvuln.get('vulnerabilities_found', []) if wpvuln else []

    max_allowed = cfg.get('max_allowed')
    if max_allowed is not None and len(vulns) > max_allowed:
        violations.append(Violation('wpvuln.max_allowed', f"<= {max_allowed}", len(vulns),
                                     f"{len(vulns)} WordPress vulnerabilit(y/ies) found, exceeding the allowed maximum of {max_allowed}."))

    max_sev = cfg.get('max_severity')
    if max_sev and vulns:
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        limit = sev_order.get(str(max_sev).upper(), 4)
        worst = [v for v in vulns if sev_order.get(str(v.get('severity', 'INFO')).upper(), 4) < limit]
        if worst:
            names = ', '.join(sorted({v.get('name', '') for v in worst})[:5])
            violations.append(Violation('wpvuln.max_severity', f"<= {max_sev}", f"found: {names}",
                                         f"WordPress vulnerabilities above the allowed severity ({max_sev}) are present: {names}."))
    return violations


def check_ports(policy, reports):
    violations = []
    cfg = policy.get('ports')
    if not cfg:
        return violations
    portscan = reports.get('portscan', {})
    open_ports = set(portscan.get('open_ports', {}).keys()) if portscan else set()
    disallow = [str(p) for p in cfg.get('disallow', [])]
    hit = [p for p in disallow if p in open_ports]
    if hit:
        violations.append(Violation('ports.disallow', f"none of {disallow}", hit,
                                     f"Disallowed open port(s) detected: {', '.join(hit)}."))
    return violations


def check_content(policy, reports):
    violations = []
    cfg = policy.get('content')
    if not cfg or not cfg.get('disallow_exposed_files', True):
        return violations
    content = reports.get('content', {})
    found_files = content.get('found_files', []) if content else []
    crit_kw = ('backup', 'sql', 'dump', 'config', '.env', 'key', 'credential', '.log')
    exposed = [f.get('path') for f in found_files if any(k in str(f.get('path', '')).lower() for k in crit_kw)]
    if exposed:
        violations.append(Violation('content.disallow_exposed_files', 'none exposed', exposed,
                                     f"Backup/config-like file(s) directly accessible: {', '.join(exposed[:5])}."))
    return violations


def check_correlate(policy, reports):
    cfg = policy.get('correlate')
    findings = run_rules(reports)
    score, grade = compute_score(findings)
    violations = []
    if not cfg:
        return violations, findings, score, grade

    max_score = cfg.get('max_score')
    if max_score is not None and score > max_score:
        violations.append(Violation('correlate.max_score', f"<= {max_score}", score,
                                     f"Combined risk score {score} exceeds the allowed maximum of {max_score}."))

    disallow_sev = [s.upper() for s in cfg.get('disallow_severity', [])]
    hit = [f for f in findings if f.severity in disallow_sev]
    if hit:
        titles = ', '.join(f.title for f in hit[:5])
        violations.append(Violation('correlate.disallow_severity', f"none of {disallow_sev}", titles,
                                     f"Correlated finding(s) at a disallowed severity level: {titles}."))
    return violations, findings, score, grade


CHECKS = [check_headers, check_ssl, check_wpvuln, check_ports, check_content]


def run_policy(policy, reports):
    violations = []
    for check in CHECKS:
        violations.extend(check(policy, reports))
    corr_violations, findings, score, grade = check_correlate(policy, reports)
    violations.extend(corr_violations)
    return violations, findings, score, grade


def print_report(domain, policy_path, violations, score, grade):
    print(logo)
    print(f"{LY}{'═'*65}{N}")
    print(f"  {W}MERLIN — Policy Gate{N}")
    print(f"{LY}{'═'*65}{N}\n")
    print(f"  {LC}Target{N}    : {W}{domain}{N}")
    print(f"  {LC}Policy{N}    : {W}{policy_path}{N}")
    if score is not None:
        grade_color = {'A': LG, 'B': LG, 'C': LY, 'D': LR, 'F': LR}.get(grade, W)
        print(f"  {LC}Risk score{N}: {W}{score}/100{N}  Grade {grade_color}{grade}{N}")
    print(f"\n{LY}{'-'*65}{N}")

    if not violations:
        print(f"\n  {sukses} {LG}PASS{N} — no policy violations found.")
    else:
        print(f"\n  {LR}FAIL{N} — {len(violations)} policy violation(s):\n")
        for v in violations:
            print(f"  {LR}x{N} {W}{v.rule}{N}")
            print(f"    expected: {v.expected}")
            print(f"    actual  : {v.actual}")
            print(f"    {v.message}\n")
    print(f"{LY}{'═'*65}{N}")


def save_report(output_dir, domain, policy_path, violations, score, grade):
    os.makedirs(output_dir, exist_ok=True)
    fname = os.path.join(output_dir, f"policy_{_norm(domain)}.json")
    data = {
        'target':              domain,
        'policy_file':         policy_path,
        'passed':              not violations,
        'violations':          [v.to_dict() for v in violations],
        'combined_risk_score': score,
        'combined_risk_grade': grade,
        'generated_at':        time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    icon = sukses if not violations else err
    print(f"{icon} Policy report saved -> {LY}{fname}{N}")
    return fname


def main():
    parser = argparse.ArgumentParser(description=LY + "Merlin -- Policy Gate (CI/CD)")
    parser.add_argument('-d', '--domain', required=True, help='Domain/host the other Merlin modules were run against')
    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR, help='Directory containing prior Merlin JSON reports')
    parser.add_argument('-p', '--policy', dest='policy_path', default=None,
                         help='Path to .merlinpolicy.yml/.yaml/.json (default: auto-detect in current directory)')
    args = parser.parse_args()

    policy_path = find_policy_file(args.policy_path)
    if not policy_path:
        print(f"{err} No policy file found. Looked for: {', '.join(DEFAULT_POLICY_NAMES)} (or pass -p).")
        sys.exit(2)

    try:
        policy = load_policy(policy_path)
    except Exception as e:
        print(f"{err} Failed to load policy file {policy_path}: {e}")
        sys.exit(2)

    reports, missing = load_reports(args.output_dir, args.domain)
    if not reports:
        print(f"{err} No Merlin reports found for {W}{args.domain}{N} in {args.output_dir}.")
        print(f"{note} Run some scans first, then re-run the policy gate.")
        sys.exit(2)

    violations, findings, score, grade = run_policy(policy, reports)
    print_report(args.domain, policy_path, violations, score, grade)
    save_report(args.output_dir, args.domain, policy_path, violations, score, grade)

    sys.exit(1 if violations else 0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\033[1;92m[*]\033[0m Policy check interrupted.\033[0m')
        sys.exit(130)
