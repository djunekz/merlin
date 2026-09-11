#
# Risk Timeline : Tools Merlin
# Takes a lightweight "snapshot" of a target's current security posture from
# the JSON reports other Merlin modules have already saved, appends it to a
# per-domain history file, and diffs it against the previous snapshot to
# surface drift: headers that disappeared, a TLS grade that got worse, a
# certificate approaching expiry, a new port opening, a version changing,
# a new WordPress vulnerability appearing, or the combined correlation
# score moving. Like correlate.py, this module only reads reports already
# on disk — it never scans or exploits anything itself.
#

import os, sys, json, argparse, time
from datetime import datetime

from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR

from correlate import load_reports, _norm, MODULE_PATTERNS  # reuse report loading

MAX_HISTORY = 60  # keep the last N snapshots per domain


def _history_path(output_dir, domain):
    return os.path.join(output_dir, f"history_{_norm(domain)}.json")


def _load_history(output_dir, domain):
    path = _history_path(output_dir, domain)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


def _save_history(output_dir, domain, history):
    os.makedirs(output_dir, exist_ok=True)
    path = _history_path(output_dir, domain)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(history[-MAX_HISTORY:], f, indent=4, ensure_ascii=False)
    return path


def build_snapshot(reports, domain, output_dir):
    """Reduce full reports down to the small set of trackable fields."""
    snap = {'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'domain': domain}

    headers = reports.get('headers', {}).get('results', {})
    if headers:
        sec = headers.get('security_headers', {})
        snap['headers'] = {h: bool(v.get('ok')) for h, v in sec.items()}
        snap['header_grade'] = f"{headers.get('grade_score', 0)}/{headers.get('grade_max', 0)}"

    ssl = reports.get('ssl', {})
    if ssl:
        cert = ssl.get('cert', {}) or {}
        weak_proto = [p for p, ok in ssl.get('protocols', {}).items() if ok and p in ('TLSv1', 'TLSv1.1')]
        snap['ssl'] = {
            'grade':          ssl.get('grade', ''),
            'cert_not_after': cert.get('not_after'),
            'cert_days_left': cert.get('days_left'),
            'weak_protocols': weak_proto,
        }

    tech = reports.get('techfinger', {})
    if tech:
        snap['tech_versions'] = tech.get('versions', {})

    portscan = reports.get('portscan', {})
    if portscan:
        snap['open_ports'] = sorted(portscan.get('open_ports', {}).keys(), key=lambda x: int(x) if x.isdigit() else 0)

    wpvuln = reports.get('wpvuln', {})
    if wpvuln:
        vulns = wpvuln.get('vulnerabilities_found', [])
        snap['wpvuln'] = {'count': len(vulns), 'names': sorted({v.get('name', '') for v in vulns})}

    content = reports.get('content', {})
    if content:
        crit_kw = ('backup', 'sql', 'dump', 'config', '.env', 'key', 'credential', '.log')
        exposed = [f.get('path') for f in content.get('found_files', [])
                   if any(k in str(f.get('path', '')).lower() for k in crit_kw)]
        snap['exposed_files'] = sorted(exposed)

    # pull in the combined score from correlate.py's own saved report, if present
    corr_path = os.path.join(output_dir, f"correlate_{_norm(domain)}.json")
    if os.path.exists(corr_path):
        try:
            with open(corr_path, 'r', encoding='utf-8') as f:
                corr = json.load(f)
            snap['correlate_score'] = corr.get('combined_risk_score')
            snap['correlate_grade'] = corr.get('combined_risk_grade')
            snap['finding_ids']     = sorted(f['id'] for f in corr.get('findings', []))
        except (json.JSONDecodeError, IOError):
            pass

    return snap


class DriftEvent:
    def __init__(self, direction, text):
        self.direction = direction  # 'up' (worse), 'down' (better), 'flat'/'info'
        self.text = text


def diff_snapshots(prev, curr):
    events = []

    # Security headers
    ph = prev.get('headers', {})
    ch = curr.get('headers', {})
    for h in set(ph) | set(ch):
        was_ok = ph.get(h)
        now_ok = ch.get(h)
        if was_ok is None or now_ok is None or was_ok == now_ok:
            continue
        if was_ok and not now_ok:
            events.append(DriftEvent('up', f"Header regression: {h} was present/OK, now missing or misconfigured"))
        elif not was_ok and now_ok:
            events.append(DriftEvent('down', f"Header improved: {h} is now present and OK"))

    # SSL grade
    pg, cg = prev.get('ssl', {}).get('grade'), curr.get('ssl', {}).get('grade')
    if pg and cg and pg != cg:
        order = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5}
        worse = order.get(cg, 99) > order.get(pg, -1)
        events.append(DriftEvent('up' if worse else 'down',
                                  f"TLS grade changed: {pg} -> {cg}"))

    # Weak protocols appearing/disappearing
    pw = set(prev.get('ssl', {}).get('weak_protocols', []) or [])
    cw = set(curr.get('ssl', {}).get('weak_protocols', []) or [])
    for proto in cw - pw:
        events.append(DriftEvent('up', f"Weak TLS protocol re-enabled: {proto}"))
    for proto in pw - cw:
        events.append(DriftEvent('down', f"Weak TLS protocol disabled: {proto}"))

    # Certificate expiry
    days = curr.get('ssl', {}).get('cert_days_left')
    if isinstance(days, int):
        if days < 0:
            events.append(DriftEvent('up', f"Certificate is EXPIRED ({abs(days)} days ago)"))
        elif days <= 7:
            events.append(DriftEvent('up', f"Certificate expires in {days} day(s) — urgent"))
        elif days <= 30:
            events.append(DriftEvent('up', f"Certificate expires in {days} day(s)"))

    # Fingerprinted component versions
    pv = prev.get('tech_versions', {})
    cv = curr.get('tech_versions', {})
    for tech in set(pv) | set(cv):
        if tech in pv and tech in cv and pv[tech] != cv[tech]:
            events.append(DriftEvent('flat', f"{tech} version changed: {pv[tech]} -> {cv[tech]}"))
        elif tech in cv and tech not in pv:
            events.append(DriftEvent('flat', f"New technology detected: {tech} {cv[tech]}"))

    # Open ports
    pp = set(prev.get('open_ports', []) or [])
    cp = set(curr.get('open_ports', []) or [])
    for p in cp - pp:
        events.append(DriftEvent('up', f"New open port: {p}"))
    for p in pp - cp:
        events.append(DriftEvent('down', f"Port closed: {p}"))

    # WordPress vulnerabilities
    pwv = prev.get('wpvuln', {})
    cwv = curr.get('wpvuln', {})
    if pwv or cwv:
        p_names, c_names = set(pwv.get('names', [])), set(cwv.get('names', []))
        for name in c_names - p_names:
            events.append(DriftEvent('up', f"New WordPress vulnerability flagged: {name}"))
        for name in p_names - c_names:
            events.append(DriftEvent('down', f"WordPress vulnerability resolved: {name}"))

    # Exposed backup/config files
    pf = set(prev.get('exposed_files', []) or [])
    cf = set(curr.get('exposed_files', []) or [])
    for path in cf - pf:
        events.append(DriftEvent('up', f"Newly exposed sensitive file: {path}"))
    for path in pf - cf:
        events.append(DriftEvent('down', f"Sensitive file no longer exposed: {path}"))

    # Combined correlation score
    ps, cs = prev.get('correlate_score'), curr.get('correlate_score')
    if isinstance(ps, int) and isinstance(cs, int) and ps != cs:
        events.append(DriftEvent('up' if cs > ps else 'down',
                                  f"Combined risk score moved: {ps} -> {cs}"))

    return events


def print_snapshot_summary(domain, snap):
    print(logo)
    print(f"{LY}{'═'*65}{N}")
    print(f"  {W}MERLIN — Risk Timeline{N}")
    print(f"{LY}{'═'*65}{N}\n")
    print(f"  {LC}Target{N}    : {W}{domain}{N}")
    print(f"  {LC}Snapshot{N}  : {W}{snap['timestamp']}{N}")
    if 'ssl' in snap:
        print(f"  {LC}TLS grade{N} : {W}{snap['ssl'].get('grade','?')}{N}   "
              f"cert expires: {W}{snap['ssl'].get('cert_not_after','?')}{N} "
              f"({snap['ssl'].get('cert_days_left','?')} days)")
    if 'correlate_score' in snap:
        print(f"  {LC}Risk score{N}: {W}{snap['correlate_score']}/100{N}  grade {W}{snap.get('correlate_grade','?')}{N}")


def print_drift(events, since):
    print(f"\n{LY}{'-'*65}{N}")
    if since is None:
        print(f"  {note} First snapshot recorded for this target — nothing to compare yet.")
        print(f"  {note} Run this again after the target changes (or after a re-scan) to see drift.")
    elif not events:
        print(f"  {sukses} No drift since last snapshot ({since}). Posture unchanged.")
    else:
        print(f"  {W}Drift since last snapshot ({since}):{N}\n")
        for e in events:
            if e.direction == 'up':
                icon, color = '▲', LR
            elif e.direction == 'down':
                icon, color = '▼', LG
            else:
                icon, color = '●', LC
            print(f"  {color}{icon}{N} {e.text}")
    print(f"{LY}{'═'*65}{N}")


def print_history(domain, history):
    print(logo)
    print(f"{LY}{'═'*65}{N}")
    print(f"  {W}MERLIN — Risk Timeline History for {domain}{N}")
    print(f"{LY}{'═'*65}{N}\n")
    if not history:
        print(f"  {note} No history recorded yet for this target.")
        return
    for snap in history:
        score = snap.get('correlate_score')
        grade = snap.get('correlate_grade')
        ssl_grade = snap.get('ssl', {}).get('grade', '-')
        score_str = f"{score}/100 ({grade})" if score is not None else '-'
        print(f"  {DG}{snap['timestamp']}{N}  TLS:{W}{ssl_grade}{N}  Risk:{W}{score_str}{N}")
    print(f"\n{LY}{'═'*65}{N}")


def main():
    parser = argparse.ArgumentParser(description=LY + "Merlin -- Risk Timeline")
    parser.add_argument('-d', '--domain', required=True,
                         help='Domain/host the other Merlin modules were run against')
    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR,
                         help='Directory containing prior Merlin JSON reports and history')
    parser.add_argument('--show', action='store_true', help='Print recorded history instead of taking a new snapshot')
    args = parser.parse_args()

    history = _load_history(args.output_dir, args.domain)

    if args.show:
        print_history(args.domain, history)
        return

    reports, missing = load_reports(args.output_dir, args.domain)
    if not reports:
        print(f"{err} No Merlin reports found for {W}{args.domain}{N} in {args.output_dir}.")
        print(f"{note} Run some scans (and ideally the Correlation Engine) first, then re-run this.")
        sys.exit(1)

    snap = build_snapshot(reports, args.domain, args.output_dir)
    print_snapshot_summary(args.domain, snap)

    prev = history[-1] if history else None
    events = diff_snapshots(prev, snap) if prev else []
    print_drift(events, prev['timestamp'] if prev else None)

    history.append(snap)
    path = _save_history(args.output_dir, args.domain, history)
    print(f"{sukses} Snapshot recorded -> {LY}{path}{N}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\033[1;92m[*]\033[0m Risk timeline interrupted. Returning to menu...\033[0m')
