#
# Exposure Storytelling Report : Tools Merlin
# Turns the raw JSON reports other Merlin modules already saved into a
# plain-language narrative: "here is what an outside observer could learn
# about this target in a few minutes, without touching anything invasive."
# Meant to be handed to a non-technical stakeholder alongside (or instead
# of) a raw finding list. It reads reports already on disk; it does not
# scan or exploit anything itself.
#

import os, sys, json, argparse, time
from datetime import datetime

from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import OUTPUT_DIR

from correlate import load_reports, _norm, run_rules, compute_score, SEVERITY_ORDER


def _get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return cur if cur is not None else default


def _load_correlate(output_dir, domain, reports):
    path = os.path.join(output_dir, f"correlate_{_norm(domain)}.json")
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data.get('findings', []), data.get('combined_risk_score'), data.get('combined_risk_grade')
        except (json.JSONDecodeError, IOError):
            pass
    findings = run_rules(reports)
    score, grade = compute_score(findings)
    return [f.to_dict() for f in findings], score, grade


# ---------------------------------------------------------------------------
# Narrative sections — each returns a plain-language paragraph, or None if
# there isn't enough data to say anything meaningful.
# ---------------------------------------------------------------------------

def sec_identity(r, domain):
    whois = r.get('whois', {}).get('parsed', {})
    if not whois:
        return None
    registrar = whois.get('registrar', 'an unknown registrar')
    created   = whois.get('creation_date', 'an unknown date')
    expires   = whois.get('expiration_date', 'an unknown date')
    org       = whois.get('org') or whois.get('registrant_name')
    para = (f"**{domain}** is registered through {registrar}, created on {created}, "
            f"and set to expire on {expires}.")
    if org:
        para += f" WHOIS records list the registrant organization as *{org}*."
    else:
        para += " Registrant details are privacy-protected or not publicly listed."
    return para


def sec_first_contact(r, domain):
    headers = r.get('headers', {}).get('results', {})
    ssl     = r.get('ssl', {})
    if not headers and not ssl:
        return None
    parts = []
    if headers:
        score, mx = headers.get('grade_score', 0), headers.get('grade_max', 0)
        pct = round(100 * score / mx) if mx else 0
        parts.append(f"The site's HTTP security headers score {score}/{mx} ({pct}%) against baseline best practice.")
        leak = headers.get('leak_headers', {})
        if leak:
            parts.append(f"The response itself volunteers implementation details via {', '.join(leak.keys())}.")
    if ssl:
        grade = ssl.get('grade', 'unknown')
        cert  = ssl.get('cert', {})
        days  = cert.get('days_left')
        cert_note = ''
        if isinstance(days, int):
            if days < 0:
                cert_note = f" Its TLS certificate expired {abs(days)} day(s) ago."
            elif days <= 30:
                cert_note = f" Its TLS certificate expires in {days} day(s)."
        parts.append(f"Its TLS configuration grades out at **{grade}**.{cert_note}")
    return ' '.join(parts)


def sec_stack(r, domain):
    tech = r.get('techfinger', {})
    if not tech:
        return None
    versions = tech.get('versions', {})
    technologies = tech.get('technologies', [])
    if versions:
        listed = ', '.join(f"{k} {v}" for k, v in list(versions.items())[:6])
        return (f"Passive fingerprinting identifies the stack as: {listed}. "
                "Exact version numbers being visible means an outsider doesn't need to "
                "guess before checking a target against a public vulnerability database.")
    if technologies:
        return f"Passive fingerprinting identifies the stack as: {', '.join(technologies[:8])}."
    return None


def sec_surface(r, domain):
    dns      = r.get('dns', {})
    portscan = r.get('portscan', {})
    content  = r.get('content', {})
    parts = []
    if dns:
        subs = dns.get('subdomains', [])
        if subs:
            parts.append(f"DNS enumeration surfaced {len(subs)} subdomain(s), expanding the visible attack surface beyond the main site.")
        if dns.get('zone_transfer'):
            parts.append("A DNS zone transfer succeeded, which is normally disabled — it hands over the internal DNS map in one request.")
    if portscan:
        open_ports = portscan.get('open_ports', {})
        risky = [p for p, v in open_ports.items() if isinstance(v, dict) and v.get('risk')]
        if open_ports:
            parts.append(f"A port scan found {len(open_ports)} open port(s)" +
                         (f", including {len(risky)} flagged as higher-risk ({', '.join(risky)})." if risky else "."))
    if content:
        files, dirs = content.get('found_files', []), content.get('found_dirs', [])
        if files or dirs:
            parts.append(f"Content discovery located {len(files)} accessible file path(s) and {len(dirs)} directory path(s) that weren't linked from the site's normal navigation.")
    return ' '.join(parts) if parts else None


def sec_crawl(r, domain):
    webshake = r.get('webshake', {})
    if not webshake:
        return None
    emails  = webshake.get('emails_found', [])
    forms   = webshake.get('forms_found', [])
    secrets = webshake.get('secrets_found', [])
    sensitive = webshake.get('sensitive_exposed', [])
    parts = []
    if emails:
        parts.append(f"{len(emails)} email address(es) were harvested just by crawling public pages.")
    if forms:
        parts.append(f"{len(forms)} form(s) were found, marking places where the site accepts user input.")
    if secrets or sensitive:
        parts.append(f"Most notably, passive crawling turned up {len(secrets)} potential secret(s) and "
                     f"{len(sensitive)} sensitive data exposure(s) — findings that required no active testing at all.")
    return ' '.join(parts) if parts else None


def sec_known_issues(r, domain):
    wpvuln = r.get('wpvuln', {})
    vuln   = r.get('vuln', {}).get('results', {})
    parts = []
    if wpvuln:
        vulns = wpvuln.get('vulnerabilities_found', [])
        if vulns:
            names = ', '.join(sorted({v.get('name', '') for v in vulns})[:5])
            parts.append(f"The WordPress-specific scan flagged {len(vulns)} issue(s): {names}.")
    if isinstance(vuln, dict):
        total = sum(len(v) for v in vuln.values() if isinstance(v, list))
        if total:
            parts.append(f"The web application scanner separately logged {total} input-handling finding(s) (SQLi/XSS/SSTI-class).")
    return ' '.join(parts) if parts else None


def sec_breach(r, domain):
    hibp = r.get('hibp', {})
    if not hibp:
        return None
    pwned = hibp.get('pwned') or hibp.get('pwned_count')
    if pwned:
        return (f"Have I Been Pwned data shows {pwned} match(es) tied to checked credentials for this target — "
                "meaning some of these may already be circulating in breach dumps used for credential stuffing.")
    return None


def sec_combined(findings):
    if not findings:
        return None
    top = findings[:3]
    lines = []
    for f in top:
        lines.append(f"- **{f['title']}** ({f['severity']}): {f['narrative']}")
    return ("Individually, several of the items above would be routine findings. Looked at together, "
            "a small number of combinations stand out as the realistic path an attacker would actually take:\n\n"
            + '\n\n'.join(lines))


def sec_bottom_line(findings, score, grade):
    if not findings:
        return "No cross-signal risk chains were identified from the reports on hand. Combined risk grade: not enough data yet."
    ranked = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f['severity']))[:3]
    lines = [f"{i}. **{f['title']}** — {f['recommendation']}" for i, f in enumerate(ranked, 1)]
    return (f"Combined exposure score: **{score}/100 (grade {grade})**.\n\n"
            f"If only three things get fixed this week, fix these first:\n\n" + '\n'.join(lines))


SECTIONS = [
    ("Who Owns This",                sec_identity),
    ("What a Visitor's Browser Sees", sec_first_contact),
    ("What's Running Under the Hood", sec_stack),
    ("How Big the Attack Surface Is", sec_surface),
    ("What a Crawl Turns Up",         sec_crawl),
    ("Known Issues on Record",        sec_known_issues),
    ("Breach Exposure",               sec_breach),
]


def build_report(domain, reports, findings, score, grade):
    lines = []
    lines.append(f"# Exposure Story — {domain}")
    lines.append(f"*Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by Merlin's storytelling report — "
                 "a plain-language read of data already collected by other Merlin modules.*\n")
    lines.append("## What This Report Is\n")
    lines.append("This isn't a raw finding dump. It's the same data, told as a story: what someone "
                 "outside your organization could learn about this target in the time it takes to "
                 "read this page, and where those individually-small facts add up to real risk.\n")

    any_section = False
    for title, fn in SECTIONS:
        para = fn(reports, domain)
        if para:
            any_section = True
            lines.append(f"## {title}\n")
            lines.append(para + "\n")

    if not any_section:
        lines.append("*No underlying module reports were found for this target yet — run some Merlin "
                     "scans first, then generate this report.*\n")

    combined = sec_combined(findings)
    if combined:
        lines.append("## The Combined Picture\n")
        lines.append(combined + "\n")

    lines.append("## Bottom Line\n")
    lines.append(sec_bottom_line(findings, score, grade) + "\n")

    return '\n'.join(lines)


def print_console(domain, markdown_len, findings, score, grade):
    print(logo)
    print(f"{LY}{'═'*65}{N}")
    print(f"  {W}MERLIN — Exposure Storytelling Report{N}")
    print(f"{LY}{'═'*65}{N}\n")
    print(f"  {LC}Target{N}              : {W}{domain}{N}")
    print(f"  {LC}Correlated findings{N}  : {LR if findings else LG}{len(findings)}{N}")
    if findings:
        grade_color = {'A': LG, 'B': LG, 'C': LY, 'D': LR, 'F': LR}.get(grade, W)
        print(f"  {LC}Combined risk score{N}  : {W}{score}/100{N}  Grade {grade_color}{grade}{N}")
    print(f"  {LC}Report length{N}       : {W}{markdown_len}{N} characters (Markdown)")
    print(f"\n{LY}{'═'*65}{N}")


def main():
    parser = argparse.ArgumentParser(description=LY + "Merlin -- Exposure Storytelling Report")
    parser.add_argument('-d', '--domain', required=True,
                         help='Domain/host the other Merlin modules were run against')
    parser.add_argument('-o', '--output', dest='output_dir', default=OUTPUT_DIR,
                         help='Directory containing prior Merlin JSON reports')
    args = parser.parse_args()

    reports, missing = load_reports(args.output_dir, args.domain)
    if not reports:
        print(f"{err} No Merlin reports found for {W}{args.domain}{N} in {args.output_dir}.")
        print(f"{note} Run some scans first, then generate the story report.")
        sys.exit(1)

    findings, score, grade = _load_correlate(args.output_dir, args.domain, reports)
    markdown = build_report(args.domain, reports, findings, score, grade)

    print_console(args.domain, len(markdown), findings, score, grade)

    os.makedirs(args.output_dir, exist_ok=True)
    fname = os.path.join(args.output_dir, f"story_{_norm(args.domain)}.md")
    with open(fname, 'w', encoding='utf-8') as f:
        f.write(markdown)
    print(f"{sukses} Story report saved -> {LY}{fname}{N}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\033[1;92m[*]\033[0m Story report interrupted. Returning to menu...\033[0m')
