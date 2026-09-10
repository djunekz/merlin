<div align="center">

```
  ___      ___   _______   _______   ___      __   ____  ____
 ("  \    /"  | /"      | /"      \ |"  |    |" \ (\"  \|"   |
  \   \  //   |(: ______)|:        |||  |    ||  ||.\   \    |
  /\   \/.    | \/      ||_____/   )|:  |    |:  ||: \.  \   |
 |: \.        | // _____) //      /  \  |___ |.  ||.  \   \. |
 |.  \    /:  |(:       ||:  __   \ ( \_|:  \|   ||    \   \ |
 |___|\__/|___| \_______)|__|  \___) \_______)\___)\___|\___\)
```

**Website Vulnerability Scanner for Termux & Linux**

[![Version](https://img.shields.io/badge/version-1.1.2-brightgreen?style=flat-square)](https://github.com/djunekz/merlin)
[![Python](https://img.shields.io/badge/python-3.x-blue?style=flat-square)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-orange?style=flat-square)](https://termux.dev/)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-djunekz-purple?style=flat-square)](https://github.com/djunekz)

</div>

---

<div align="center">
  <h1>About</h1>
</div>

**Merlin** is a command-line website vulnerability scanner built with Python, designed to run on **Termux** (Android) and **Linux**. It provides a comprehensive suite of tools for security analysts to assess website vulnerabilities through an easy-to-use terminal interface.

> [!NOTE]
> **For authorized security testing only.** Always obtain written permission before scanning any target. See [DISCLAIMER](DISCLAIMER.md), [SECURITY](SECURITY.md), and [LICENSE](LICENSE).

---

<div align="center">
  <h1>Features</h1>
</div>

| Module | Description |
|---|---|
| **WP Vuln** | WordPress vulnerability checker — plugins, themes, core CVEs, xmlrpc abuse, REST API user enumeration, version disclosure |
| **SQLi Scan** | SQL injection (45 payloads) + XSS (30 payloads) + SSTI + Path Traversal + Open Redirect + Info Disclosure |
| **WebShake** | Web crawler — CMS detection, email/phone harvest, secret/API key detection, broken link tracker, metadata scraper, JSON report |
| **Web Analyzer** | 14-module full-stack audit — CORS, cookie flags, clickjacking, broken access control, sensitive data exposure, score summary |
| **Port Scanner** | Multi-thread port scanner — banner grab, service fingerprint, HTTP probe per port, risky port warnings |
| **DNS Lookup** | Full DNS records + zone transfer + passive subdomain enumeration + SPF/DMARC analysis + DNSSEC check |
| **WHOIS Lookup** | Domain registration info with expiry countdown, abuse contact, EPP status explanation, privacy detection |
| **Tech Fingerprint** | 70+ technology signatures — CMS, framework, CDN, analytics, JS libraries, payment gateways, version extraction |
| **Header Grabber** | Security header grading A+ to F — CSP/HSTS deep analysis, cookie flags, redirect chain tracking |
| **SSL Audit** | Certificate expiry countdown, cipher suite check, deprecated protocol detection (TLS 1.0/1.1) |
| **WAF Detect** | Web Application Firewall identification from headers and response patterns |
| **Content Discovery** | Probe 40+ sensitive file paths — `.env`, `.git`, `backup.zip`, `config.php`, and more |
| **HIBP Check** | Leaked credential lookup via HaveIBeenPwned API (k-anonymity, no plain-text password sent) |
| **Correlation Engine** | Cross-references reports from every other module and surfaces "risk chains" — combinations of individually minor findings that become critical together (e.g. missing HSTS + weak TLS = downgrade surface; vulnerable CMS + exposed DB port = direct compromise path). Outputs a combined 0–100 risk score with letter grade |
| **Risk Timeline** | Snapshots a target's posture on every run and diffs it against the last one — flags regressions (▲), improvements (▼), and neutral changes (●): new open ports, certificates nearing expiry, header regressions, new/resolved vulnerabilities, and combined score movement over time |
| **Exposure Story Report** | Turns the same underlying data into a plain-language narrative (Markdown) for non-technical stakeholders — what an outsider could learn about the target, synthesized into a "combined picture" of the top risk chains and a bottom-line top-3 fix list |
| **Settings** | Persistent JSON config — 15+ options including proxy, HIBP API key, report format, crawl depth |
| **Update Checker** | Auto-detect latest version from GitHub and pull updates via git |

---

<div align="center">
  <h1>Project Structure</h1>
</div>

```
merlin/
├── merlin.sh                  # Main launcher (loading screen + entry point)
├── install.sh                 # Installer for Termux / Linux
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── core/                      # Python source modules
│   ├── __init__.py            # Version & author — single source of truth
│   ├── merlin.py              # Main menu & router (15 options)
│   ├── merlincolor.py         # ANSI color constants
│   ├── merlinset.py           # Shared variables (version, author, prompts)
│   ├── merlinlogo.py          # ASCII banner & menu strings
│   ├── merlinconf.py          # Config loader / editor (15+ settings)
│   ├── merlinup.py            # Update checker
│   ├── wpvuln.py              # WordPress vulnerability scanner
│   ├── websqli.py             # SQLi + XSS + SSTI + Path Traversal scanner
│   ├── webshake.py            # Web crawler & recon
│   ├── webanalyst.py          # Full web stack analyzer (14 modules)
│   ├── portscan.py            # Port scanner + banner grab
│   ├── dnslookup.py           # DNS lookup & subdomain enumeration
│   ├── whoislookup.py         # WHOIS lookup
│   ├── techfinger.py          # Technology fingerprinting (70+ signatures)
│   ├── headergrab.py          # HTTP header security grader (A+ to F)
│   ├── sslaudit.py            # SSL/TLS audit
│   ├── wafdetect.py           # WAF detection
│   ├── hibpcheck.py           # HaveIBeenPwned credential check
│   ├── contentdiscovery.py    # Sensitive file discovery
│   ├── correlate.py           # Correlation Engine — cross-module risk chains
│   ├── risktimeline.py        # Risk Timeline — posture snapshots & drift detection
│   └── storyreport.py         # Exposure Storytelling Report — plain-language narrative
└── .github/
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── feature_request.md
    └── PULL_REQUEST_TEMPLATE.md
```

---

<div align="center">
  <h1>Installation</h1>
</div>

### Quick Install

```bash
git clone https://github.com/djunekz/merlin
cd merlin
bash install.sh
```

The installer will auto-detect your environment and present a menu:

```
  [1] Install for Termux
  [2] Install for Linux (apt / Debian / Ubuntu)
  [3] Install for Arch Linux
  [4] Install for Fedora / RHEL
  [x] Exit
```

After installation, a symlink is created so you can run Merlin from anywhere:

```bash
merlin
```

### Manual Install

#### Termux
```bash
pkg update && pkg install python git
pip install requests colorama beautifulsoup4 lxml urllib3 dnspython python-whois
git clone https://github.com/djunekz/merlin
cd merlin
bash merlin.sh
```

#### Linux
```bash
sudo apt-get update && sudo apt-get install python3 python3-pip git
pip3 install requests colorama beautifulsoup4 lxml urllib3 dnspython python-whois
git clone https://github.com/djunekz/merlin
cd merlin
bash merlin.sh
```

---

<div align="center">
  <h1>Usage</h1>
</div>

### Launch via symlink (after install)
```bash
merlin
```

### Or launch directly
```bash
bash merlin.sh
```

### Or run Python directly
```bash
cd core && python merlin.py
```

### Menu Options

```
[1]  WP Vulnerability Scan  — WordPress vulnerability scan
[2]  SQLi / XSS / SSTI      — SQL injection + XSS + SSTI + Path Traversal
[3]  WebShake / Crawler     — Web crawler & recon
[4]  Web Security Analyzer  — Full web stack audit (14 modules)
[5]  Port Scanner           — Multi-thread port scan + banner grab
[6]  DNS Deep Lookup        — Full DNS records + subdomain enumeration
[7]  WHOIS Deep Lookup      — Domain registration info + abuse contact
[8]  Tech Fingerprint       — Identify 70+ technologies
[9]  HTTP Header Analyzer   — Security header grading A+ to F
[10] SSL/TLS Auditor        — Certificate & cipher suite check
[11] Content Discovery      — Scan for exposed sensitive files
[12] HIBP Credential Checker — Leaked credential lookup
[13] Correlation Engine     — Cross-module risk chains + combined risk score
[14] Risk Timeline          — Posture snapshots + drift tracking over time
[15] Exposure Story Report  — Plain-language narrative report for stakeholders
[0]  Settings / Config      — Edit scanner configuration
[u]  Check Update           — Check and pull latest version
[x]  Exit
```

> Modules `[13]`–`[15]` read the JSON reports already saved by `[1]`–`[12]` — run at least a couple of scans against a target before using them, or they'll tell you there's nothing to correlate yet.

---

<div align="center">
  <h1>Correlation, Timeline & Story Reports</h1>
</div>

`[13]`, `[14]`, and `[15]` don't scan anything themselves — they read the JSON reports that scans `[1]`–`[12]` already saved to `output_dir`, and turn that raw data into something more useful. Typical workflow against one target:

```bash
cd core
python merlin.py
# run [9] Header Analyzer, [10] SSL Auditor, [8] Tech Fingerprint,
# [5] Port Scanner, [1] WP Vuln Scan, [6] DNS Lookup, [11] Content Discovery, ...
# (any subset works — each rule/section just skips if its data isn't there)

# then:
[13]  Correlation Engine     -> combined risk score + cross-module risk chains
[14]  Risk Timeline          -> snapshot + drift vs. the last run (re-run [14] over time)
[15]  Exposure Story Report  -> plain-language .md report for stakeholders
```

Each writes its own report to `output_dir`:
- `correlate_{domain}.json` — findings, combined score/grade
- `history_{domain}.json` — append-only snapshot history (use `[14]` with "show history" to review it)
- `story_{domain}.md` — the narrative report, ready to paste into a client deliverable or convert to PDF/Word

---

<div align="center">
  <h1>Configuration</h1>
</div>

Settings are stored in `core/merlin_config.json` and can be edited from within the tool via **[0] Settings / Config**.

| Key | Default | Description |
|---|---|---|
| `timeout` | `10` | HTTP request timeout in seconds |
| `user_agent` | Mobile Chrome | User-Agent header for requests |
| `max_threads` | `5` | Maximum concurrent threads |
| `output_dir` | `./merlin_output` | Directory to save scan results |
| `proxy` | *(empty)* | HTTP/HTTPS proxy (e.g. `http://127.0.0.1:8080`) |
| `verbose` | `false` | Show verbose output during scans |
| `crawl_depth` | `2` | Maximum crawl depth for WebShake |
| `sqli_deep_scan` | `false` | Enable deep scan mode (45 payloads, slower) |
| `port_range` | `1-1024` | Default port range for port scanner |
| `dns_resolvers` | `[]` | Custom DNS resolvers (empty = system default) |
| `save_reports` | `true` | Auto-save JSON report after each scan |
| `report_format` | `json` | Report format (`json` / `html` — html planned) |
| `follow_redirects` | `true` | Follow HTTP redirects |
| `ssl_verify` | `true` | Verify SSL certificates on requests |
| `hibp_api_key` | *(empty)* | HaveIBeenPwned API key for email breach lookup |

---

## Requirements

- Python 3.6+
- Git
- pip packages: `requests`, `colorama`, `beautifulsoup4`, `lxml`, `urllib3`, `dnspython`, `python-whois`

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING](CONTRIBUTING.md) before submitting a pull request.

---

## Security

Please read [SECURITY](SECURITY.md) for the responsible disclosure policy.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  <h1>Known Gaps & TODO</h1>
</div>

> Things that are missing, incomplete, or need further work before the next release.

### Critical — Must Fix
| Item | Notes |
|---|---|
| `install.sh` not updated | Missing new dependencies: `dnspython` and `python-whois`. Without them, the DNS and WHOIS modules will crash immediately on a fresh install |
| `merlin.sh` out of sync | The loading screen still references 6 modules; it needs to reflect the current 14+ |
| `merlinlogo.py` out of sync | The ASCII menu in the logo still shows the old 6-option layout, not matching the actual `merlin.py` menu |
| `webshakeset.py` needs review | Unclear whether the `min` variable shadowing built-in `min()` was fixed here; requires a manual check |

### Important — Incomplete
| Item | Notes |
|---|---|
| HTML report export | `report_format: html` is accepted in config but not yet implemented — only JSON works |
| `hibpcheck.py` requires a paid API key | HIBP v3 API for email breach lookup requires a paid subscription key; setup instructions need to be added to the docs |
| SSL cipher check limited on Termux | Python's built-in `ssl` module on Termux is restricted — cipher enumeration may be incomplete compared to native OpenSSL |
| `contentdiscovery.py` wordlist is hardcoded | The 40+ sensitive paths are hardcoded; loading a custom wordlist from an external file is not yet supported |
| Subdomain enumeration is passive only | `dnslookup.py` uses a static 80-word wordlist — no integration with passive sources like crt.sh or SecurityTrails API |
| `CONTRIBUTING.md` and `SECURITY.md` are placeholders | Both files exist but contain no real content; they need to be written properly |

### Nice to Have — Roadmap
| Item | Notes |
|---|---|
| CVE lookup integration | Query NVD/NIST API directly from WP plugin/theme scan results |
| Batch URL scanning | Accept a `.txt` file of multiple URLs and scan them in sequence |
| Proxy authentication | Proxy with `username:password` credentials not yet supported |
| Scheduled scan / cron mode | ~~Run scans automatically on a schedule and diff results against previous runs~~ — drift detection now covered by `[14] Risk Timeline`; still need actual cron/scheduler wiring to auto re-run scans |
| Plugin system | Allow external modules to be dropped in without editing `merlin.py` directly |
| TUI (Terminal UI) | More interactive interface using `curses` or `rich` layout instead of plain input/print |
| PDF report export | Print-ready PDF report output |

---

## ⚠️ Disclaimer

> [!NOTE]
> Please read [DISCLAIMER](DISCLAIMER.md). This tool is intended for **educational purposes** and **authorized penetration testing only**. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before scanning any target system.

---

<div align="center">
Official developer by <a href="https://github.com/djunekz">djunekz</a>
</div>
