# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.1.2] — 2026-05-16

### Fixed
- **`merlinset.py`** — Variable `warn` was never defined, causing `NameError: name 'warn' is not defined` across multiple modules (`websqli.py`, `webanalyst.py`, `techfinger.py`, `headergrab.py`, `hibpcheck.py`, `sslaudit.py`, `contentdiscovery.py`); added `warn` as a proper colored symbol consistent with the existing symbol set
- **`portscan.py`** — `_parse_port_range()` would raise `ValueError: invalid literal for int()` when `PORT_RANGE` config value was a named preset string (e.g. `"full"`, `"remote"`); added preset resolver supporting `full`, `all`, `remote`, `web`, and `common` named ranges; non-numeric and unrecognized values now fall back to port 1–1024 instead of crashing
- **`wpvuln.py`** — Report save raised `[Errno 21] Is a directory` when the user passed a directory path (e.g. `./merlin_output`) as the output argument; fixed by detecting directory paths and automatically appending the filename `wpvuln_{domain}.json`; also added `os.makedirs()` to ensure parent directories exist before writing
- **`merlin.py`** — `os.system()` replaced with `subprocess.run()` wrapped in `try/except KeyboardInterrupt`; pressing `Ctrl+C` during any scan now cleanly prints "Scan interrupted. Returning to menu..." and resets `SIGINT` to default instead of dumping a raw traceback and leaving the terminal in a broken state
- **All scan modules** (`websqli.py`, `webshake.py`, `portscan.py`, `techfinger.py`, `headergrab.py`, `sslaudit.py`, `contentdiscovery.py`, `dnslookup.py`, `whoislookup.py`) — Added `KeyboardInterrupt` handler wrapping the `__main__` entry point so `Ctrl+C` always exits gracefully to the menu without raw traceback; added `import signal` to all affected files
- **All scan modules** (`webshake.py`, `webanalyst.py`, `websqli.py`, `techfinger.py`, `headergrab.py`, `sslaudit.py`, `contentdiscovery.py`, `wpvuln.py`) — Added `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)` and `logging.getLogger("urllib3").setLevel(logging.ERROR)` to suppress the repetitive `InsecureRequestWarning: Unverified HTTPS request` spam that flooded the terminal output on every request
- **`headergrab.py`** — `--compare-http` flag passed by `merlin.py` was not recognized, causing `unrecognized arguments: --compare-http` error; implemented the missing `--compare-http` argument and `_compare_http_https()` function that fetches both HTTP and HTTPS versions of the target and prints a side-by-side comparison of status codes, redirect chains, response time, grade scores, and per-header PRESENT/MISSING diff

- **`merlin.sh`** — `SCRIPT_DIR` resolved incorrectly when launched via symlink (`/usr/bin/merlin`); `${BASH_SOURCE[0]}` pointed to the symlink path, not the real file, so `core/` was never found; fixed by using `readlink -f` to resolve the symlink before computing the directory
- **`install.sh`** — `pip install` on Termux missing `--break-system-packages` flag, causing pip to refuse installation on newer Python versions; added flag to all pip calls in the Termux install path; also added `rich` to `PIP_DEPS` (required by `wpvuln.py` but missing from the installer, causing `ModuleNotFoundError` at runtime); fixed `SCRIPT_DIR` to also use `readlink -f` for consistency
- **`websqli.py`** / **`webanalyst.py`** — `logging.basicConfig()` call was split across a multiline string; the regex patch for adding `urllib3` log suppression broke the string mid-token (`%(asctime)` was cut, leaving `s'+LC+...` as a dangling fragment), causing `SyntaxError: closing parenthesis ']' does not match opening parenthesis '('`; fixed by rewriting the full `basicConfig` block cleanly on one logical line
- **`contentdiscovery.py`** / **`dnslookup.py`** / **`headergrab.py`** / **`portscan.py`** / **`sslaudit.py`** / **`techfinger.py`** / **`whoislookup.py`** — `KeyboardInterrupt` handler `print()` string was written with a literal newline character instead of the escape sequence `\n`, causing Python to treat the string as unterminated and raise `SyntaxError: unterminated string literal`; fixed across all 7 files

### Changed
- **`merlinconf.py`** — Default `timeout` reduced from 10 s to 8 s; `TIMEOUT` is now exported as a `(connect_timeout, read_timeout)` tuple `(8, 16)` so slow targets fail fast on connect without waiting forever on a hung read

---

## [1.1.1] — 2026-05-16

### Fixed
- **`merlinset.py`** — Variable `warn` was never defined, causing `NameError: name 'warn' is not defined` across multiple modules (`websqli.py`, `webanalyst.py`, `techfinger.py`, `headergrab.py`, `hibpcheck.py`, `sslaudit.py`, `contentdiscovery.py`); added `warn` as a proper colored symbol consistent with the existing symbol set
- **`portscan.py`** — `_parse_port_range()` would raise `ValueError: invalid literal for int()` when `PORT_RANGE` config value was a named preset string (e.g. `"full"`, `"remote"`); added preset resolver supporting `full`, `all`, `remote`, `web`, and `common` named ranges; non-numeric and unrecognized values now fall back to port 1–1024 instead of crashing
- **`wpvuln.py`** — Report save raised `[Errno 21] Is a directory` when the user passed a directory path (e.g. `./merlin_output`) as the output argument; fixed by detecting directory paths and automatically appending the filename `wpvuln_{domain}.json`; also added `os.makedirs()` to ensure parent directories exist before writing

---

## [1.1.0] — 2026-05-15

### Added
#### New Modules
- **`portscan.py`** — Multi-thread port scanner with banner grabbing, service fingerprinting from banners (SSH/FTP/MySQL/Redis/etc.), HTTP probe per port (title/server/redirect), scan presets (web/db/mail/remote/common/full), 80+ service map, risky port warnings (Redis/MongoDB/Docker/Elasticsearch)
- **`dnslookup.py`** — Full DNS lookup: zone transfer (AXFR), reverse DNS, passive subdomain enumeration (80+ wordlist, multi-thread), email security analysis (SPF/DMARC policy), DNSSEC check, full record types (A/AAAA/MX/NS/TXT/CNAME/SOA/SRV/CAA/SPF/DMARC)
- **`whoislookup.py`** — WHOIS lookup with extended server map (30+ TLDs), abuse contact parsing (email+phone), expiry countdown + status (CRITICAL/WARNING), EPP status code explanation, WHOIS privacy detection, registrant/admin/tech contact parsing
- **`techfinger.py`** — Technology fingerprinting with 70+ signatures: CMS, framework, web server, CDN, analytics, JS libraries, payment gateways, hosting providers; per-tech version extraction, categorized output, cookie-based detection
- **`headergrab.py`** — HTTP header grabber with security grading A+ to F (like securityheaders.com), CSP deep analysis (unsafe-inline/eval/wildcard), HSTS deep analysis (max-age/includeSubDomains/preload), cookie flag analysis, HTTP→HTTPS redirect check, redirect chain tracker, information-leaking header detection
- **`sslaudit.py`** — SSL/TLS audit: cipher suite check, certificate expiry countdown, chain validation, deprecated protocol detection (TLS 1.0/1.1)
- **`wafdetect.py`** — Standalone WAF detection: identifies WAF vendor (Cloudflare, Akamai, Imperva, AWS WAF, F5, etc.) from headers and response patterns
- **`hibpcheck.py`** — Leaked credential checker via HaveIBeenPwned API using k-anonymity model (no plain-text password transmitted)
- **`contentdiscovery.py`** — Sensitive file discovery: probes 40+ sensitive paths (`.env`, `backup.zip`, `config.php`, `.git/HEAD`, etc.) that may be unintentionally exposed; multi-thread, saves JSON report
- **`__init__.py`** — Single source of truth for version and author metadata; all modules now import from here so a version bump requires only one line change

#### New Features in Existing Modules
- **JSON** — report export, HTML export still pending
- **`webshake.py`** — CMS detection (12 CMS), email and phone harvesting, HTML comment scraper, external script tracker, secret/API key detection in source HTML, sensitive file checker (40+ paths), page hash deduplication, redirect chain tracking, slowest page ranking, metadata scraper (title/description/keywords/og tags), JSON report export
- **`websqli.py`** — 45 SQLi payloads (error-based/union/time-based blind/stacked/MSSQL/Oracle/PostgreSQL), 50+ error signatures, 30 XSS payloads + attribute injection + DOM-based + filter bypass, SSTI detection (Jinja2/Twig/Freemarker), Path Traversal (11 payloads), HTML Injection, Open Redirect (14 redirect parameters), Info Disclosure scan, injection across all parameters (not just the first), JSON report export
- **`webanalyst.py`** — 14 check modules: SSL, security headers, robots.txt, sitemap, sensitive files, directory listing, CORS (reflect+credentials), cookie flags, clickjacking, mixed content, SRI check, form security (CSRF/method/file upload), WAF detection, broken access control (30+ endpoints), sensitive data exposure in source (14 patterns), final score summary
- **`wpvuln.py`** — xmlrpc.php check, REST API user enumeration, WP version disclosure check, `readme.html` exposure check, retry logic (3x with exponential backoff) for all requests
- **`merlinconf.py`** — 9 new settings: `crawl_depth`, `sqli_deep_scan`, `port_range`, `dns_resolvers`, `save_reports`, `report_format`, `follow_redirects`, `ssl_verify`, `hibp_api_key`; config merging on update (existing values are preserved); fallback save with backup and recreate on corrupted JSON
- **`merlin.py`** — Main menu expanded from 6 to 14 options; dispatch dictionary + while loop; all new modules registered

### Fixed
- **`merlincolor.py`** — `LG` was defined twice (`\033[1;37m` then overwritten by `\033[1;92m`); first variable renamed to `LW` (bright white) to eliminate the conflict
- **`merlinset.py`** — `from datetime import *` replaced with `from datetime import datetime, date, timedelta`; the wildcard import was pulling `datetime.time` (the class) into the global namespace, silently overwriting the `time` module and causing `time.sleep()` to raise `AttributeError: type object 'time' has no attribute 'sleep'`
- **`merlinset.py`** — Variable named `min` was shadowing Python's built-in `min()`; renamed to `min_pfx`
- **`webshakeset.py`** — Same shadowing issue: variable `min` renamed to `min_pfx`
- **`webshake.py`** — `sys.exit()` was called inside an exception loop, killing the entire program when a single URL failed; replaced with `continue`; added separate error handling for timeout vs. connection errors
- **`websqli.py`** — Critical bug: `url.split('=')[0] + '=' + payload` only injected into the first parameter, completely breaking multi-parameter URLs; replaced with a proper `_inject_param()` function using `urllib.parse`
- **`merlin.py`** — URLs were not quoted when passed to `os.system()`, causing failures with URLs containing spaces or special characters; switched to `subprocess`; unhandled `KeyboardInterrupt` / `EOFError` now caught with a clean exit message
- **`merlinconf.py`** — New config keys were not merged when a config file already existed, causing new settings to be silently lost after updates; fixed with `defaults | existing` merge strategy; no fallback on corrupted JSON — now catches the error, backs up the broken file, and recreates defaults
- **`wpvuln.py`** — No retry logic on requests; all requests now retry up to 3 times with exponential backoff
- **`merlinset.py`** / **`merlinup.py`** / **`merlinlogo.py`** / **`webshakeset.py`** — Hardcoded version strings removed from all files; version is now imported from `core/__init__.py` (single source of truth)

### Changed
- `core/` module count expanded from 9 to 20 modules
- `merlin.py` main menu expanded from 6 to 14 options
- All scan modules now support saving JSON reports to `output_dir`
- Version management centralized in `core/__init__.py`

---

## [1.0.0] — 2026-04-23

### Added
- Initial public release of Merlin
- **WP Vuln** — WordPress vulnerability scanner (`wpvuln.py`)
- **SQLi Scan** — SQL injection vulnerability scanner (`websqli.py`)
- **WebShake** — Web crawler and link enumerator (`webshake.py`)
- **Web Analyzer** — Full web stack analyzer with CMS detection and header inspection (`webanalyst.py`)
- **Settings / Config** — Persistent JSON configuration editor (`merlinconf.py`)
  - Configurable: timeout, user-agent, max threads, output directory, proxy, verbose mode
- **Update Checker** — GitHub-based version check and auto-update via `git pull` (`merlinup.py`)
- **Animated launcher** — `merlin.sh` with loading screen, spinner animation, and graceful exit screen
- **Installer** — `install.sh` with support for Termux, Debian/Ubuntu, Arch Linux, and Fedora/RHEL
  - Automatic symlink creation to system `$PATH`
- Modular project structure with all Python modules isolated in `core/`
- ANSI color support via `merlincolor.py`
- Shared prompts and version variables via `merlinset.py`
- ASCII banner and menu strings via `merlinlogo.py`
- MIT License with ethical use notice
- `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
- GitHub issue templates (bug report, feature request)
- GitHub pull request template

### Fixed
- Menu option `[2]` and `[3]` now correctly prompt for a target URL before launching scan
- Menu option `[4]` now correctly calls `webanalyst.py` (was incorrectly referencing `webvuln.py`)

---

### Planned
- Output saving to file per scan session *(partially shipped in v1.1.0 via JSON report)*
- CVE lookup integration
- Support for custom wordlists in WebShake and Content Discovery
- Proxy authentication support
- Batch URL scanning from file input
- HTML report export (pretty dashboard)
- Scheduled scan / cron mode
- Plugin system for external modules
