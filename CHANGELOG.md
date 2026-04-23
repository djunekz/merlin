# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [Unreleased]

### Planned
- Output saving to file per scan session
- JSON/HTML report export
- CVE lookup integration
- Support for custom wordlists in WebShake
- Proxy authentication support
- Batch URL scanning from file input
