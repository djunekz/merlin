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

[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen?style=flat-square)](https://github.com/djunekz/merlin)
[![Python](https://img.shields.io/badge/python-3.x-blue?style=flat-square)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-orange?style=flat-square)](https://termux.dev/)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-djunekz-purple?style=flat-square)](https://github.com/djunekz)

</div>

---

<div align="center">
  <h1>
    About
  </h1>
</div>

**Merlin** is a command-line website vulnerability scanner built with Python, designed to run on **Termux** (Android) and **Linux**. It provides a suite of tools for security analysts to assess website vulnerabilities with an easy-to-use terminal interface.

> [!NOTE]
> **For authorized security testing only.** Always obtain written permission before scanning any target. See [DISCLAIMER](DISCLAIMER.md) and [SECURITY](SECURITY.md) and [LICENSE](LICENSE).

---

<div align="center">
  <h1>
    Features
  </h1>
</div>

| Module | Description |
|---|---|
| **WP Vuln** | WordPress vulnerability checker — scans plugins, themes, and core for known CVEs |
| **SQLi Scan** | SQL injection vulnerability detector across URL parameters |
| **WebShake** | Web crawler and link enumerator with configurable depth |
| **Web Analyzer** | Full-stack web analyzer — headers, CMS detection, open ports, tech fingerprinting |
| **Settings** | Persistent JSON-based config editor (timeout, proxy, user-agent, threads, output dir) |
| **Update Checker** | Auto-detects latest version from GitHub and pulls updates via git |

---

<div align="center">
  <H1>
    Project Structure
  </H1>
</div>

```
merlin/
├── merlin.sh              # Main launcher (loading screen + entry point)
├── install.sh             # Installer for Termux / Linux
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── core/                  # Python source modules
│   ├── merlin.py          # Main menu & router
│   ├── merlincolor.py     # ANSI color constants
│   ├── merlinset.py       # Shared variables (version, author, prompts)
│   ├── merlinlogo.py      # ASCII banner & menu strings
│   ├── merlinconf.py      # Config loader / editor
│   ├── merlinup.py        # Update checker
│   ├── wpvuln.py          # WordPress vulnerability scanner
│   ├── websqli.py         # SQL injection scanner
│   ├── webshake.py        # Web crawler
│   └── webanalyst.py      # Web analyzer
└── .github/
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.md
    │   └── feature_request.md
    └── PULL_REQUEST_TEMPLATE.md
```

---

<div align="center">
  <h1>
    Installation
  </h1>
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

After installation, a symlink is created so you can run merlin from anywhere:

```bash
merlin
```

### Manual Install

#### Termux
```bash
pkg update && pkg install python git
pip install requests colorama beautifulsoup4 lxml urllib3
git clone https://github.com/djunekz/merlin
cd merlin
bash merlin.sh
```

#### Linux
```bash
sudo apt-get update && sudo apt-get install python3 python3-pip git
pip3 install requests colorama beautifulsoup4 lxml urllib3
git clone https://github.com/djunekz/merlin
cd merlin
bash merlin.sh
```

---

<div align="center">
  <h1>
    Usage
  </h1>
</div>

### Launch via symlink (after install)
```bash
merlin
```
### Or launch directly
```bash
bash merlin.sh
```
### Or run python directly
```bash
cd core && python merlin.py
```

### Menu Options

```
[1] Check WP Vuln        — WordPress vulnerability scan
[2] Check SQLi Vuln      — SQL injection scan
[3] WebShake Check       — Web crawler / link enumerator
[4] Web Analyzer         — Full web stack analyzer
[5] Settings / Config    — Edit scanner configuration
[6] Check Update         — Check and pull latest version
[x] exit
```

---

<div align="center">
  <h1>
    Configuration
  </h1>
</div>

Settings are stored in `core/merlin_config.json` and can be edited from within the tool via **[5] Settings / Config**.

| Key | Default | Description |
|---|---|---|
| `timeout` | `10` | HTTP request timeout in seconds |
| `user_agent` | Mobile Chrome | User-Agent header for requests |
| `max_threads` | `5` | Maximum concurrent threads |
| `output_dir` | `./merlin_output` | Directory to save scan results |
| `proxy` | *(empty)* | HTTP/HTTPS proxy (e.g. `http://127.0.0.1:8080`) |
| `verbose` | `false` | Show verbose output during scans |

---

## Requirements

- Python 3.6+
- Git
- pip packages: `requests`, `colorama`, `beautifulsoup4`, `lxml`, `urllib3`

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING](CONTRIBUTING.md) before submitting a pull request.

---

## Security

Please read [SECURITY](SECURITY.md) for our responsible disclosure policy.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer
> [!NOTE]
Please read [DISCLAIMER](DISCLAIMER.md) This tool is intended for **educational purposes** and **authorized penetration testing only**. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before scanning any target system.

---

<div align="center">
Official developer by <a href="https://github.com/djunekz">djunekz</a>
</div>
