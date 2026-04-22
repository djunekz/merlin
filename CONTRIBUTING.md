# Contributing to Merlin

Thank you for your interest in contributing to Merlin! Contributions of all kinds are welcome — bug fixes, new features, documentation improvements, and more.

Please take a moment to read these guidelines before submitting anything.

---

## Code of Conduct

Be respectful and constructive. This project is a learning and research tool — keep discussions technical and professional.

---

## How to Contribute

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/merlin
cd merlin
git checkout -b feature/your-feature-name
```

### 2. Set Up Your Environment

```bash
bash install.sh
# or manually:
pip install requests colorama beautifulsoup4 lxml urllib3
```

### 3. Make Your Changes

- Keep code readable and consistent with the existing style
- All Python modules go inside the `core/` directory
- Use the existing color variables from `merlincolor.py` for terminal output
- Use the existing prompt variables from `merlinset.py` where possible
- Test your changes on both **Termux** and **Linux** if possible

### 4. Commit Your Changes

Write clear, descriptive commit messages:

```bash
git add .
git commit -m "feat: add proxy authentication support"
git push origin feature/your-feature-name
```

Use conventional commit prefixes where possible:
- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `refactor:` — code change that neither fixes a bug nor adds a feature
- `chore:` — maintenance tasks

### 5. Open a Pull Request

Open a PR against the `main` branch. Fill out the pull request template completely.

---

## What to Contribute

### Good first issues
- Fixing typos or grammar in output messages
- Adding missing error handling
- Improving help text or usage instructions

### Feature ideas
- New scan modules (XSS, LFI, open redirect, etc.)
- Output saving (JSON / HTML reports)
- Batch scanning from file
- Improved CVE lookups

### Please avoid
- Submitting malware or intentionally harmful code
- Adding features that bypass ethical safeguards
- Opening duplicate issues without checking existing ones first

---

## Code Style

- Python 3.6+ compatible
- 4-space indentation
- Keep imports at the top of each file
- Keep module responsibilities clearly separated (don't mix UI logic into scan logic)
- Strings that appear in the terminal should use the color constants from `merlincolor.py`

---

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) when opening an issue. Include as much detail as possible — OS, Python version, Termux version (if applicable), and exact error output.

---

## Questions?

Open a [GitHub Discussion](https://github.com/djunekz/merlin/discussions) or reach out via the author's GitHub profile.
