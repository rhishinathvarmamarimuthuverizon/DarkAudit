<p align="center">
  <img src="https://img.shields.io/badge/🐍-ApkViper-00d4aa?style=for-the-badge&labelColor=1a1b26" alt="ApkViper"/>
</p>

<h1 align="center">🐍 ApkViper</h1>
<h3 align="center">Advanced Android Security Assessment Platform</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/Dependencies-Zero-success?style=flat-square" alt="Deps"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/Version-2.0.0-orange?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/Rules-50+-red?style=flat-square" alt="Rules"/>
  <img src="https://img.shields.io/badge/OWASP-Mobile%20Top%2010-critical?style=flat-square" alt="OWASP"/>
</p>

<p align="center">
  <b>Enterprise-grade Android SAST scanner. Single file. Zero dependencies. Pure Python.</b>
</p>

---

## 🎯 What is ApkViper?

**ApkViper** is a fully standalone Static Application Security Testing (SAST) tool for Android APK files. It performs deep security analysis including manifest inspection, source code scanning, inter-procedural taint analysis, cryptographic weakness detection, and generates enterprise-level reports with real-world exploit proof-of-concepts.

Unlike other tools that require complex setups, Java runtimes, or cloud connectivity — ApkViper is **a single Python file** that runs anywhere Python 3.8+ is available. No installation. No configuration. No internet.

---

## ⚡ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **50+ Security Rules** | Covers OWASP Mobile Top 10, CWE/SANS Top 25, and Android-specific vulnerabilities |
| 🧬 **Taint Analysis** | Inter-procedural source-to-sink data flow tracking |
| 📦 **Binary AXML Parser** | Parses compiled AndroidManifest.xml without apktool |
| 🧮 **DEX Analysis** | Extracts classes, strings, and method calls from Dalvik bytecode |
| 💣 **Exploit Knowledge Base** | Real-world exploit scripts and PoC code for every finding |
| 🔓 **Bypass Techniques** | SSL pinning, root detection, biometric, and other bypass methods |
| 📊 **Enterprise Dashboard** | Risk scores, severity charts, OWASP category analysis, component breakdown |
| 📄 **Multi-Format Reports** | HTML, JSON, CSV, SARIF 2.1.0 |
| 🌐 **REST API** | Headless server mode for CI/CD pipeline integration |
| 💾 **Session Management** | Auto-save/restore scan sessions |
| 🎨 **Theme Support** | Dark and Light mode toggle |
| 🖥️ **Cross-Platform** | Windows, Linux, macOS — single file, no install |
| 📡 **CLI Mode** | Headless scanning with exit codes for automation |
| 🛡️ **CVE Database** | Known Android CVEs from 2020–2026 |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ApkViper Engine                          │
├───────────┬───────────┬───────────┬───────────┬─────────────┤
│  Binary   │  Pattern  │   Taint   │  Exploit  │   Report    │
│  Parsers  │  Scanner  │   Engine  │    DB     │  Generator  │
├───────────┼───────────┼───────────┼───────────┼─────────────┤
│ AXML      │ 50+ Rules │ Source →  │ PoC Code  │ HTML/JSON/  │
│ DEX       │ Regex +   │ Sink      │ Attack    │ CSV/SARIF   │
│ ZIP       │ Semantic  │ Tracking  │ Steps     │ + Dashboard │
└───────────┴───────────┴───────────┴───────────┴─────────────┘
```

---

## 📋 Requirements

| Requirement | Details |
|-------------|---------|
| **Python** | 3.8 or higher |
| **tkinter** | Included with Python (Windows/macOS). Install `python3-tk` on Linux |
| **Dependencies** | None — uses only Python standard library |
| **Internet** | Not required — fully offline operation |
| **Disk Space** | < 1 MB (single file) |

---

## 🚀 Installation

### Option 1: Clone from GitHub

```bash
git clone https://github.com/YOUR_USERNAME/ApkViper.git
cd ApkViper
python apkviper.py
```

### Option 2: Direct Download

Download `apkviper.py` and run directly — that's it:

```bash
python apkviper.py
```

### Linux Users (tkinter)

```bash
# Ubuntu / Debian
sudo apt-get install python3-tk

# Fedora / RHEL
sudo dnf install python3-tkinter

# Arch Linux
sudo pacman -S tk
```

### Verify Installation

```bash
python apkviper.py --help
```

Expected output:
```
ApkViper v2.0.0 - Android Security Assessment

Usage:
  python apkviper.py                          Launch GUI
  python apkviper.py --scan <apk>             Headless scan
  python apkviper.py --scan <apk> --format html --output report.html
  python apkviper.py --scan <apk> --format sarif
  python apkviper.py --server --port 8089     REST API

Features: 50 rules + taint analysis + exploit DB + bypass techniques
Formats: json, html, csv, sarif
Exit: 0=pass, 1=error, 2=critical/high
```

---

## 🖥️ Usage

### GUI Mode (Default)

```bash
python apkviper.py
```

Launches the full enterprise GUI with:
- 📁 File tree browser with extracted APK contents
- 📊 Dashboard with risk scores, pie charts, bar charts
- 🔍 Findings table with search/filter
- 📋 Detail view with exploit information
- 💻 Source code viewer with syntax highlighting
- 💣 Exploit knowledge base reference
- 🔓 Bypass techniques database
- ℹ️ About with compliance information

### CLI Mode (Headless Scanning)

```bash
# Basic scan — outputs JSON to stdout
python apkviper.py --scan app.apk

# Generate HTML report
python apkviper.py --scan app.apk --format html --output report.html

# SARIF report (for GitHub Code Scanning / Azure DevOps)
python apkviper.py --scan app.apk --format sarif --output results.sarif

# CSV export (for Excel / Google Sheets)
python apkviper.py --scan app.apk --format csv --output findings.csv
```

### REST API Server

```bash
# Start on default port 8089
python apkviper.py --server

# Custom port
python apkviper.py --server --port 9090
```

#### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Upload APK file and receive scan results |
| `GET` | `/health` | Server health check |
| `GET` | `/rules` | List all security rules |

#### Example API Call

```bash
curl -X POST http://localhost:8089/scan \
  -F "file=@app.apk" \
  -H "Content-Type: multipart/form-data"
```

---

## 🔐 Security Rules Coverage

### Rule Categories

| Category | Count | Covers |
|----------|-------|--------|
| **Manifest** | 5 | Debuggable, backup, cleartext, exported components, deeplinks |
| **Cryptography** | 4 | Weak hash (MD5/SHA1), insecure cipher (DES/RC4/ECB), predictable RNG, hardcoded keys |
| **Secrets & Storage** | 6 | API keys, logging sensitive data, clipboard, SharedPrefs, file permissions, sensitive files |
| **Network** | 6 | Trust-all certs, cleartext NSC, insecure WebView, SSL override, cert bypass, SSL pinning |
| **Platform** | 6 | Zip traversal, mutable PendingIntent, content provider injection, broadcast theft, deeplink hijack, fragment injection |
| **Injection** | 3 | SQL injection, command injection, tapjacking |
| **Resilience** | 6 | Root detection, emulator detection, dynamic code loading, unsafe deserialization, obfuscation, biometric |
| **Privacy** | 4 | Dangerous permissions, tracker SDKs, hardcoded URLs, GDPR consent |
| **Authentication** | 3 | Insecure credential storage, hardcoded sessions, weak password policy |
| **Web Security** | 4 | WebView XSS, XXE injection, SSRF, open redirect |
| **Cloud** | 1 | Firebase misconfiguration |
| **Other** | 3 | Debug code, malware patterns, native libraries |
| **Taint Analysis** | ∞ | Dynamic source→sink flow detection (getIntent → query, getExtras → exec, etc.) |

### Standards & Compliance

| Standard | Coverage |
|----------|----------|
| ✅ OWASP MASVS v2 | Mobile Application Security Verification Standard |
| ✅ OWASP MASTG | Mobile Application Security Testing Guide |
| ✅ OWASP Mobile Top 10 | 2024 Edition |
| ✅ CWE/SANS Top 25 | Common Weakness Enumeration |
| ✅ CVSS 3.1 | Common Vulnerability Scoring System |
| ✅ NIST SP 800-53 | Security and Privacy Controls |
| ✅ PCI-DSS | Payment Card Industry Mobile Requirements |
| ✅ GDPR | Data Protection Impact Assessment |
| ✅ SARIF 2.1.0 | Static Analysis Results Interchange Format |

---

## 📊 Report Formats

| Format | Best For | Features |
|--------|----------|----------|
| **HTML** | Executive reporting, client delivery | Full dashboard, charts, risk scores, styled findings, standalone file |
| **JSON** | CI/CD integration, custom tooling | Machine-readable, complete metadata, all fields |
| **CSV** | Spreadsheet analysis, tracking | Import to Excel/Sheets, pivot tables, trend analysis |
| **SARIF** | GitHub Advanced Security, Azure DevOps | Native code scanning alerts, PR annotations |

---

## 🔄 CI/CD Integration

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Pass — no critical/high findings | Pipeline continues |
| `1` | Error — scan failed | Investigate |
| `2` | Fail — critical or high findings detected | Block release |

### GitHub Actions

```yaml
name: Android Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Run ApkViper Security Scan
        run: |
          python apkviper.py --scan app/build/outputs/apk/release/app-release.apk \
            --format sarif --output results.sarif
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.11-slim
  script:
    - python apkviper.py --scan $APK_PATH --format html --output security-report.html
  artifacts:
    paths:
      - security-report.html
    when: always
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'python3 apkviper.py --scan ${APK_PATH} --format html --output security-report.html'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.html'
                }
            }
        }
    }
}
```

---

## 🆚 Comparison with Other Tools

| Feature | ApkViper | MobSF | QARK | AndroBugs | Oversecured |
|---------|----------|-------|------|-----------|-------------|
| Single File Deployment | ✅ | ❌ | ❌ | ❌ | ❌ |
| Zero Dependencies | ✅ | ❌ | ❌ | ❌ | ❌ |
| No Internet Required | ✅ | ✅ | ✅ | ✅ | ❌ |
| Taint Analysis | ✅ | ❌ | ❌ | ❌ | ✅ |
| Exploit PoC Generation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Bypass Techniques DB | ✅ | ❌ | ❌ | ❌ | ❌ |
| GUI Dashboard | ✅ | ✅ | ❌ | ❌ | ✅ |
| REST API | ✅ | ✅ | ❌ | ❌ | ✅ |
| SARIF Output | ✅ | ❌ | ❌ | ❌ | ❌ |
| CVE Database | ✅ | ✅ | ❌ | ❌ | ✅ |
| Binary Manifest Parse | ✅ | ✅ | ❌ | ✅ | ✅ |
| DEX Bytecode Analysis | ✅ | ✅ | ❌ | ❌ | ✅ |
| CVSS 3.1 Scoring | ✅ | ✅ | ❌ | ❌ | ✅ |
| Cross-Platform | ✅ | ✅ | ✅ | ✅ | ❌ |
| Free & Open Source | ✅ | ✅ | ✅ | ✅ | ❌ |
| Setup Time | **0 min** | 15+ min | 10+ min | 5+ min | N/A |
| Cost | **Free** | Free | Free | Free | $$$ |

---

## 🛠️ Project Structure

```
ApkViper/
├── apkviper.py          # Complete application (single standalone file)
├── README.md            # Documentation
├── LICENSE              # MIT License
└── .gitignore           # Git ignore rules
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get involved:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/new-rule`
3. **Add** your changes to `apkviper.py`
4. **Test** with real APK files from various domains
5. **Submit** a Pull Request

### Adding Custom Security Rules

Rules follow this structure in the `RULES` list:

```python
{
    "id": "DA-CAT-NNN",        # Unique ID (DA-[Category]-[Number])
    "name": "Rule Name",       # Human-readable title
    "sev": "HIGH",             # CRITICAL | HIGH | MEDIUM | LOW | INFO
    "cwe": "CWE-XXX",         # CWE reference number
    "owasp": "M1",            # OWASP Mobile Top 10 category
    "regex": r'pattern',       # Detection regex pattern
    "types": ["SOURCE"],       # File types: MANIFEST | SOURCE | RESOURCE
    "desc": "Description",     # What this vulnerability means
    "fix": "Remediation",      # How to fix it
    "cvss": 7.5               # CVSS 3.1 base score (0.0 - 10.0)
}
```

---

## 📜 License

```
MIT License

Copyright (c) 2026 darkfox

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⚠️ Disclaimer

ApkViper is designed for **authorized security testing and research only**.

- ✅ Scan applications you **own** or have **written authorization** to test
- ✅ Use findings for **defensive hardening** and **responsible disclosure**
- ❌ Do NOT use against applications without explicit permission
- ❌ Do NOT use exploit code for unauthorized access

The authors assume no liability for misuse of this tool or any damage caused by its use. Users are solely responsible for compliance with applicable laws and regulations.

---

## 🗺️ Roadmap

- [ ] Custom YAML rule authoring
- [ ] String decryption for obfuscated apps
- [ ] MSI/DMG installer packages
- [ ] Plugin system for custom analyzers
- [ ] Multi-APK batch scanning
- [ ] Differential scan (compare versions)
- [ ] SBOM generation (Software Bill of Materials)

---

## ☕ Support the Project

If ApkViper helped you in your security work, consider buying me a coffee!

<p align="center">
  <a href="https://www.paypal.com/paypalme/rhishinathvarma">
    <img src="https://img.shields.io/badge/☕_Buy_Me_A_Coffee-PayPal-00457C?style=for-the-badge&logo=paypal&logoColor=white" alt="Buy Me A Coffee"/>
  </a>
</p>

<p align="center">
  <b>PayPal:</b> <a href="https://paypal.me/rhishinathvarma">paypal.me/rhishinathvarma</a>
</p>

---

<p align="center">
  <b>Built with 🐍 Python by darkfox</b><br/>
  <sub>Security for Android Applications</sub><br/><br/>
  <img src="https://img.shields.io/badge/⭐_Star_this_repo-if_it_helped_you-yellow?style=for-the-badge" alt="Star"/>
</p>

