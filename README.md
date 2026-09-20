# 🔐 Web Security Header Scanner

A lightweight Python-based security tool that analyzes HTTP response headers and identifies missing or misconfigured security controls.

Built as a practical cybersecurity project to understand **HTTP security headers, web hardening, security misconfigurations, and automated security assessment**.

---

## ⚡ Features

- 🔎 Analyzes common HTTP security headers
- 🔐 Checks HTTPS usage and redirects
- 🛡️ Performs basic HSTS analysis
- 🧱 Analyzes Content-Security-Policy (CSP)
- 🖼️ Checks X-Frame-Options
- 📄 Checks X-Content-Type-Options
- 🔗 Analyzes Referrer-Policy
- ⚠️ Generates severity-based security findings
- 💡 Provides recommendations for detected issues
- 📊 Calculates security-header coverage
- 📋 Supports JSON report generation
- ⏱️ Measures scan duration
- 🌐 Uses a browser-like User-Agent

---

## 🛠️ Technologies

- **Python 3**
- **Requests**
- **HTTP/HTTPS**
- **JSON**
- **Command-Line Interface (CLI)**

---

## 📋 Security Headers Checked

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Enforces HTTPS connections |
| `Content-Security-Policy` | Controls allowed browser resources |
| `X-Frame-Options` | Helps prevent clickjacking |
| `X-Content-Type-Options` | Helps prevent MIME sniffing |
| `Referrer-Policy` | Controls referrer information |

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/web-security-header-scanner.git
cd web-security-header-scanner
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

### Linux / Kali / WSL

```bash
source venv/bin/activate
```

### Windows

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 💻 Usage

Scan a website:

```bash
python scanner.py https://example.com
```

Generate a JSON report:

```bash
python scanner.py https://example.com --json
```

The JSON report contains:

- Scan timestamp
- Target URL
- Final URL after redirects
- HTTP status code
- HTTPS status
- Scan duration
- Header coverage
- Detailed header analysis
- Security findings
- Recommendations

Reports are stored in the `reports/` directory.

---

## 📸 Example

```text
 _       __     __   ____   ____  _____    ____  ____
| |     / /__  / /  / __ \ / __ \/ ___/   / __ \/ __ \
| | /| / / _ \/ /  / /_/ // /_/ / /       / /_/ / /_/ /
| |/ |/ /  __/ /  / _, _// ____/ /___    / _, _/ ____
|__/|__/\___/_/  /_/ |_/_/    \____/   /_/ |_/_/

Target: https://example.com
Final URL: https://example.com
Status Code: 200
[+] HTTPS: ENABLED

Security Headers:
----------------------------------------
[-] HSTS: MISSING
[-] CSP: MISSING
[-] Clickjacking Protection: MISSING
[-] MIME Sniffing Protection: MISSING
[-] Referrer Policy: MISSING

========================================
Security Header Coverage: 0/5 (0%)
Scan Duration: 0.42 seconds
========================================

Findings:
----------------------------------------
[MEDIUM] Missing HSTS
    Strict-Transport-Security is not present.

[MEDIUM] Missing Content-Security-Policy
    Content-Security-Policy is not present.

[MEDIUM] Missing X-Frame-Options
    X-Frame-Options is not present.
```

---

## 📁 Project Structure

```text
web-security-header-scanner/
│
├── scanner.py
├── requirements.txt
├── README.md
├── .gitignore
├── LICENSE
│
├── reports/
│   └── scan_report_*.json
│
└── screenshots/
```

---

## 🔍 How It Works

The scanner follows a simple assessment workflow:

```text
Target URL
    ↓
HTTP/HTTPS Request
    ↓
Follow Redirects
    ↓
Collect Response Headers
    ↓
Analyze Security Headers
    ↓
Identify Configuration Issues
    ↓
Generate Recommendations
    ↓
Optional JSON Report
```

The tool focuses on **security-header configuration and hardening** rather than attempting to determine whether an entire web application is secure.

---

## ⚠️ Limitations

This is a lightweight security assessment tool.

A missing security header does **not automatically mean that a website is vulnerable**. Header requirements depend on the application's architecture, functionality, browser behavior, and threat model.

This scanner does not perform:

- SQL Injection testing
- XSS testing
- Authentication testing
- Authorization testing
- File upload testing
- Business logic testing
- Vulnerability exploitation
- Full penetration testing

It should therefore be considered a **security-header assessment tool**, not a complete web vulnerability scanner.

---

## 🔐 Ethical Use

Only scan websites and systems that you **own or have explicit authorization to test**.

Do not use this tool to perform unauthorized security testing against third-party systems.

The author is not responsible for misuse of this project.

---

## 🚧 Future Improvements

Potential improvements include:

- Additional security headers
- Cookie security analysis
- TLS configuration checks
- More advanced CSP analysis
- HTML report generation
- Concurrent scanning
- Custom output formats
- Configurable severity rules

---

## 👨‍💻 Author

**Abdul Ahad**

Software Engineering Undergraduate  
Cybersecurity Enthusiast | Penetration Testing | Red Teaming

---

⭐ If you find this project useful, consider giving the repository a star.
