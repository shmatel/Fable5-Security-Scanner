HEAD
\# 🔐 Fable 5 Security Scanner



AI-powered GitHub repository security auditor built by Mathew Fidel — 

Year 2 CS Student, Riara University, Nairobi, Kenya.



Built in response to Claude Fable 5's global release on July 1, 2026 — 

the same model that autonomously found a 29-year-old Squid Proxy memory 

leak (CVE-2026-47729) and is used by the US Department of Defense.



\## What It Does



Automatically scans any GitHub repository for:

\- 🚨 Hardcoded API keys and credentials

\- 💉 SQL injection vulnerabilities  

\- 🤖 Prompt injection risks in AI-powered apps

\- 🇰🇪 M-Pesa Daraja API security issues (Kenya-specific)

\- 📦 Vulnerable dependencies

\- 🔓 Missing input validation

\- And more — powered by Claude Fable 5



\## Quick Start



```bash

git clone https://github.com/YOUR\_USERNAME/fable5-security-scanner

cd fable5-security-scanner

pip install -r requirements.txt

cp .env.example .env

\# Add your ANTHROPIC\_API\_KEY and GITHUB\_TOKEN to .env

python scanner.py https://github.com/any/repo

```



\## Example Output

🔐 SECURITY AUDIT REPORT

Repository: example-mpesa-app

Scanned: 2026-07-01 09:15 EAT

Files Scanned: 12

CRITICAL Vulnerabilities: 2

HIGH Vulnerabilities: 3

MEDIUM Vulnerabilities: 1

🚨 CRITICAL — app.py

Hardcoded M-Pesa consumer key found in source code

Fix: Move to environment variables immediately



\## Tech Stack

\- Python 3.11

\- Claude Fable 5 (Anthropic API)

\- PyGithub

\- Rich (terminal UI)



\## Built By

Mathew Fidel — CS Student, Riara University, Nairobi


# Fable5-Security-Scanner
34c582537f5a13ebad8b0af2e87c1ea6c074d3ef
