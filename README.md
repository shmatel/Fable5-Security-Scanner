Fable 5 Security Scanner
AI-powered GitHub repository security auditor built by Mathew Fidel — 

Built in response to Claude Fable 5's global release on July 1, 2026 — 
the same model that autonomously found a 29-year-old Squid Proxy memory 
leak (CVE-2026-47729) and is used by the US Department of Defense.

What It Does
Automatically scans any GitHub repository for:
- Hardcoded API keys and credentials
- SQL injection vulnerabilities  
- Prompt injection risks in AI-powered apps
- Vulnerable dependencies
- Missing input validation

## Quick Start
```bash
git clone https://github.com/YOUR\_USERNAME/fable5-security-scanner
cd fable5-security-scanner
pip install -r requirements.txt
cp .env.example .env
\# Add your ANTHROPIC\_API\_KEY and GITHUB\_TOKEN to .env
python scanner.py https://github.com/any/repo
```

Example Output:

<img width="1359" height="462" alt="Screenshot 2026-07-10 154224" src="https://github.com/user-attachments/assets/6ececabb-f5ce-4415-8aed-3ec224f94588" />
<img width="1354" height="585" alt="Screenshot 2026-07-10 154238" src="https://github.com/user-attachments/assets/e631c5ad-8966-42fb-a879-4e9fa8ef0f71" />






Tech Stack:
Python 3.11
Claude Fable 5 (Anthropic API)
PyGithub
Rich (terminal UI)








Built By:
Mathew Fidel — CS Student, Riara University, Nairobi
Fable5-Security-Scanner
34c582537f5a13ebad8b0af2e87c1ea6c074d3ef

***
!!! WARNING / DISCLAIMER !!!
Update(s) may not be configured due to insufficient capital for api-tokens. However, it runs perfectly fine the way it is already.
***
