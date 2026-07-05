# prompts.py — Security audit prompts for Claude Fable 5

SYSTEM_PROMPT = """You are an expert cybersecurity engineer specialising in 
code security audits. You have deep expertise in:
- OWASP Top 10 vulnerabilities
- API security (especially M-Pesa Daraja API implementations)
- Prompt injection attacks in AI-powered applications
- Kenyan fintech security patterns
- Hardcoded credentials and secret management

When auditing code, you are thorough, precise and structured.
You always return findings in the exact JSON format requested.
You never make up vulnerabilities — only report what you actually find."""

def build_audit_prompt(filename: str, code: str) -> str:
    return f"""Audit this code file for security vulnerabilities.

FILE: {filename}

CODE:
{code[:8000]}

Return a JSON object with this exact structure:
{{
    "file": "{filename}",
    "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE",
    "vulnerabilities": [
        {{
            "type": "vulnerability type",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "line_hint": "approximate location or pattern",
            "description": "what the vulnerability is",
            "recommendation": "how to fix it"
        }}
    ],
    "kenya_specific": [
        {{
            "issue": "Kenya/M-Pesa specific security concern",
            "recommendation": "fix"
        }}
    ],
    "summary": "one paragraph summary of overall security posture"
}}

Return ONLY valid JSON. No preamble, no markdown, no explanation."""

DEPENDENCY_PROMPT = """Analyse these Python dependencies for known security issues.
Return JSON only:
{{
    "risky_packages": [
        {{
            "package": "name",
            "version": "version if known", 
            "risk": "description of risk",
            "fix": "recommended action"
        }}
    ],
    "overall_dependency_risk": "HIGH|MEDIUM|LOW|SAFE"
}}"""