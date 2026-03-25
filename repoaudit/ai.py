import json

def generate_report(repo_name: str, findings: dict) -> str:
    """Send findings to local Ollama (Mistral) and get a human-readable security report."""
    try:
        import ollama
    except ImportError:
        return "_Ollama not installed. Run: pip install ollama_"

    semgrep = findings.get("semgrep", [])
    deps = findings.get("dependencies", [])
    secrets = findings.get("secrets", [])

    # Build a tight summary for the prompt (avoid token bloat)
    semgrep_summary = json.dumps(semgrep[:15], indent=2) if semgrep else "None"
    deps_summary = json.dumps(deps[:10], indent=2) if deps else "None"
    secrets_summary = json.dumps([
        {k: v for k, v in s.items() if k != "snippet"}
        for s in secrets[:10]
    ], indent=2) if secrets else "None"

    prompt = f"""You are a senior security engineer. Analyze these findings from a security audit of the GitHub repo "{repo_name}" and write a clear, actionable security report.

STATIC ANALYSIS FINDINGS (Semgrep):
{semgrep_summary}

VULNERABLE DEPENDENCIES:
{deps_summary}

HARDCODED SECRETS FOUND:
{secrets_summary}

Write a security report with these sections:
1. Executive Summary (2-3 sentences, overall risk level: Critical/High/Medium/Low)
2. Critical Issues (things that need fixing TODAY)
3. Dependency Vulnerabilities (list CVEs and what to upgrade to)
4. Secrets & Credentials (any hardcoded keys or passwords found)
5. Recommendations (top 5 actionable fixes, prioritized)

Be direct, specific, and practical. No fluff. Use markdown formatting."""

    try:
        response = ollama.chat(
            model="mistral",
            messages=[{"role": "user", "content": prompt}]
        )
        return response["message"]["content"]
    except Exception as e:
        return f"_AI report generation failed: {e}. Is Ollama running? Try: ollama serve_"