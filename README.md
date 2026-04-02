# RepoSec

> Free, open-source AI-powered security audit for any GitHub repository. One command. Zero cost.

```bash
pip install reposec
reposec https://github.com/anyone/anyrepo
```

## What it does

Point it at any public GitHub repo and get a full security report in ~30 seconds:

- Static analysis (Semgrep — OWASP Top 10, injection, XSS, SSRF)
- Dependency vulnerability scan (CVEs via pip-audit / npm audit)
- Hardcoded secrets detection (AWS keys, API tokens, passwords)
- AI-written human-readable report (runs locally via Ollama — no API key needed)

## Installation

```bash
pip install reposec
```

You also need [Ollama](https://ollama.com) for the AI report:

```bash
ollama pull mistral
```

## Usage

```bash
reposec https://github.com/user/repo

reposec https://github.com/user/repo --output myreport.md

reposec https://github.com/user/repo --no-ai
```

## Output.

A clean Markdown report with:
- Executive summary with overall risk level
- Table of all static analysis findings with severity
- List of vulnerable dependencies with CVE IDs and fix versions
- Hardcoded secrets with file + line number
- Top 5 prioritized recommendations

## Stack

| Tool | Purpose | Cost |
|------|---------|------|
| Semgrep | Static analysis | Free |
| pip-audit / npm audit | Dep scanning | Free |
| Custom regex scanner | Secret detection | Free |
| Ollama + Mistral 7B | AI report writing | Free, runs locally |

## License

MIT — free forever.

---

Built by [@NISTALTALSON](https://github.com/NISTALTALSON)
