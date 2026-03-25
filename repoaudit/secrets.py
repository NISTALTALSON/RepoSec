import os
import re

# Patterns for common secrets
SECRET_PATTERNS = [
    ("AWS Access Key",      r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",      r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Private Key",         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("GitHub Token",        r"ghp_[0-9a-zA-Z]{36}"),
    ("Generic API Key",     r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][a-zA-Z0-9]{16,}['\"]"),
    ("Password in code",    r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]"),
    ("Generic Secret",      r"(?i)(secret|token)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
    ("Google API Key",      r"AIza[0-9A-Za-z\-_]{35}"),
    ("Slack Token",         r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    ("Stripe Key",          r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
]

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                   ".pdf", ".zip", ".lock", ".sum", ".woff", ".ttf"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

def run_secret_scan(repo_path: str) -> list[dict]:
    """Scan all source files for hardcoded secrets using regex patterns."""
    findings = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for secret_type, pattern in SECRET_PATTERNS:
                            if re.search(pattern, line):
                                findings.append({
                                    "type": secret_type,
                                    "file": os.path.relpath(fpath, repo_path),
                                    "line": lineno,
                                    "snippet": line.strip()[:120],
                                })
                                break
            except (PermissionError, OSError):
                continue

    return findings