import subprocess
import json
import os

def run_semgrep(repo_path: str) -> list[dict]:
    """Run Semgrep with OWASP + security rules. Returns list of findings."""
    findings = []

    result = subprocess.run(
        [
            "semgrep", "--config=auto",
            "--json",
            "--quiet",
            "--no-error",
            repo_path
        ],
        capture_output=True, text=True, timeout=120
    )

    if result.stdout:
        try:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                findings.append({
                    "rule": r.get("check_id", "unknown"),
                    "file": os.path.relpath(r["path"], repo_path),
                    "line": r["start"]["line"],
                    "message": r["extra"].get("message", ""),
                    "severity": r["extra"].get("severity", "WARNING"),
                    "code": r["extra"].get("lines", "").strip(),
                })
        except json.JSONDecodeError:
            pass

    return findings