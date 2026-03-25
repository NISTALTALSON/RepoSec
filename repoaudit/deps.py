import subprocess
import json
import os

def run_dep_audit(repo_path: str) -> list[dict]:
    """Scan dependencies for known CVEs. Supports Python and Node.js."""
    findings = []

    # Python — pip-audit
    req_file = os.path.join(repo_path, "requirements.txt")
    if os.path.exists(req_file):
        result = subprocess.run(
            ["pip-audit", "-r", req_file, "--format=json", "-q"],
            capture_output=True, text=True, timeout=60
        )
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                for dep in data:
                    for vuln in dep.get("vulns", []):
                        findings.append({
                            "package": dep["name"],
                            "installed_version": dep["version"],
                            "cve": vuln["id"],
                            "description": vuln.get("description", ""),
                            "fix_versions": vuln.get("fix_versions", []),
                            "ecosystem": "Python",
                        })
            except json.JSONDecodeError:
                pass

    # Node.js — npm audit
    pkg_file = os.path.join(repo_path, "package.json")
    if os.path.exists(pkg_file):
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True,
            timeout=60, cwd=repo_path
        )
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                vulns = data.get("vulnerabilities", {})
                for pkg_name, info in vulns.items():
                    findings.append({
                        "package": pkg_name,
                        "installed_version": info.get("range", "unknown"),
                        "cve": ", ".join(info.get("cves", ["N/A"])),
                        "description": info.get("title", ""),
                        "fix_versions": [],
                        "ecosystem": "Node.js",
                        "severity": info.get("severity", "unknown"),
                    })
            except json.JSONDecodeError:
                pass

    return findings