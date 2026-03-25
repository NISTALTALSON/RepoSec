import os
import re
import shutil
import subprocess
import tempfile

def fetch_repo(repo_url: str) -> tuple[str, str]:
    """Clone a GitHub repo to a temp directory. Returns (path, repo_name)."""
    repo_url = repo_url.rstrip("/")
    if not repo_url.startswith("https://github.com/"):
        raise ValueError("Only GitHub URLs are supported right now. Example: https://github.com/user/repo")

    match = re.match(r"https://github\.com/([^/]+)/([^/]+)", repo_url)
    if not match:
        raise ValueError("Invalid GitHub URL format.")

    repo_name = f"{match.group(1)}/{match.group(2)}"
    tmp_dir = tempfile.mkdtemp(prefix="repoaudit_")
    clone_path = os.path.join(tmp_dir, match.group(2))

    result = subprocess.run(
        ["git", "clone", "--depth=1", repo_url, clone_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed: {result.stderr}")

    return clone_path, repo_name