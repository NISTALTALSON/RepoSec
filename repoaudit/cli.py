import click
import sys
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from .fetcher import fetch_repo
from .scanner import run_semgrep
from .deps import run_dep_audit
from .secrets import run_secret_scan
from .ai import generate_report
from .report import save_report

console = Console()

@click.command()
@click.argument("repo_url")
@click.option("--output", "-o", default="report.md", help="Output file name (default: report.md)")
@click.option("--no-ai", is_flag=True, default=False, help="Skip AI summary, raw findings only")
def main(repo_url, output, no_ai):
    """
    RepoSec - Free AI-powered security audit for any GitHub repo.

    Example: reposec https://github.com/user/repo
    """
    console.print(Panel.fit(
        "[bold purple]RepoAudit[/bold purple] [dim]- Free Open Source Security Scanner[/dim]",
        border_style="purple"
    ))

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:

        task = progress.add_task("Fetching repository...", total=None)
        repo_path, repo_name = fetch_repo(repo_url)
        progress.update(task, description=f"[green]Fetched[/green] {repo_name}")

        task2 = progress.add_task("Running static analysis (Semgrep)...", total=None)
        semgrep_findings = run_semgrep(repo_path)
        count = len(semgrep_findings)
        progress.update(task2, description=f"[green]Static analysis done[/green] — {count} findings")

        task3 = progress.add_task("Scanning dependencies...", total=None)
        dep_findings = run_dep_audit(repo_path)
        progress.update(task3, description=f"[green]Dependency scan done[/green] — {len(dep_findings)} vulnerable packages")

        task4 = progress.add_task("Hunting for secrets...", total=None)
        secret_findings = run_secret_scan(repo_path)
        progress.update(task4, description=f"[green]Secret scan done[/green] — {len(secret_findings)} secrets found")

        all_findings = {
            "semgrep": semgrep_findings,
            "dependencies": dep_findings,
            "secrets": secret_findings,
        }

        if not no_ai:
            task5 = progress.add_task("Generating AI report (Ollama)...", total=None)
            ai_summary = generate_report(repo_name, all_findings)
            progress.update(task5, description="[green]AI report generated[/green]")
        else:
            ai_summary = None

        task6 = progress.add_task("Saving report...", total=None)
        save_report(output, repo_name, repo_url, all_findings, ai_summary)
        progress.update(task6, description=f"[green]Report saved[/green] -> {output}")

    total = count + len(dep_findings) + len(secret_findings)
    console.print(f"\n[bold green]Done![/bold green] Found [bold]{total}[/bold] issues total.")
    console.print(f"Report saved to [bold cyan]{output}[/bold cyan]\n")