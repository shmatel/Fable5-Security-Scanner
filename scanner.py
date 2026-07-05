# scanner.py — Fable 5 Security Scanner by Mathew Fidel

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from dotenv import load_dotenv
import anthropic
from github import Github, GithubException
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from prompts import SYSTEM_PROMPT, build_audit_prompt
from report import generate_report

load_dotenv()
console = Console()

# Supported file extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.php',
    '.java', '.go', '.rb', '.env', '.yml', '.yaml',
    '.json', '.sh', '.bash'
}

# Files to skip
SKIP_FILES = {
    'package-lock.json', 'yarn.lock', 'poetry.lock',
    '.gitignore', 'LICENSE', 'CHANGELOG.md'
}

MAX_FILES = 20  # Limit to avoid huge API costs
MAX_FILE_SIZE = 50000  # Skip files larger than 50KB


def get_repo_files(repo_url: str) -> tuple[list, str]:
    """Download files from a GitHub repository."""
    
    token = os.getenv('GITHUB_TOKEN')
    g = Github(token) if token else Github()
    
    # Parse repo from URL
    # Handles: https://github.com/user/repo or github.com/user/repo
    repo_url = repo_url.replace('https://github.com/', '').replace('github.com/', '')
    repo_url = repo_url.rstrip('/')
    
    console.print(f"\n[cyan]📡 Connecting to GitHub repository: {repo_url}[/cyan]")
    
    try:
        repo = g.get_repo(repo_url)
        repo_name = repo.name
    except GithubException as e:
        console.print(f"[red]❌ Could not access repository: {e}[/red]")
        sys.exit(1)
    
    files = []
    
    def get_contents_recursive(path=""):
        try:
            contents = repo.get_contents(path)
            for content in contents:
                if content.type == "dir":
                    get_contents_recursive(content.path)
                elif content.type == "file":
                    ext = Path(content.name).suffix.lower()
                    if (ext in SCANNABLE_EXTENSIONS and 
                        content.name not in SKIP_FILES and
                        content.size < MAX_FILE_SIZE):
                        files.append(content)
                        if len(files) >= MAX_FILES:
                            return
        except GithubException:
            pass
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("Fetching repository files...", total=None)
        get_contents_recursive()
    
    console.print(f"[green]✅ Found {len(files)} files to scan[/green]")
    return files, repo_name


def scan_file(client: anthropic.Anthropic, filename: str, code: str) -> dict:
    """Send a file to Claude Fable 5 for security analysis."""
    
    try:
        message = client.messages.create(
            model="claude-fable-5",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": build_audit_prompt(filename, code)
            }]
        )
        
        response_text = message.content[0].text.strip()
        
        # Clean response if needed
        if response_text.startswith("```"):
            response_text = response_text.split("```")[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        
        return json.loads(response_text)
        
    except json.JSONDecodeError:
        return {
            "file": filename,
            "risk_level": "UNKNOWN",
            "vulnerabilities": [],
            "kenya_specific": [],
            "summary": "Could not parse response for this file."
        }
    except Exception as e:
        return {
            "file": filename,
            "risk_level": "ERROR",
            "vulnerabilities": [],
            "kenya_specific": [],
            "summary": f"Error scanning file: {str(e)}"
        }


def check_dependencies(client: anthropic.Anthropic, files: list) -> dict:
    """Check requirements.txt for vulnerable dependencies."""
    
    req_file = None
    for f in files:
        if f.name in ('requirements.txt', 'package.json', 'Gemfile'):
            req_file = f
            break
    
    if not req_file:
        return {"risky_packages": [], "overall_dependency_risk": "UNKNOWN"}
    
    try:
        content = req_file.decoded_content.decode('utf-8')
        message = client.messages.create(
            model="claude-sonnet-4-6",  # Use cheaper model for deps
            max_tokens=1000,
            messages=[{
                "role": "user",
                "content": f"Check these dependencies for security issues:\n\n{content}\n\nReturn JSON only with risky_packages array and overall_dependency_risk field."
            }]
        )
        result = json.loads(message.content[0].text.strip())
        return result
    except Exception:
        return {"risky_packages": [], "overall_dependency_risk": "UNKNOWN"}


def main():
    console.print(Panel.fit(
        "[bold green]🔐 Fable 5 Security Scanner[/bold green]\n"
        "[dim]AI-powered code security auditor by Mathew Fidel[/dim]\n"
        "[dim]Powered by Claude Fable 5 — Anthropic[/dim]",
        border_style="green"
    ))
    
    # Get repo URL from user
    if len(sys.argv) > 1:
        repo_url = sys.argv[1]
    else:
        repo_url = console.input("\n[bold]Enter GitHub repo URL:[/bold] ").strip()
    
    if not repo_url:
        console.print("[red]❌ Please provide a GitHub repository URL[/red]")
        sys.exit(1)
    
    # Check API key
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        console.print("[red]❌ ANTHROPIC_API_KEY not found in .env file[/red]")
        sys.exit(1)
    
    client = anthropic.Anthropic(api_key=api_key)
    
    # Get repo files
    files, repo_name = get_repo_files(repo_url)
    
    if not files:
        console.print("[yellow]⚠️ No scannable files found in repository[/yellow]")
        sys.exit(0)
    
    # Scan each file
    results = []
    console.print(f"\n[bold cyan]🔍 Scanning {len(files)} files with Claude Fable 5...[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=False,
    ) as progress:
        
        for file in files:
            task = progress.add_task(f"Scanning {file.name}...", total=None)
            
            try:
                code = file.decoded_content.decode('utf-8', errors='ignore')
                result = scan_file(client, file.path, code)
                results.append(result)
                
                # Show quick result
                risk = result.get('risk_level', 'UNKNOWN')
                color = {
                    'CRITICAL': 'red', 'HIGH': 'orange1',
                    'MEDIUM': 'yellow', 'LOW': 'blue',
                    'SAFE': 'green', 'UNKNOWN': 'dim'
                }.get(risk, 'dim')
                
                progress.update(
                    task, 
                    description=f"[{color}]{risk}[/{color}] — {file.name}"
                )
                progress.stop_task(task)
                
            except Exception as e:
                progress.update(task, description=f"[red]ERROR[/red] — {file.name}")
                progress.stop_task(task)
    
    # Check dependencies
    console.print("\n[cyan]📦 Checking dependencies...[/cyan]")
    dep_results = check_dependencies(client, files)
    
    # Generate report
    generate_report(repo_name, repo_url, results, dep_results, console)


if __name__ == "__main__":
    main()