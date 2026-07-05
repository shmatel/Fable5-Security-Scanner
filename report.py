# report.py — Report generator for Fable 5 Security Scanner

import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box


SEVERITY_COLORS = {
    'CRITICAL': 'bold red',
    'HIGH': 'bold orange1', 
    'MEDIUM': 'bold yellow',
    'LOW': 'bold blue',
    'SAFE': 'bold green',
    'UNKNOWN': 'dim'
}


def generate_report(
    repo_name: str, 
    repo_url: str, 
    results: list, 
    dep_results: dict,
    console: Console
):
    """Generate and display the security report."""
    
    console.print(f"\n\n{'='*60}")
    console.print(Panel.fit(
        f"[bold]🔐 SECURITY AUDIT REPORT[/bold]\n"
        f"[dim]Repository: {repo_name}[/dim]\n"
        f"[dim]Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M')} EAT[/dim]\n"
        f"[dim]Powered by Claude Fable 5[/dim]",
        border_style="cyan"
    ))
    
    # Count vulnerabilities by severity
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    critical_files = []
    
    for result in results:
        risk = result.get('risk_level', 'UNKNOWN')
        vulns = result.get('vulnerabilities', [])
        
        for v in vulns:
            sev = v.get('severity', '')
            if sev == 'CRITICAL':
                total_critical += 1
            elif sev == 'HIGH':
                total_high += 1
            elif sev == 'MEDIUM':
                total_medium += 1
            elif sev == 'LOW':
                total_low += 1
        
        if risk in ('CRITICAL', 'HIGH'):
            critical_files.append(result)
    
    # Summary table
    summary_table = Table(title="Scan Summary", box=box.ROUNDED)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Count", justify="center")
    
    summary_table.add_row("Files Scanned", str(len(results)))
    summary_table.add_row(
        "[bold red]CRITICAL Vulnerabilities[/bold red]", 
        f"[bold red]{total_critical}[/bold red]"
    )
    summary_table.add_row(
        "[bold orange1]HIGH Vulnerabilities[/bold orange1]", 
        f"[bold orange1]{total_high}[/bold orange1]"
    )
    summary_table.add_row(
        "[bold yellow]MEDIUM Vulnerabilities[/bold yellow]", 
        f"[bold yellow]{total_medium}[/bold yellow]"
    )
    summary_table.add_row(
        "[bold blue]LOW Vulnerabilities[/bold blue]", 
        f"[bold blue]{total_low}[/bold blue]"
    )
    
    console.print("\n")
    console.print(summary_table)
    
    # Critical and High findings detail
    if critical_files:
        console.print("\n[bold red]🚨 CRITICAL & HIGH RISK FILES[/bold red]\n")
        
        for result in critical_files:
            filename = result.get('file', 'Unknown')
            risk = result.get('risk_level', 'UNKNOWN')
            vulns = result.get('vulnerabilities', [])
            kenya = result.get('kenya_specific', [])
            summary = result.get('summary', '')
            
            color = SEVERITY_COLORS.get(risk, 'dim')
            
            console.print(Panel(
                f"[{color}]Risk Level: {risk}[/{color}]\n\n"
                f"[bold]Summary:[/bold] {summary}\n",
                title=f"📄 {filename}",
                border_style=color.replace('bold ', '')
            ))
            
            # Vulnerabilities table
            if vulns:
                vuln_table = Table(box=box.SIMPLE, show_header=True)
                vuln_table.add_column("Severity", style="bold", width=10)
                vuln_table.add_column("Type", width=20)
                vuln_table.add_column("Description", width=40)
                vuln_table.add_column("Fix", width=30)
                
                for v in vulns:
                    sev = v.get('severity', 'UNKNOWN')
                    sev_color = SEVERITY_COLORS.get(sev, 'dim')
                    vuln_table.add_row(
                        f"[{sev_color}]{sev}[/{sev_color}]",
                        v.get('type', ''),
                        v.get('description', '')[:80],
                        v.get('recommendation', '')[:50]
                    )
                
                console.print(vuln_table)
            
            # Kenya-specific issues
            if kenya:
                console.print("[bold cyan]🇰🇪 Kenya-Specific Issues:[/bold cyan]")
                for k in kenya:
                    console.print(f"  • {k.get('issue', '')}")
                    console.print(f"    [dim]Fix: {k.get('recommendation', '')}[/dim]")
    
    # Dependency results
    risky_packages = dep_results.get('risky_packages', [])
    dep_risk = dep_results.get('overall_dependency_risk', 'UNKNOWN')
    
    if risky_packages:
        console.print(f"\n[bold orange1]📦 DEPENDENCY RISKS ({dep_risk})[/bold orange1]\n")
        for pkg in risky_packages:
            console.print(
                f"  ⚠️  [orange1]{pkg.get('package')}[/orange1] — "
                f"{pkg.get('risk', '')}\n"
                f"     Fix: [green]{pkg.get('fix', '')}[/green]"
            )
    
    # Final verdict
    console.print("\n")
    if total_critical > 0:
        verdict = "[bold red]❌ CRITICAL ISSUES FOUND — Fix before deployment[/bold red]"
    elif total_high > 0:
        verdict = "[bold orange1]⚠️ HIGH RISK ISSUES FOUND — Fix urgently[/bold orange1]"
    elif total_medium > 0:
        verdict = "[bold yellow]⚡ MEDIUM RISK ISSUES FOUND — Fix soon[/bold yellow]"
    elif total_low > 0:
        verdict = "[bold blue]ℹ️ LOW RISK ISSUES FOUND — Review when possible[/bold blue]"
    else:
        verdict = "[bold green]✅ NO MAJOR VULNERABILITIES FOUND — Good job![/bold green]"
    
    console.print(Panel(
        verdict + f"\n\n[dim]Report generated by Fable 5 Security Scanner\n"
        f"Built by Mathew Fidel — github.com/your-username/fable5-security-scanner[/dim]",
        border_style="cyan",
        title="🔐 Final Verdict"
    ))
    
    # Save JSON report
    report_data = {
        "repo": repo_url,
        "scanned_at": datetime.now().isoformat(),
        "summary": {
            "files_scanned": len(results),
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low
        },
        "files": results,
        "dependencies": dep_results
    }
    
    report_filename = f"security_report_{repo_name}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(report_filename, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    console.print(f"\n[dim]📄 Full report saved to: {report_filename}[/dim]\n")