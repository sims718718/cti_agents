"""Rich terminal display helpers."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box
from rich.text import Text

# Severity indicator: bullet symbol + label so meaning is conveyed without
# relying on colour alone (colorblind accessibility).
_SEV_LABELS: dict[str, str] = {
    "critical": "[red]■ CRITICAL[/red]",
    "high":     "[orange3]▲ HIGH[/orange3]",
    "medium":   "[yellow]● MEDIUM[/yellow]",
    "low":      "[green]○ LOW[/green]",
}


class Display:
    """All terminal output for the CTI pipeline."""

    def __init__(self):
        self.console = Console(legacy_windows=False)

    # ── Banner ─────────────────────────────────────────────────────────────────

    def banner(self):
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold cyan]CTI Multi-Agent Threat Intelligence System[/bold cyan]\n"
                "[dim]Intel Collection -> Analysis -> Hunt Planning -> Peer Review[/dim]",
                border_style="cyan",
                padding=(1, 4),
            )
        )
        self.console.print(f"[dim]Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")

    # ── Phase headers ──────────────────────────────────────────────────────────

    def phase(self, title: str, agent: str):
        self.console.print()
        self.console.print(Rule(f"[bold yellow]{title}[/bold yellow]", style="yellow"))
        self.console.print(f"[dim]Agent: {agent}[/dim]\n")

    # ── Collection summary ─────────────────────────────────────────────────────

    def collection_summary(self, raw: dict):
        table = Table(
            title="Collected Intelligence",
            box=box.ROUNDED,
            border_style="blue",
            show_header=True,
            header_style="bold blue",
        )
        table.add_column("Source Type", style="cyan")
        table.add_column("Items", justify="right", style="bold white")

        counts = {
            "News Articles (RSS)": len(raw.get("news_articles", [])),
            "Botnet C2 IPs (Feodo)": len(raw.get("ip_indicators", [])),
            "IOCs (ThreatFox)": len(raw.get("iocs", [])),
            "Malicious URLs (URLhaus)": len(raw.get("url_indicators", [])),
            "Malware Samples (Bazaar)": len(raw.get("malware_samples", [])),
            "Known Exploited CVEs (CISA)": len(raw.get("vulnerabilities", [])),
            "STIX Objects": len(raw.get("stix_objects", [])),
        }

        total = 0
        for label, count in counts.items():
            style = "green" if count > 0 else "dim"
            table.add_row(f"[{style}]{label}[/{style}]", f"[{style}]{count}[/{style}]")
            total += count

        table.add_section()
        table.add_row("[bold]Total[/bold]", f"[bold green]{total}[/bold green]")
        self.console.print(table)
        self.console.print()

        # Show any feed errors that occurred during collection
        if raw.get("errors"):
            self.feed_errors(raw["errors"])

    def feed_errors(self, errors: list[dict]) -> None:
        """Display a warning table of feed collection errors."""
        if not errors:
            return
        t = Table(
            title="Feed Collection Errors",
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold yellow",
        )
        t.add_column("Source", style="cyan")
        t.add_column("Error", style="white")
        for err in errors:
            source = err.get("feed", err.get("source", "unknown"))
            t.add_row(source, err.get("error", "unknown error"))
        self.console.print(t)
        self.console.print()

    # ── Iteration ──────────────────────────────────────────────────────────────

    def iteration_header(self, iteration: int, max_iterations: int):
        self.console.print()
        self.console.print(
            Rule(
                f"[bold magenta]Iteration {iteration} / {max_iterations}[/bold magenta]",
                style="magenta",
            )
        )

    def agent_step(self, agent_name: str, action: str):
        self.console.print(f"\n  [bold cyan]▶ {agent_name}[/bold cyan]")
        self.console.print(f"    [dim]{action}[/dim]")

    def agent_done(self, agent_name: str, result_summary: str):
        self.console.print(f"    [green]✓[/green] {result_summary}")

    def parse_error_warning(self, agent_name: str) -> None:
        """Warn the user that an agent returned a parse-error fallback."""
        self.console.print(
            f"  [bold yellow]WARNING:[/bold yellow] {agent_name} failed to parse the "
            "model response — output may be empty or incomplete."
        )

    # ── Review result ──────────────────────────────────────────────────────────

    def review_result(self, review: dict, threshold: int):
        score = review.get("overall_score", "?")
        approved = review.get("approved", False)
        color = "green" if approved else "yellow" if isinstance(score, int) and score >= threshold - 2 else "red"

        self.console.print()
        self.console.print(
            Panel(
                f"[bold]Overall Score:[/bold] [{color}]{score}/10[/{color}]    "
                f"[bold]Status:[/bold] {'[green]APPROVED[/green]' if approved else '[red]NEEDS REVISION[/red]'}\n\n"
                + self._bullet_list("Strengths", review.get("strengths", []), "green")
                + self._bullet_list("Critical Gaps", review.get("critical_gaps", []), "red"),
                title="[bold]Lead Analyst Review[/bold]",
                border_style=color,
                padding=(0, 2),
            )
        )

        # Show scores table
        scores = review.get("scores", {})
        if scores:
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            t.add_column("Metric", style="dim")
            t.add_column("Score", justify="right")
            for metric, val in scores.items():
                label = metric.replace("_", " ").title()
                bar = "█" * int(val) + "░" * (10 - int(val)) if isinstance(val, int) else ""
                t.add_row(label, f"{val}/10 [dim]{bar}[/dim]")
            self.console.print(t)

    def _bullet_list(self, title: str, items: list, color: str) -> str:
        if not items:
            return ""
        bullets = "\n".join(f"  • {item}" for item in items)
        return f"[bold {color}]{title}:[/bold {color}]\n{bullets}\n\n"

    def iterating(self, review: dict):
        self.console.print()
        sf = review.get("summarizer_feedback", "")
        hf = review.get("hunter_feedback", "")
        if sf:
            self.console.print(f"  [yellow]Summarizer feedback:[/yellow] {self._trunc(sf)}")
        if hf:
            self.console.print(f"  [yellow]Hunter feedback:[/yellow] {self._trunc(hf)}")
        self.console.print("  [dim]-> Re-running agents with feedback...[/dim]")

    def approved(self, score):
        self.console.print(
            f"\n  [bold green][OK] Analysis approved by Lead Analyst (score: {score}/10)[/bold green]"
        )

    def max_iterations_reached(self, score):
        self.console.print(
            f"\n  [bold yellow][!] Max iterations reached (final score: {score}/10)[/bold yellow]"
        )

    # ── Final report ──────────────────────────────────────────────────────────

    def final_report(self, report: dict):
        self.console.print()
        self.console.print(Rule("[bold green]FINAL REPORT[/bold green]", style="green"))

        summary = report.get("intel_summary", {})
        hunt = report.get("hunt_plan", {})
        plan_meta = hunt.get("hunt_plan", {})

        # Executive Summary
        self.console.print(
            Panel(
                summary.get("executive_summary", "[no summary]"),
                title="[bold]Executive Summary[/bold]",
                border_style="blue",
            )
        )

        # Primary Threats
        threats = summary.get("threat_landscape", {}).get("primary_threats", [])
        if threats:
            t = Table(
                title="Primary Threats",
                box=box.ROUNDED,
                border_style="red",
                header_style="bold red",
            )
            t.add_column("Threat", style="bold white")
            t.add_column("Type")
            t.add_column("Severity")
            t.add_column("MITRE Techniques")
            for threat in threats:
                sev = threat.get("severity", "").lower()
                sev_label = _SEV_LABELS.get(sev, f"[white]{sev.upper()}[/white]")
                t.add_row(
                    threat.get("name", ""),
                    threat.get("type", ""),
                    sev_label,
                    ", ".join(threat.get("mitre_techniques", [])[:2]),
                )
            self.console.print(t)

        # Hunt Plan Overview
        self.console.print(
            Panel(
                f"[bold]Title:[/bold] {plan_meta.get('title', '')}\n"
                f"[bold]Objective:[/bold] {plan_meta.get('objective', '')}\n"
                f"[bold]Priority:[/bold] {plan_meta.get('priority', '')}   "
                f"[bold]Duration:[/bold] {plan_meta.get('estimated_duration', '')}   "
                f"[bold]Skill Level:[/bold] {plan_meta.get('analyst_skill_level', '')}",
                title="[bold]Hunt Plan Overview[/bold]",
                border_style="magenta",
            )
        )

        # Hypotheses summary
        hypotheses = hunt.get("hypotheses", [])
        if hypotheses:
            t = Table(
                title="Hunt Hypotheses",
                box=box.ROUNDED,
                border_style="magenta",
                header_style="bold magenta",
            )
            t.add_column("ID", style="bold")
            t.add_column("Title")
            t.add_column("Risk")
            t.add_column("Queries")
            for hyp in hypotheses:
                risk = hyp.get("risk_level", "").lower()
                risk_label = _SEV_LABELS.get(risk, f"[white]{risk.upper()}[/white]")
                t.add_row(
                    hyp.get("id", ""),
                    hyp.get("title", ""),
                    risk_label,
                    str(len(hyp.get("hunt_queries", []))),
                )
            self.console.print(t)

        # Priorities
        priorities = summary.get("recommended_priorities", [])
        if priorities:
            self.console.print(
                Panel(
                    "\n".join(f"  {i+1}. {p}" for i, p in enumerate(priorities)),
                    title="[bold]Recommended Priorities[/bold]",
                    border_style="yellow",
                )
            )

        # Metadata
        self.console.print(
            f"\n[dim]Iterations: {report.get('total_iterations')}  |  "
            f"Final Score: {report.get('final_score')}/10  |  "
            f"Status: {report.get('status')}[/dim]\n"
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _trunc(text: str, limit: int = 200) -> str:
        """Truncate text and append an ellipsis if it was cut."""
        return text[:limit] + "…" if len(text) > limit else text
