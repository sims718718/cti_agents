#!/usr/bin/env python3
"""CTI Multi-Agent Threat Intelligence System.

Agents
------
1. IntelCollectorAgent  – Pulls raw OSINT from RSS, abuse.ch APIs, CISA KEV, and STIX.
2. IntelSummarizerAgent – Uses Claude to distill raw data into a structured threat summary.
3. ThreatHunterAgent    – Uses Claude to build prioritized hunt hypotheses and detection queries.
4. LeadAnalystAgent     – Uses Claude to peer-review both outputs, score quality,
                          and iterate with specific feedback until the threshold is met.

Usage
-----
    python main.py                          # default: RSS + API feeds
    python main.py --feeds rss api stix     # include STIX (slower)
    python main.py --output report.json     # save final JSON report
    python main.py --max-iter 2 --threshold 8
"""
from __future__ import annotations

import json
import sys

import typer
from dotenv import load_dotenv

load_dotenv()

from config import ANTHROPIC_API_KEY, MAX_ITERATIONS, QUALITY_THRESHOLD
from pipeline import run_pipeline
from utils.display import Display

app = typer.Typer(add_completion=False)


@app.command()
def run(
    feeds: list[str] = typer.Option(
        ["rss", "api"],
        "--feeds",
        "-f",
        help="Feed types to collect: rss, api, stix",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Write final JSON report to this file path",
    ),
    max_iter: int = typer.Option(
        MAX_ITERATIONS,
        "--max-iter",
        min=1,
        help="Maximum lead-analyst review cycles (>= 1)",
    ),
    threshold: int = typer.Option(
        QUALITY_THRESHOLD,
        "--threshold",
        min=1,
        max=10,
        help="Quality score (1-10) required for approval",
    ),
    stix_url: str = typer.Option(
        None,
        "--stix-url",
        help="Optional: URL of a STIX 2.x JSON bundle to include",
    ),
    stix_file: str = typer.Option(
        None,
        "--stix-file",
        help="Optional: Path to a local STIX 2.x JSON bundle file",
    ),
    hunt_refine_iters: int = typer.Option(
        2,
        "--hunt-refine-iters",
        min=0,
        help="Number of hunter-only refinement passes after the main QA loop (0 to skip)",
    ),
):
    """Run the CTI multi-agent threat intelligence pipeline."""
    # ── Input validation ───────────────────────────────────────────────────────
    valid_types = {"rss", "api", "stix"}
    bad = set(feeds) - valid_types
    if bad:
        typer.echo(f"ERROR: Unknown feed type(s): {', '.join(sorted(bad))}. Choose from: rss, api, stix", err=True)
        raise typer.Exit(code=1)

    if stix_url and stix_file:
        typer.echo("ERROR: --stix-url and --stix-file are mutually exclusive. Provide one or the other.", err=True)
        raise typer.Exit(code=1)

    # Pre-flight: check API key before printing the banner or making any network
    # calls, so users get an immediate actionable error on misconfiguration.
    if not ANTHROPIC_API_KEY:
        typer.echo(
            "ERROR: ANTHROPIC_API_KEY is not set. Copy .env.example to .env and add your key.",
            err=True,
        )
        raise typer.Exit(code=1)

    display = Display()
    display.banner()

    try:
        final_report = run_pipeline(
            feed_types=list(feeds),
            max_iterations=max_iter,
            quality_threshold=threshold,
            stix_url=stix_url,
            stix_file=stix_file,
            display=display,
            hunt_refinement_iters=hunt_refine_iters,
        )
    except ValueError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1)

    # ── Phase 3: Output ────────────────────────────────────────────────────────
    display.phase("PHASE 3: FINAL REPORT", "")
    display.final_report(final_report)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=2, default=str)
        display.console.print(f"[green]✓ Full report saved → {output}[/green]\n")


if __name__ == "__main__":
    app()
