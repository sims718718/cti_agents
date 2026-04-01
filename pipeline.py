"""Reusable pipeline function shared by the CLI and the web backend."""
from __future__ import annotations

from typing import Callable

import anthropic
from dotenv import load_dotenv

load_dotenv()

from config import (
    ANTHROPIC_API_KEY,
    FEEDS,
    LIMITS,
    MAX_ITERATIONS,
    MODEL,
    QUALITY_THRESHOLD,
)
from agents.intel_collector import IntelCollectorAgent
from agents.intel_summarizer import IntelSummarizerAgent
from agents.threat_hunter import ThreatHunterAgent
from agents.lead_analyst import LeadAnalystAgent


def run_pipeline(
    feed_types: list[str] | None = None,
    max_iterations: int = MAX_ITERATIONS,
    quality_threshold: int = QUALITY_THRESHOLD,
    stix_url: str | None = None,
    stix_file: str | None = None,
    document_uploads: list[dict] | None = None,
    progress_callback: Callable[[str], None] | None = None,
    display=None,
    selected_rss_feeds: list[dict] | None = None,
    selected_api_feeds: list[dict] | None = None,
    time_from=None,
    time_to=None,
    hunt_refinement_iters: int = 2,
) -> dict:
    """Run the full CTI pipeline and return the final report dict.

    Args:
        feed_types: Feed categories to use: ["rss", "api", "stix"]. Defaults to ["rss", "api"].
        max_iterations: Maximum lead-analyst review cycles.
        quality_threshold: Score (1-10) required for approval.
        stix_url: Optional URL of a STIX 2.x JSON bundle.
        stix_file: Optional path to a local STIX 2.x JSON bundle file.
        document_uploads: List of dicts with keys: filename, content_type, bytes.
        progress_callback: Called with string progress tokens as the pipeline runs.
        display: Optional rich Display instance (CLI mode only).

    Returns:
        Final report dict.

    Raises:
        ValueError: If ANTHROPIC_API_KEY is not set.
    """
    if not ANTHROPIC_API_KEY:
        raise ValueError(
            "ANTHROPIC_API_KEY is not set. Copy .env.example to .env and add your key."
        )

    if feed_types is None:
        feed_types = ["rss", "api"]

    def _cb(token: str) -> None:
        if progress_callback:
            progress_callback(token)

    # ── Build active feed config ───────────────────────────────────────────────
    active_feeds = dict(FEEDS)
    if stix_url:
        active_feeds["stix"]["user_bundle"] = {
            "type": "url",
            "url": stix_url,
            "description": "User-supplied STIX bundle",
        }
        if "stix" not in feed_types:
            feed_types = list(feed_types) + ["stix"]

    if stix_file:
        active_feeds["stix"]["user_file"] = {
            "type": "file",
            "path": stix_file,
            "description": "User-supplied STIX file",
        }
        if "stix" not in feed_types:
            feed_types = list(feed_types) + ["stix"]

    # ── Init agents ────────────────────────────────────────────────────────────
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    collector  = IntelCollectorAgent()
    summarizer = IntelSummarizerAgent(client, MODEL)
    hunter     = ThreatHunterAgent(client, MODEL)
    lead       = LeadAnalystAgent(client, MODEL)

    # ── Phase 1: Collection ────────────────────────────────────────────────────
    _cb("phase:collection")
    if display:
        display.phase("PHASE 1: INTELLIGENCE COLLECTION", "IntelCollectorAgent")
    raw_intel = collector.run(
        active_feeds,
        feed_types=list(feed_types),
        limits=LIMITS,
        document_uploads=document_uploads or [],
        selected_rss_feeds=selected_rss_feeds,
        selected_api_feeds=selected_api_feeds,
        time_from=time_from,
        time_to=time_to,
    )

    if display:
        display.collection_summary(raw_intel)

    total_items = sum(
        len(raw_intel.get(k, []))
        for k in ["news_articles", "ip_indicators", "iocs", "url_indicators",
                  "malware_samples", "vulnerabilities", "stix_objects", "document_intel"]
    )
    _cb(f"collected:{total_items}")

    # ── Phase 2: Analysis loop ─────────────────────────────────────────────────
    _cb("phase:analysis")
    if display:
        display.phase("PHASE 2: MULTI-AGENT ANALYSIS & REVIEW LOOP", "LeadAnalystAgent")
    final_report = lead.orchestrate(
        raw_intel=raw_intel,
        summarizer=summarizer,
        hunter=hunter,
        display=display,
        max_iterations=max_iterations,
        quality_threshold=quality_threshold,
        progress_callback=progress_callback,
        hunt_refinement_iters=hunt_refinement_iters,
    )

    _cb("phase:complete")
    return final_report
