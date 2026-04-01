# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CTI Agents is a multi-agent Cyber Threat Intelligence (CTI) pipeline. It collects raw OSINT from RSS feeds, abuse.ch APIs (Feodo, ThreatFox, URLhaus, MalwareBazaar), CISA KEV, and STIX/TAXII sources, then passes the data through three Claude-powered agents (Summarizer → Hunter → Lead Analyst) in an iterative quality-controlled loop.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY

# Run the pipeline (default: rss + api feeds)
python main.py

# Common options
python main.py --feeds rss api stix          # Include STIX/TAXII (slow)
python main.py --output report.json          # Save final report
python main.py --max-iter 2 --threshold 8    # Tune QA loop
python main.py --hunt-refine-iters 3         # Hunter-only refinement passes after main QA loop (default: 2)
python main.py --stix-url https://...        # Custom STIX bundle URL
python main.py --stix-file /path/to/bundle.json
```

There is no test suite. There is no build step—this is a pure Python project.

## Architecture

### Pipeline Phases

**Phase 1 — Collection** (`agents/intel_collector.py`)
`IntelCollectorAgent` is the only non-LLM agent. It pulls raw data from all configured sources in `config.py` and returns a single `raw_intel` dict with keys: `news_articles`, `ip_indicators`, `iocs`, `url_indicators`, `malware_samples`, `vulnerabilities`, `stix_objects`, `document_intel`, `errors`.

**Phase 2 — Multi-Agent QA Loop** (orchestrated by `agents/lead_analyst.py`, wired up by `pipeline.py`)
`LeadAnalystAgent.orchestrate()` runs two sub-phases:

*Sub-phase A — Main QA loop* (up to `max_iterations`):
1. `IntelSummarizerAgent.run(raw_intel, feedback)` → structured `intel_summary` JSON
2. `ThreatHunterAgent.run(intel_summary, feedback)` → `hunt_plan` JSON with hypotheses and detection queries
3. `LeadAnalystAgent.review(intel_summary, hunt_plan)` → score (1–10) + per-agent feedback

If `score < threshold`, feedback is passed back to step 1 and the loop repeats. If approved or max iterations reached, the loop exits.

*Sub-phase B — Hunter-only refinement* (up to `hunt_refinement_iters`, default 2):
After the main loop, `LeadAnalystAgent._review_hunt_plan()` scores only the hunt plan and feeds specific hunter feedback to `ThreatHunterAgent` for additional passes without re-running the summarizer.

**Phase 3 — Output** (`utils/display.py`)
Rich terminal display + optional JSON file export.

**`pipeline.py`** is the shared coordination layer called by both `main.py` (CLI) and any web backend. It instantiates agents, wires document uploads, and runs both phases.

### Base Agent (`agents/base_agent.py`)

All LLM agents inherit `BaseAgent`, which provides:
- `_chat(messages)` — Claude API wrapper (uses model from `config.MODEL`)
- `_parse_json(text)` — extracts JSON from responses; tries raw JSON, markdown fences, then outermost-brace regex; returns `{}` on failure so the pipeline never crashes
- `_truncate(data, max_chars)` — serializes to JSON and trims at `max_chars` to stay within context limits (60k for raw intel, 40k for combined review)

### Configuration (`config.py`)

Central place for: feed URLs, per-source item limits (prevent token overflow), Claude model name, default quality parameters. Change `config.MODEL` to switch Claude model versions. Change `config.LIMITS` to tune how much data each feed contributes.

### Key Data Schemas

Each agent consumes the previous agent's structured JSON output. The schemas are defined by the system prompts inside each agent file—`IntelSummarizerAgent` produces `threat_landscape`, `key_iocs`, `recommended_priorities`; `ThreatHunterAgent` produces `hunt_plan`, `hypotheses` (each with `hunt_queries` in KQL/SPL/Sigma/YARA), `ioc_hunt_list`.

## Adding New Feed Sources

1. Add a collector method to `feeds/api_feeds.py` (REST) or `feeds/rss_feed.py` (RSS)
2. Add the source URL and item limit to `config.py`
3. Call the new method from `IntelCollectorAgent.run()` and merge into `raw_intel`

## Document Upload Support

`feeds/document_feed.py` extracts text from PDF, Markdown, and TXT files passed as `document_uploads` to `run_pipeline()`. Each file is capped at 8,000 characters and placed in `raw_intel["document_intel"]`. PDF extraction requires the optional `pypdf` package; without it, PDFs return a placeholder message instead of crashing.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Claude API key |
| `OTX_API_KEY` | No | AlienVault OTX (currently unused in feeds; reserved) |

## Dependencies

`anthropic`, `feedparser`, `requests`, `stix2`, `taxii2-client`, `python-dotenv`, `rich`, `typer`. Optional: `pypdf` for PDF document uploads. TAXII support is optional—missing `taxii2-client` is handled gracefully.
