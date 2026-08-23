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

# Web UI (FastAPI, served at :8000; docker-compose maps it to :8001)
pip install -r requirements-dev.txt   # adds pytest, pytest-mock, responses
uvicorn web.app:app --reload
docker compose up --build -d          # or via Docker

# Tests
pytest tests/ -v
pytest tests/unit/test_base_agent.py -v      # single file
pytest tests/unit/test_base_agent.py::test_name -v  # single test
pytest tests/integration/ -v                 # integration only
```

There is no build step—this is a pure Python project.

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

### Web UI (`web/app.py`, `web/storage.py`, `web/feed_store.py`)

FastAPI wraps the same `pipeline.run_pipeline()` used by the CLI. `POST /api/runs` generates a `run_id`, then hands the pipeline call to a `ThreadPoolExecutor` (via `BackgroundTasks`) so the request returns immediately (202) while the run executes in the background; `GET /api/runs/{id}/status` polls `web/storage.py` for progress. `web/storage.py` persists one JSON file per run (list/get/append-log) under the run's directory. `web/feed_store.py` persists user-added RSS/API feeds (`/api/feeds/*`) separately from the built-in `config.py` feeds — built-ins can't be deleted through the API. Static frontend (`web/static/`) is vanilla HTML/CSS/JS, no build step.

### Progress events (`utils/events.py`)

`pipeline.py` and `agents/lead_analyst.py` report progress through `progress_callback: Callable[[dict], None]`, used only by the web backend (`web/app.py`) — the CLI passes a `Display` instance instead and never touches this callback. Every event is a plain dict `{"event": "<name>", ...payload}` built by one of `utils/events.py`'s builder functions (e.g. `events.summarizer_done(n_threats)`); never construct one by hand at the call site. `web/storage.py::append_log()` persists whatever it's given as-is. `web/storage.py::get_run()` runs each stored `log` entry through `events.normalize_log_entry()` before returning it, so runs recorded before this module existed (plain string tokens like `"summarizer_done:3_threats"`) render the same as new ones — the on-disk JSON files themselves are never rewritten. `web/static/app.js`'s `fmtEvent()` switches on `event["event"]`, no string parsing.

### Base Agent (`agents/base_agent.py`)

All LLM agents inherit `BaseAgent`, which provides:
- `_chat(system, messages, max_tokens)` — Claude API wrapper (uses model from `config.MODEL`)
- `_parse_json(text)` — extracts JSON from responses; tries raw JSON, markdown fences, then a depth-balanced brace/bracket scan; raises `ValueError` if nothing parses
- `_call_and_parse(system, messages, fallback, max_tokens)` — the shared call → parse → fallback pattern used by every LLM agent's `run()`/`review()`. On success returns the parsed dict with `parse_error: False` set; on a parse failure returns a copy of `fallback` augmented with `parse_error: True` and `raw_response` (first 2000 chars). Callers (e.g. `LeadAnalystAgent.orchestrate()`) should check the `parse_error` flag rather than sniffing content fields for a magic-string prefix.
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
| `ANTHROPIC_MODEL` | No | Overrides `config.MODEL` (default `claude-sonnet-4-6`) |
| `OTX_API_KEY` | No | AlienVault OTX (currently unused in feeds; reserved) |
| `VIRUSTOTAL_API_KEY` | No | Reserved for future use |
| `STIX_TIMEOUT` | No | STIX/TAXII request timeout in seconds (default 20) |

## Dependencies

`anthropic`, `feedparser`, `requests`, `stix2`, `taxii2-client`, `python-dotenv`, `rich`, `typer`, `fastapi`, `uvicorn`, `python-multipart`. Optional: `pypdf` for PDF document uploads. TAXII support is optional—missing `taxii2-client` is handled gracefully. Test-only (`requirements-dev.txt`): `pytest`, `pytest-mock`, `responses`.
