# CTI Agents

A multi-agent Cyber Threat Intelligence (CTI) pipeline powered by Claude. It aggregates OSINT from RSS feeds, abuse.ch APIs, CISA KEV, and STIX/TAXII sources, then routes the data through three specialized Claude agents in an iterative quality-controlled loop to produce structured threat summaries and detection-ready hunt plans.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Phase 1 — Collection                                       │
│  IntelCollectorAgent (no LLM)                               │
│   ├─ RSS feeds (SANS, Krebs, Bleeping Computer, …)          │
│   ├─ abuse.ch APIs (Feodo, ThreatFox, URLhaus, Bazaar)      │
│   ├─ CISA Known Exploited Vulnerabilities                   │
│   ├─ STIX/TAXII (MITRE ATT&CK or custom bundle)            │
│   └─ Document uploads (PDF / Markdown / TXT)               │
└───────────────────────┬─────────────────────────────────────┘
                        │ raw_intel dict
┌───────────────────────▼─────────────────────────────────────┐
│  Phase 2 — Multi-Agent QA Loop                              │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  IntelSummarizerAgent  →  structured threat summary  │   │
│  │         ↓                                            │   │
│  │  ThreatHunterAgent     →  hunt hypotheses + queries  │   │
│  │         ↓                                            │   │
│  │  LeadAnalystAgent      →  score (1–10) + feedback    │   │
│  │         ↓ score < threshold?                         │   │
│  │  ←──── iterate with feedback (up to max_iter) ──────┘│   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Hunter-only refinement passes (hunt_refinement_iters)      │
└───────────────────────┬─────────────────────────────────────┘
                        │ final report
┌───────────────────────▼─────────────────────────────────────┐
│  Phase 3 — Output                                           │
│   ├─ Rich terminal display                                  │
│   └─ Optional JSON file export                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- An [Anthropic API key](https://console.anthropic.com/)

### Install

```bash
git clone https://github.com/your-username/cti-agents.git
cd cti-agents

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-...
```

### Run

```bash
python main.py
```

---

## Docker

```bash
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY

docker compose up --build -d
```

The web UI is available at **http://localhost:8001**.

To stop:

```bash
docker compose down
```

---

## Web UI

The FastAPI web interface (served at port 8001) provides:

- **Run pipeline** — configure feeds, thresholds, and document uploads through a browser
- **Run history** — browse past runs and download their JSON reports
- **Custom feeds** — add, edit, and remove RSS/API feed sources without editing code
- **Document upload** — submit PDF, Markdown, or TXT files as additional intel context

The API schema is available at `http://localhost:8001/docs`.

---

## CLI Reference

```
python main.py [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--feeds` / `-f` | `rss api` | Feed types to collect. Repeatable: `--feeds rss --feeds api --feeds stix` |
| `--output` / `-o` | _(none)_ | Write the final JSON report to this file path |
| `--max-iter` | `3` | Maximum lead-analyst review cycles (min 1) |
| `--threshold` | `7` | Quality score 1–10 required for approval |
| `--hunt-refine-iters` | `2` | Hunter-only refinement passes after the main QA loop (0 to skip) |
| `--stix-url` | _(none)_ | URL of a STIX 2.x JSON bundle to fetch and include |
| `--stix-file` | _(none)_ | Path to a local STIX 2.x JSON bundle file |

`--stix-url` and `--stix-file` are mutually exclusive.

### Examples

```bash
# RSS + API feeds (default)
python main.py

# Include MITRE ATT&CK via STIX/TAXII (slower — external network call)
python main.py --feeds rss api stix

# Save the final report
python main.py --output report.json

# Tighter quality bar, fewer iterations
python main.py --threshold 8 --max-iter 2

# Custom STIX bundle
python main.py --stix-url https://example.com/bundle.json
python main.py --stix-file /path/to/bundle.json

# Skip hunter refinement passes
python main.py --hunt-refine-iters 0
```

---

## Feed Sources

| Type | Source | Data |
|---|---|---|
| RSS | SANS Internet Storm Center | Daily threat advisories |
| RSS | Krebs on Security | In-depth security journalism |
| RSS | Bleeping Computer | Malware/breach news |
| RSS | The Hacker News | Vulnerability and threat news |
| RSS | Recorded Future | Threat intelligence blog |
| API | Feodo Tracker (abuse.ch) | Botnet C2 IP block-list |
| API | ThreatFox (abuse.ch) | Recent IOCs |
| API | URLhaus (abuse.ch) | Recent malicious URLs |
| API | MalwareBazaar (abuse.ch) | Recent malware samples |
| API | CISA KEV | Known Exploited Vulnerabilities catalog |
| STIX | MITRE ATT&CK TAXII 2.1 | ATT&CK techniques and groups |

All abuse.ch and CISA feeds are public and require no API key.

---

## Document Uploads

You can supply your own threat reports, incident summaries, or research notes as additional context. Supported formats:

- **PDF** — requires the optional `pypdf` package (`pip install pypdf`)
- **Markdown** (`.md`)
- **Plain text** (`.txt`)

Each document is capped at 8,000 characters. Via the CLI or `run_pipeline()`:

```python
from pipeline import run_pipeline

report = run_pipeline(
    feed_types=["rss", "api"],
    document_uploads=[
        {
            "filename": "incident.pdf",
            "content_type": "application/pdf",
            "bytes": open("incident.pdf", "rb").read(),
        }
    ],
)
```

Via the web UI, use the **Upload Documents** section on the run configuration page.

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Your Claude API key from [console.anthropic.com](https://console.anthropic.com) |
| `ANTHROPIC_MODEL` | No | Override the Claude model (default: `claude-sonnet-4-6`) |
| `OTX_API_KEY` | No | AlienVault OTX key (reserved for future use) |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal key (reserved for future use) |
| `STIX_TIMEOUT` | No | STIX/TAXII request timeout in seconds (default: `20`) |

### Tuning (`config.py`)

`LIMITS` controls how many items each source contributes to avoid overwhelming the LLM context window:

```python
LIMITS = {
    "rss_per_feed":    5,   # articles per RSS feed
    "feodo_ips":      25,
    "threatfox_iocs": 15,
    "urlhaus_urls":   15,
    "malware_samples":10,
    "cisa_kevs":      20,
    "stix_objects":   20,
}
```

`MAX_ITERATIONS` and `QUALITY_THRESHOLD` set the defaults for the QA loop (overridable via CLI flags).

---

## Adding Custom Feeds

### RSS

1. Add an entry to `RSS_FEEDS` in `config.py`:
   ```python
   {"id": "myorg", "name": "My Org Blog", "url": "https://blog.myorg.com/feed"},
   ```

2. No code changes needed — `IntelCollectorAgent` picks up all `RSS_FEEDS` automatically.

### REST API

1. Add a collector function in `feeds/api_feeds.py`.
2. Add the endpoint URL and limit to `config.py`.
3. Call the new function from `IntelCollectorAgent.run()` in `agents/intel_collector.py` and merge results into `raw_intel`.

### Custom feeds via web UI

The web UI includes a **Custom Feeds** manager — you can add RSS and API sources through the browser without editing any files.

---

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Run a specific test file:

```bash
pytest tests/unit/test_base_agent.py -v
```

Run only integration tests:

```bash
pytest tests/integration/ -v
```

---

## Project Structure

```
cti-agents/
├── main.py                   # Typer CLI entry point
├── pipeline.py               # Shared pipeline orchestration (CLI + web)
├── config.py                 # Feed URLs, model, limits, thresholds
├── requirements.txt          # Runtime dependencies
├── requirements-dev.txt      # Test/dev dependencies
├── Dockerfile
├── docker-compose.yml
├── .env.example              # Template — copy to .env and fill in your key
│
├── agents/
│   ├── base_agent.py         # Shared _chat(), _parse_json(), _truncate()
│   ├── intel_collector.py    # Phase 1: data collection (no LLM)
│   ├── intel_summarizer.py   # Phase 2a: Claude threat summary
│   ├── threat_hunter.py      # Phase 2b: Claude hunt plan
│   └── lead_analyst.py       # Phase 2c: Claude QA review + loop orchestration
│
├── feeds/
│   ├── api_feeds.py          # abuse.ch / CISA REST collectors
│   ├── rss_feed.py           # feedparser-based RSS collector
│   ├── stix_feed.py          # STIX/TAXII 2.1 connector
│   └── document_feed.py      # PDF / Markdown / TXT extractor
│
├── utils/
│   └── display.py            # Rich terminal UI
│
├── web/
│   ├── app.py                # FastAPI routes
│   ├── feed_store.py         # Custom feed persistence
│   ├── storage.py            # Run history storage
│   └── static/               # Web UI static files
│
└── tests/
    ├── conftest.py
    ├── unit/                 # Per-module unit tests
    └── integration/          # End-to-end pipeline tests
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `anthropic` | Claude API client |
| `feedparser` | RSS/Atom feed parsing |
| `requests` | HTTP client for API feeds |
| `stix2` | STIX 2.x object parsing |
| `taxii2-client` | TAXII 2.1 server connectivity |
| `python-dotenv` | `.env` file loading |
| `rich` | Terminal formatting |
| `typer` | CLI framework |
| `fastapi` + `uvicorn` | Web API server |
| `python-multipart` | File upload handling |
| `pypdf` _(optional)_ | PDF text extraction |

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss the proposed change.
