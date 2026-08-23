"""Typed progress-event vocabulary.

`pipeline.py` and `agents/lead_analyst.py` report progress through a
`progress_callback: Callable[[dict], None]`. Every event passed to it is a
plain dict shaped `{"event": "<name>", ...payload}`, built by exactly one of
the functions below — never assembled by hand at the call site. That's what
keeps the vocabulary (event names, payload field names) from drifting between
the emitters here, `web/storage.py`'s persistence, and the renderer in
`web/static/app.js`.

Consumers (CLI aside — `utils.display.Display` is driven directly, not
through events) should switch on the `"event"` key, not reconstruct meaning
from string parsing.
"""
from __future__ import annotations

from typing import Any

# ── Collection phase (pipeline.py) ──────────────────────────────────────────

def phase_collection() -> dict:
    return {"event": "phase_collection"}


def collected(total_items: int) -> dict:
    return {"event": "collected", "total_items": total_items}


def phase_analysis() -> dict:
    return {"event": "phase_analysis"}


def phase_complete() -> dict:
    return {"event": "phase_complete"}


# ── Per-agent pass (agents/lead_analyst.py) ─────────────────────────────────

def agent_started(agent: str) -> dict:
    """`agent` is a short id: "summarizer" | "hunter" | "lead_analyst"."""
    return {"event": "agent_started", "agent": agent}


def parse_error(agent: str) -> dict:
    """The named agent's response could not be parsed as JSON; a fallback
    was used. `agent` is the same short id as `agent_started`."""
    return {"event": "parse_error", "agent": agent}


def summarizer_done(n_threats: int) -> dict:
    return {"event": "summarizer_done", "n_threats": n_threats}


def hunter_done(n_hypotheses: int) -> dict:
    return {"event": "hunter_done", "n_hypotheses": n_hypotheses}


def review_done(score: Any) -> dict:
    return {"event": "review_done", "score": score}


# ── Main QA loop (agents/lead_analyst.py::orchestrate) ──────────────────────

def iteration(n: int) -> dict:
    return {"event": "iteration", "n": n}


def approved() -> dict:
    return {"event": "approved"}


def iterating() -> dict:
    return {"event": "iterating"}


def max_iterations_reached() -> dict:
    return {"event": "max_iterations_reached"}


# ── Hunter-only refinement loop (agents/lead_analyst.py::orchestrate) ──────

def hunt_refinement(n: int) -> dict:
    return {"event": "hunt_refinement", "n": n}


def hunt_review_done(score: Any) -> dict:
    return {"event": "hunt_review_done", "score": score}


def hunt_approved() -> dict:
    return {"event": "hunt_approved"}


def hunt_iterating() -> dict:
    return {"event": "hunt_iterating"}


def hunt_max_iterations_reached() -> dict:
    return {"event": "hunt_max_iterations_reached"}


# ── Backward compatibility ───────────────────────────────────────────────────

# Runs created before this module existed stored plain strings ("agent:X",
# not the short id used by agent_started/parse_error today).
_LEGACY_AGENT_IDS = {
    "IntelSummarizerAgent": "summarizer",
    "ThreatHunterAgent": "hunter",
    "LeadAnalystAgent": "lead_analyst",
}


def normalize_log_entry(entry: Any) -> dict:
    """Convert one stored log entry into the current event shape.

    Runs persisted before this module existed have `log` entries that are
    plain strings (e.g. `"summarizer_done:3_threats"`); every entry logged
    since is already a dict built by the functions above. Route every stored
    entry through this before rendering so callers never branch on shape
    themselves — this is the only place that knows the legacy string format.

    Does not touch anything on disk: `web/storage.py` calls this when
    *serving* a run's log, not when writing one, so old runs' JSON files are
    never rewritten.
    """
    if isinstance(entry, dict):
        return entry
    if not isinstance(entry, str):
        return {"event": "unknown", "raw": str(entry)}

    token = entry
    exact = {
        "approved": approved,
        "iterating": iterating,
        "max_iterations_reached": max_iterations_reached,
        "hunt_approved": hunt_approved,
        "hunt_iterating": hunt_iterating,
        "hunt_max_iterations_reached": hunt_max_iterations_reached,
    }
    if token in exact:
        return exact[token]()

    prefix, _, rest = token.partition(":")

    if prefix == "phase":
        return {
            "collection": phase_collection,
            "analysis": phase_analysis,
            "complete": phase_complete,
        }.get(rest, lambda: {"event": "unknown", "raw": token})()
    if prefix == "collected":
        return collected(_as_int(rest))
    if prefix == "iteration":
        return iteration(_as_int(rest))
    if prefix == "agent":
        return agent_started(_LEGACY_AGENT_IDS.get(rest, rest))
    if prefix == "warning":
        # "warning:summarizer_parse_error" / "warning:hunter_parse_error"
        return parse_error(rest.removesuffix("_parse_error"))
    if prefix == "summarizer_done":
        # rest looks like "3_threats"
        return summarizer_done(_as_int(rest.split("_", 1)[0]))
    if prefix == "hunter_done":
        return hunter_done(_as_int(rest.split("_", 1)[0]))
    if prefix == "review_done":
        # rest looks like "score=7"
        return review_done(_as_int(rest.partition("=")[2]))
    if prefix == "hunt_refinement":
        return hunt_refinement(_as_int(rest))
    if prefix == "hunt_review_done":
        return hunt_review_done(_as_int(rest.partition("=")[2]))

    return {"event": "unknown", "raw": token}


def _as_int(s: str) -> int | str:
    try:
        return int(s)
    except ValueError:
        return s
