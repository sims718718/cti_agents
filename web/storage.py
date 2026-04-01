"""Report storage — lightweight JSON file persistence.

Layout
------
reports/index.json          manifest (newest-first list of run summaries)
reports/{run_id}.json       full run record
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORTS_DIR = Path(__file__).parent.parent / "reports"
INDEX_FILE = REPORTS_DIR / "index.json"

_lock = threading.Lock()


def _ensure_dir() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _read_index() -> list[dict]:
    if not INDEX_FILE.exists():
        return []
    try:
        return json.loads(INDEX_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _write_index(index: list[dict]) -> None:
    INDEX_FILE.write_text(json.dumps(index, indent=2, default=str), encoding="utf-8")


def _run_path(run_id: str) -> Path:
    return REPORTS_DIR / f"{run_id}.json"


def _read_run(run_id: str) -> dict | None:
    p = _run_path(run_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_run(record: dict) -> None:
    _run_path(record["run_id"]).write_text(
        json.dumps(record, indent=2, default=str), encoding="utf-8"
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Public API ─────────────────────────────────────────────────────────────────

def create_run(
    run_id: str,
    name: str,
    feed_types: list[str],
    has_documents: bool = False,
    document_names: list[str] | None = None,
    time_range: str = "all",
) -> dict:
    """Create a new pending run record and register it in the index."""
    _ensure_dir()
    summary = {
        "run_id": run_id,
        "name": name,
        "status": "pending",
        "feed_types": feed_types,
        "time_range": time_range,
        "has_documents": has_documents,
        "document_names": document_names or [],
        "final_score": None,
        "total_iterations": None,
        "created_at": _now(),
        "completed_at": None,
        "error": None,
    }
    record = {**summary, "log": [], "report": None}

    with _lock:
        _write_run(record)
        index = _read_index()
        index.insert(0, summary)
        _write_index(index)

    return record


def update_run_status(run_id: str, status: str) -> None:
    with _lock:
        record = _read_run(run_id)
        if record is None:
            return
        record["status"] = status
        _write_run(record)
        index = _read_index()
        for entry in index:
            if entry["run_id"] == run_id:
                entry["status"] = status
                break
        _write_index(index)


def append_log(run_id: str, token: str) -> None:
    with _lock:
        record = _read_run(run_id)
        if record is None:
            return
        record.setdefault("log", []).append(token)
        _write_run(record)


def complete_run(run_id: str, report: dict) -> None:
    now = _now()
    final_score = report.get("final_score")
    total_iterations = report.get("total_iterations")

    with _lock:
        record = _read_run(run_id)
        if record is None:
            return
        record["status"] = "completed"
        record["completed_at"] = now
        record["final_score"] = final_score
        record["total_iterations"] = total_iterations
        record["report"] = report
        _write_run(record)

        index = _read_index()
        for entry in index:
            if entry["run_id"] == run_id:
                entry["status"] = "completed"
                entry["completed_at"] = now
                entry["final_score"] = final_score
                entry["total_iterations"] = total_iterations
                break
        _write_index(index)


def fail_run(run_id: str, error: str) -> None:
    now = _now()
    with _lock:
        record = _read_run(run_id)
        if record is None:
            return
        record["status"] = "failed"
        record["completed_at"] = now
        record["error"] = error
        _write_run(record)

        index = _read_index()
        for entry in index:
            if entry["run_id"] == run_id:
                entry["status"] = "failed"
                entry["completed_at"] = now
                entry["error"] = error
                break
        _write_index(index)


def get_run(run_id: str) -> dict | None:
    return _read_run(run_id)


def list_runs() -> list[dict]:
    _ensure_dir()
    return _read_index()


def delete_run(run_id: str) -> bool:
    with _lock:
        p = _run_path(run_id)
        existed = p.exists()
        if existed:
            p.unlink(missing_ok=True)
        index = _read_index()
        new_index = [e for e in index if e["run_id"] != run_id]
        _write_index(new_index)
    return existed
