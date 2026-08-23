"""Unit tests for web/storage.py's run-log normalization (see utils/events.py)."""
from __future__ import annotations

import json

import pytest

from web import storage


@pytest.fixture(autouse=True)
def _isolate_reports_dir(tmp_path, monkeypatch):
    """Point storage at a scratch directory so tests never touch the real
    reports/ folder (which holds actual historical run data)."""
    monkeypatch.setattr(storage, "REPORTS_DIR", tmp_path)
    monkeypatch.setattr(storage, "INDEX_FILE", tmp_path / "index.json")
    yield


class TestGetRunNormalizesLog:
    def test_new_style_entries_pass_through(self):
        storage.create_run("run-1", "Test Run", feed_types=["rss"])
        storage.append_log("run-1", {"event": "phase_collection"})

        record = storage.get_run("run-1")

        assert record["log"] == [{"event": "phase_collection"}]

    def test_legacy_string_entries_are_normalized_on_read(self):
        storage.create_run("run-2", "Legacy Run", feed_types=["rss"])
        # Simulate a run persisted before the typed-event system by writing
        # raw legacy tokens directly, bypassing append_log's dict-only API.
        record = storage._read_run("run-2")
        record["log"] = ["phase:collection", "collected:28", "agent:IntelSummarizerAgent"]
        storage._write_run(record)

        result = storage.get_run("run-2")

        assert result["log"] == [
            {"event": "phase_collection"},
            {"event": "collected", "total_items": 28},
            {"event": "agent_started", "agent": "summarizer"},
        ]

    def test_normalization_does_not_rewrite_the_file_on_disk(self):
        storage.create_run("run-3", "Legacy Run", feed_types=["rss"])
        record = storage._read_run("run-3")
        record["log"] = ["phase:collection"]
        storage._write_run(record)

        storage.get_run("run-3")  # triggers normalization, should not persist it

        raw = json.loads(storage._run_path("run-3").read_text(encoding="utf-8"))
        assert raw["log"] == ["phase:collection"]

    def test_missing_run_returns_none(self):
        assert storage.get_run("does-not-exist") is None
