"""Unit tests for utils/events.py — the typed progress-event vocabulary."""
from __future__ import annotations

from utils import events


class TestBuilders:
    def test_phase_events(self):
        assert events.phase_collection() == {"event": "phase_collection"}
        assert events.phase_analysis() == {"event": "phase_analysis"}
        assert events.phase_complete() == {"event": "phase_complete"}

    def test_collected(self):
        assert events.collected(28) == {"event": "collected", "total_items": 28}

    def test_agent_started(self):
        assert events.agent_started("summarizer") == {"event": "agent_started", "agent": "summarizer"}

    def test_parse_error(self):
        assert events.parse_error("hunter") == {"event": "parse_error", "agent": "hunter"}

    def test_summarizer_done(self):
        assert events.summarizer_done(5) == {"event": "summarizer_done", "n_threats": 5}

    def test_hunter_done(self):
        assert events.hunter_done(3) == {"event": "hunter_done", "n_hypotheses": 3}

    def test_review_done(self):
        assert events.review_done(8.7) == {"event": "review_done", "score": 8.7}

    def test_iteration(self):
        assert events.iteration(2) == {"event": "iteration", "n": 2}

    def test_loop_control_events(self):
        assert events.approved() == {"event": "approved"}
        assert events.iterating() == {"event": "iterating"}
        assert events.max_iterations_reached() == {"event": "max_iterations_reached"}

    def test_hunt_refinement_events(self):
        assert events.hunt_refinement(1) == {"event": "hunt_refinement", "n": 1}
        assert events.hunt_review_done(9) == {"event": "hunt_review_done", "score": 9}
        assert events.hunt_approved() == {"event": "hunt_approved"}
        assert events.hunt_iterating() == {"event": "hunt_iterating"}
        assert events.hunt_max_iterations_reached() == {"event": "hunt_max_iterations_reached"}


class TestNormalizeLogEntry:
    def test_dict_passes_through_unchanged(self):
        entry = {"event": "summarizer_done", "n_threats": 5}
        assert events.normalize_log_entry(entry) is entry

    def test_non_string_non_dict_becomes_unknown(self):
        assert events.normalize_log_entry(None) == {"event": "unknown", "raw": "None"}

    def test_exact_match_tokens(self):
        assert events.normalize_log_entry("approved") == {"event": "approved"}
        assert events.normalize_log_entry("hunt_approved") == {"event": "hunt_approved"}
        assert events.normalize_log_entry("max_iterations_reached") == {"event": "max_iterations_reached"}

    def test_phase_tokens(self):
        assert events.normalize_log_entry("phase:collection") == {"event": "phase_collection"}
        assert events.normalize_log_entry("phase:analysis") == {"event": "phase_analysis"}
        assert events.normalize_log_entry("phase:complete") == {"event": "phase_complete"}

    def test_collected_token(self):
        assert events.normalize_log_entry("collected:28") == {"event": "collected", "total_items": 28}

    def test_iteration_token(self):
        assert events.normalize_log_entry("iteration:2") == {"event": "iteration", "n": 2}

    def test_agent_token_maps_class_name_to_short_id(self):
        assert events.normalize_log_entry("agent:IntelSummarizerAgent") == {
            "event": "agent_started", "agent": "summarizer",
        }
        assert events.normalize_log_entry("agent:ThreatHunterAgent") == {
            "event": "agent_started", "agent": "hunter",
        }
        assert events.normalize_log_entry("agent:LeadAnalystAgent") == {
            "event": "agent_started", "agent": "lead_analyst",
        }

    def test_warning_token_becomes_parse_error(self):
        assert events.normalize_log_entry("warning:summarizer_parse_error") == {
            "event": "parse_error", "agent": "summarizer",
        }
        assert events.normalize_log_entry("warning:hunter_parse_error") == {
            "event": "parse_error", "agent": "hunter",
        }

    def test_summarizer_and_hunter_done_tokens(self):
        assert events.normalize_log_entry("summarizer_done:5_threats") == {
            "event": "summarizer_done", "n_threats": 5,
        }
        assert events.normalize_log_entry("hunter_done:3_hypotheses") == {
            "event": "hunter_done", "n_hypotheses": 3,
        }

    def test_review_done_token(self):
        assert events.normalize_log_entry("review_done:score=8") == {
            "event": "review_done", "score": 8,
        }

    def test_review_done_token_with_float_score(self):
        # Real historical runs recorded non-integer scores (e.g. "8.7").
        assert events.normalize_log_entry("review_done:score=8.7") == {
            "event": "review_done", "score": "8.7",
        }

    def test_hunt_refinement_tokens(self):
        assert events.normalize_log_entry("hunt_refinement:1") == {"event": "hunt_refinement", "n": 1}
        assert events.normalize_log_entry("hunt_review_done:score=9") == {
            "event": "hunt_review_done", "score": 9,
        }

    def test_unrecognized_token_is_surfaced_not_dropped(self):
        assert events.normalize_log_entry("some_future_token") == {
            "event": "unknown", "raw": "some_future_token",
        }

    def test_real_historical_run_log_normalizes_without_error(self):
        # Verbatim log from reports/15dc1f90-48bf-4b72-ba6c-86c6211e5a26.json,
        # predating this module.
        legacy_log = [
            "phase:collection", "collected:28", "phase:analysis", "iteration:1",
            "agent:IntelSummarizerAgent", "summarizer_done:5_threats",
            "agent:ThreatHunterAgent", "hunter_done:3_hypotheses",
            "agent:LeadAnalystAgent", "review_done:score=5", "iterating",
            "iteration:2", "agent:IntelSummarizerAgent", "summarizer_done:5_threats",
            "agent:ThreatHunterAgent", "hunter_done:3_hypotheses",
            "agent:LeadAnalystAgent", "review_done:score=8.7", "approved",
            "hunt_refinement:1", "hunt_review_done:score=9", "hunt_approved",
            "phase:complete",
        ]
        normalized = [events.normalize_log_entry(e) for e in legacy_log]
        assert all(isinstance(e, dict) and "event" in e for e in normalized)
        assert normalized[0] == {"event": "phase_collection"}
        assert normalized[-1] == {"event": "phase_complete"}
        assert all(e["event"] != "unknown" for e in normalized)
