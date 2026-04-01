"""Integration tests for pipeline.run_pipeline()."""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_llm_response(text: str):
    """Build a mock anthropic response object."""
    response = MagicMock()
    response.content = [MagicMock(text=text)]
    return response


# ── Pipeline tests ─────────────────────────────────────────────────────────────

class TestRunPipeline:
    """Test run_pipeline() with all external calls mocked."""

    def _run(self, mocker, summary_json, hunt_json, review_json, **kwargs):
        """Helper: mock all LLM + feed calls and run the pipeline.

        hunt_refinement_iters defaults to 0 to keep mock response counts simple.
        Pass explicitly to test refinement behaviour.
        """
        kwargs.setdefault("hunt_refinement_iters", 0)

        # Mock feed collection to return minimal data
        mocker.patch("agents.intel_collector.fetch_rss_feeds", return_value=[])
        mocker.patch("agents.intel_collector.fetch_feodo_tracker", return_value=[])
        mocker.patch("agents.intel_collector.fetch_threatfox", return_value=[])
        mocker.patch("agents.intel_collector.fetch_urlhaus", return_value=[])
        mocker.patch("agents.intel_collector.fetch_malware_bazaar", return_value=[])
        mocker.patch("agents.intel_collector.fetch_cisa_kev", return_value=[])

        # Mock LLM responses: summarizer → summary, hunter → hunt, analyst → review
        import anthropic
        mock_client = MagicMock(spec=anthropic.Anthropic)
        mock_client.messages.create.side_effect = [
            _make_llm_response(summary_json),
            _make_llm_response(hunt_json),
            _make_llm_response(review_json),
        ]
        mocker.patch("pipeline.anthropic.Anthropic", return_value=mock_client)
        mocker.patch("pipeline.ANTHROPIC_API_KEY", "test-key")

        import importlib, pipeline
        importlib.reload(pipeline)  # pick up patched ANTHROPIC_API_KEY
        mocker.patch("pipeline.ANTHROPIC_API_KEY", "test-key")

        from pipeline import run_pipeline
        kwargs.setdefault("max_iterations", 1)
        return run_pipeline(feed_types=["rss", "api"], **kwargs)

    def test_missing_api_key_raises(self, mocker):
        mocker.patch("pipeline.ANTHROPIC_API_KEY", "")
        from pipeline import run_pipeline
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            run_pipeline()

    def test_approved_on_first_iteration(self, mocker, sample_intel_summary, sample_hunt_plan, sample_review_approved):
        import json
        report = self._run(
            mocker,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
            max_iterations=3,
        )
        assert report["total_iterations"] == 1
        assert report["status"] == "approved"

    def test_report_has_expected_keys(self, mocker, sample_intel_summary, sample_hunt_plan, sample_review_approved):
        import json
        report = self._run(
            mocker,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
        )
        for key in ("status", "total_iterations", "final_score", "intel_summary",
                    "hunt_plan", "lead_analyst_review", "iteration_history", "collection_metadata"):
            assert key in report, f"Missing key: {key}"

    def test_stix_url_adds_stix_to_feed_types(self, mocker, sample_intel_summary, sample_hunt_plan, sample_review_approved):
        import json
        mocker.patch("agents.intel_collector.fetch_from_url", return_value=[])
        report = self._run(
            mocker,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
            stix_url="https://example.com/bundle.json",
        )
        assert "stix" in report["collection_metadata"]["feed_types"]

    def test_stix_file_adds_stix_to_feed_types(self, mocker, sample_intel_summary, sample_hunt_plan, sample_review_approved, tmp_path):
        import json
        stix_file = tmp_path / "bundle.json"
        stix_file.write_text('{"objects": []}', encoding="utf-8")
        mocker.patch("agents.intel_collector.fetch_from_file", return_value=[])
        report = self._run(
            mocker,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
            stix_file=str(stix_file),
        )
        assert "stix" in report["collection_metadata"]["feed_types"]

    def test_max_iterations_reached_status(self, mocker, sample_intel_summary, sample_hunt_plan):
        import json
        review_not_approved = {
            "overall_score": 5,
            "approved": False,
            "scores": {},
            "strengths": [],
            "critical_gaps": ["Incomplete"],
            "summarizer_feedback": "Improve coverage",
            "hunter_feedback": "Add more queries",
            "reviewer_notes": "Needs work",
        }
        # Mock enough LLM calls for 2 iterations (summarizer + hunter + reviewer each time)
        import anthropic
        mock_client = MagicMock(spec=anthropic.Anthropic)
        mock_client.messages.create.side_effect = [
            _make_llm_response(json.dumps(sample_intel_summary)),
            _make_llm_response(json.dumps(sample_hunt_plan)),
            _make_llm_response(json.dumps(review_not_approved)),
            _make_llm_response(json.dumps(sample_intel_summary)),
            _make_llm_response(json.dumps(sample_hunt_plan)),
            _make_llm_response(json.dumps(review_not_approved)),
            # hunt refinement passes
            _make_llm_response(json.dumps(review_not_approved)),
            _make_llm_response(json.dumps(sample_hunt_plan)),
            _make_llm_response(json.dumps(review_not_approved)),
        ]
        mocker.patch("agents.intel_collector.fetch_rss_feeds", return_value=[])
        mocker.patch("agents.intel_collector.fetch_feodo_tracker", return_value=[])
        mocker.patch("agents.intel_collector.fetch_threatfox", return_value=[])
        mocker.patch("agents.intel_collector.fetch_urlhaus", return_value=[])
        mocker.patch("agents.intel_collector.fetch_malware_bazaar", return_value=[])
        mocker.patch("agents.intel_collector.fetch_cisa_kev", return_value=[])
        mocker.patch("pipeline.anthropic.Anthropic", return_value=mock_client)
        mocker.patch("pipeline.ANTHROPIC_API_KEY", "test-key")

        from pipeline import run_pipeline
        report = run_pipeline(feed_types=["rss", "api"], max_iterations=2, hunt_refinement_iters=0)
        assert report["total_iterations"] == 2
        assert report["status"] == "max_iterations_reached"

    def test_progress_callbacks_emitted(self, mocker, sample_intel_summary, sample_hunt_plan, sample_review_approved):
        import json
        tokens = []
        mocker.patch("agents.intel_collector.fetch_rss_feeds", return_value=[])
        mocker.patch("agents.intel_collector.fetch_feodo_tracker", return_value=[])
        mocker.patch("agents.intel_collector.fetch_threatfox", return_value=[])
        mocker.patch("agents.intel_collector.fetch_urlhaus", return_value=[])
        mocker.patch("agents.intel_collector.fetch_malware_bazaar", return_value=[])
        mocker.patch("agents.intel_collector.fetch_cisa_kev", return_value=[])

        import anthropic
        mock_client = MagicMock(spec=anthropic.Anthropic)
        mock_client.messages.create.side_effect = [
            _make_llm_response(json.dumps(sample_intel_summary)),
            _make_llm_response(json.dumps(sample_hunt_plan)),
            _make_llm_response(json.dumps(sample_review_approved)),
        ]
        mocker.patch("pipeline.anthropic.Anthropic", return_value=mock_client)
        mocker.patch("pipeline.ANTHROPIC_API_KEY", "test-key")

        from pipeline import run_pipeline
        run_pipeline(
            feed_types=["rss", "api"],
            max_iterations=1,
            hunt_refinement_iters=0,
            progress_callback=tokens.append,
        )
        assert "phase:collection" in tokens
        assert "phase:analysis" in tokens
        assert "phase:complete" in tokens
        assert any(t.startswith("collected:") for t in tokens)
