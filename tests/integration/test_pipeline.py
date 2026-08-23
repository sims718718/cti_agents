"""Integration tests for pipeline.run_pipeline()."""
from __future__ import annotations

import json

import pytest


class TestRunPipeline:
    """Test run_pipeline() with all external calls mocked."""

    def _run(self, mock_feed_collection, mock_llm_client, summary_json, hunt_json, review_json, **kwargs):
        """Helper: build the LLM response sequence and run the pipeline.

        hunt_refinement_iters defaults to 0 to keep mock response counts simple.
        Pass explicitly to test refinement behaviour.
        """
        kwargs.setdefault("hunt_refinement_iters", 0)
        mock_llm_client([summary_json, hunt_json, review_json])

        import importlib, pipeline
        importlib.reload(pipeline)  # pick up patched ANTHROPIC_API_KEY

        from pipeline import run_pipeline
        kwargs.setdefault("max_iterations", 1)
        return run_pipeline(feed_types=["rss", "api"], **kwargs)

    def test_missing_api_key_raises(self, mocker):
        mocker.patch("pipeline.ANTHROPIC_API_KEY", "")
        from pipeline import run_pipeline
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            run_pipeline()

    def test_approved_on_first_iteration(
        self, mock_feed_collection, mock_llm_client, sample_intel_summary, sample_hunt_plan, sample_review_approved
    ):
        report = self._run(
            mock_feed_collection, mock_llm_client,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
            max_iterations=3,
        )
        assert report["total_iterations"] == 1
        assert report["status"] == "approved"

    def test_report_has_expected_keys(
        self, mock_feed_collection, mock_llm_client, sample_intel_summary, sample_hunt_plan, sample_review_approved
    ):
        report = self._run(
            mock_feed_collection, mock_llm_client,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
        )
        for key in ("status", "total_iterations", "final_score", "intel_summary",
                    "hunt_plan", "lead_analyst_review", "iteration_history", "collection_metadata"):
            assert key in report, f"Missing key: {key}"

    def test_stix_url_adds_stix_to_feed_types(
        self, mocker, mock_feed_collection, mock_llm_client, sample_intel_summary, sample_hunt_plan, sample_review_approved
    ):
        mocker.patch("agents.intel_collector.fetch_from_url", return_value=[])
        report = self._run(
            mock_feed_collection, mock_llm_client,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
            stix_url="https://example.com/bundle.json",
        )
        assert "stix" in report["collection_metadata"]["feed_types"]

    def test_stix_file_adds_stix_to_feed_types(
        self, mocker, mock_feed_collection, mock_llm_client, sample_intel_summary, sample_hunt_plan,
        sample_review_approved, tmp_path,
    ):
        stix_file = tmp_path / "bundle.json"
        stix_file.write_text('{"objects": []}', encoding="utf-8")
        mocker.patch("agents.intel_collector.fetch_from_file", return_value=[])
        report = self._run(
            mock_feed_collection, mock_llm_client,
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
            stix_file=str(stix_file),
        )
        assert "stix" in report["collection_metadata"]["feed_types"]

    def test_max_iterations_reached_status(
        self, mock_feed_collection, mock_llm_client, sample_intel_summary, sample_hunt_plan
    ):
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
        # Enough responses for 2 main-loop iterations (summarizer + hunter +
        # reviewer each) plus 1 hunt-refinement pass (review + hunter + review).
        mock_llm_client([
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(review_not_approved),
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(review_not_approved),
            json.dumps(review_not_approved),
            json.dumps(sample_hunt_plan),
            json.dumps(review_not_approved),
        ])

        from pipeline import run_pipeline
        report = run_pipeline(feed_types=["rss", "api"], max_iterations=2, hunt_refinement_iters=0)
        assert report["total_iterations"] == 2
        assert report["status"] == "max_iterations_reached"

    def test_progress_callbacks_emitted(
        self, mock_feed_collection, mock_llm_client, sample_intel_summary, sample_hunt_plan, sample_review_approved
    ):
        received = []
        mock_llm_client([
            json.dumps(sample_intel_summary),
            json.dumps(sample_hunt_plan),
            json.dumps(sample_review_approved),
        ])

        from pipeline import run_pipeline
        run_pipeline(
            feed_types=["rss", "api"],
            max_iterations=1,
            hunt_refinement_iters=0,
            progress_callback=received.append,
        )
        event_names = [e["event"] for e in received]
        assert "phase_collection" in event_names
        assert "phase_analysis" in event_names
        assert "phase_complete" in event_names
        assert "collected" in event_names
