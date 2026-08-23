"""Unit tests for LeadAnalystAgent."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agents.lead_analyst import LeadAnalystAgent


@pytest.fixture
def agent(mock_anthropic_client):
    return LeadAnalystAgent(client=mock_anthropic_client, model="test-model")


class TestReview:
    def test_success_returns_parsed_review(
        self, agent, mock_anthropic_client, sample_intel_summary, sample_hunt_plan, sample_review_approved
    ):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(sample_review_approved))
        ]
        result = agent.review(sample_intel_summary, sample_hunt_plan)
        assert result["parse_error"] is False
        assert result["overall_score"] == 8
        assert result["approved"] is True

    def test_parse_failure_returns_typed_fallback(
        self, agent, mock_anthropic_client, sample_intel_summary, sample_hunt_plan
    ):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text="not valid json")
        ]
        result = agent.review(sample_intel_summary, sample_hunt_plan)
        assert result["parse_error"] is True
        assert result["overall_score"] == 5
        assert result["approved"] is False
        assert "raw_response" in result


class TestReviewHuntPlan:
    def test_success_returns_parsed_hunt_review(
        self, agent, mock_anthropic_client, sample_intel_summary, sample_hunt_plan
    ):
        hunt_review = {
            "hunt_score": 9,
            "hunt_approved": True,
            "hunter_feedback": "",
            "hunt_strengths": [],
            "hunt_gaps": [],
        }
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(hunt_review))
        ]
        result = agent._review_hunt_plan(sample_intel_summary, sample_hunt_plan)
        assert result["parse_error"] is False
        assert result["hunt_score"] == 9

    def test_parse_failure_returns_typed_fallback(
        self, agent, mock_anthropic_client, sample_intel_summary, sample_hunt_plan
    ):
        mock_anthropic_client.messages.create.return_value.content = [MagicMock(text="garbage")]
        result = agent._review_hunt_plan(sample_intel_summary, sample_hunt_plan)
        assert result["parse_error"] is True
        assert result["hunt_score"] == 5
        assert result["hunt_approved"] is False


class TestMeetsThreshold:
    """Locks in the shared pass/fail decision used by both the main QA loop
    and the hunter-only refinement loop, so the two can no longer drift
    independently (see agents/lead_analyst.py::_meets_threshold)."""

    @pytest.mark.parametrize(
        "score,approved,threshold,expected",
        [
            (8, False, 7, True),      # score alone clears threshold
            (5, True, 7, True),       # explicit approval overrides a low score
            (5, False, 7, False),     # neither approved nor above threshold
            (None, False, 7, False),  # missing score treated as 0
            (7, False, 7, True),      # exactly at threshold
        ],
    )
    def test_matrix(self, score, approved, threshold, expected):
        assert LeadAnalystAgent._meets_threshold(score, approved, threshold) is expected


class TestOrchestrate:
    """Exercises orchestrate() directly with stub summarizer/hunter agents,
    independent of pipeline.py."""

    @staticmethod
    def _stub(run_return):
        stub = MagicMock()
        stub.run.return_value = run_return
        return stub

    def test_approved_first_iteration_skips_further_main_loop_iterations(
        self, agent, mock_anthropic_client, sample_raw_intel, sample_intel_summary,
        sample_hunt_plan, sample_review_approved,
    ):
        # hunt_refinement_iters=0 isolates the main QA loop's early-exit
        # behavior; the hunter-only refinement phase (a separate loop that
        # always runs at least one review pass) is covered separately.
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(sample_review_approved))
        ]
        summarizer = self._stub({**sample_intel_summary, "parse_error": False})
        hunter = self._stub({**sample_hunt_plan, "parse_error": False})

        report = agent.orchestrate(
            sample_raw_intel, summarizer, hunter,
            max_iterations=3, quality_threshold=7, hunt_refinement_iters=0,
        )

        assert report["status"] == "approved"
        assert report["total_iterations"] == 1
        summarizer.run.assert_called_once()
        hunter.run.assert_called_once()

    def test_parse_error_flag_triggers_warning_callback(
        self, agent, mock_anthropic_client, sample_raw_intel, sample_hunt_plan, sample_review_approved,
    ):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(sample_review_approved))
        ]
        broken_summary = {
            "executive_summary": "[Parse error on iteration 1] boom",
            "parse_error": True,
            "threat_landscape": {"primary_threats": []},
        }
        summarizer = self._stub(broken_summary)
        hunter = self._stub({**sample_hunt_plan, "parse_error": False})

        received: list[dict] = []
        agent.orchestrate(
            sample_raw_intel, summarizer, hunter,
            max_iterations=1, quality_threshold=7, hunt_refinement_iters=0,
            progress_callback=received.append,
        )

        assert {"event": "parse_error", "agent": "summarizer"} in received
