"""Unit tests for ThreatHunterAgent."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agents.threat_hunter import ThreatHunterAgent


@pytest.fixture
def agent(mock_anthropic_client):
    return ThreatHunterAgent(client=mock_anthropic_client, model="test-model")


class TestRun:
    def test_success_returns_parsed_hunt_plan(self, agent, mock_anthropic_client, sample_intel_summary, sample_hunt_plan):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(sample_hunt_plan))
        ]
        result = agent.run(sample_intel_summary)
        assert result["parse_error"] is False
        assert result["hunt_plan"]["title"] == sample_hunt_plan["hunt_plan"]["title"]

    def test_parse_failure_returns_typed_fallback(self, agent, mock_anthropic_client, sample_intel_summary):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text="not valid json")
        ]
        result = agent.run(sample_intel_summary, iteration=3)
        assert result["parse_error"] is True
        assert "Parse error on iteration 3" in result["hunt_plan"]["title"]
        assert result["hypotheses"] == []
        assert "raw_response" in result

    def test_feedback_is_prepended_to_user_content(self, agent, mock_anthropic_client, sample_intel_summary, sample_hunt_plan):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(sample_hunt_plan))
        ]
        agent.run(sample_intel_summary, feedback="Add more Sigma coverage.")
        _, kwargs = mock_anthropic_client.messages.create.call_args
        user_content = kwargs["messages"][0]["content"]
        assert "Lead Analyst Feedback" in user_content
        assert "Add more Sigma coverage." in user_content
