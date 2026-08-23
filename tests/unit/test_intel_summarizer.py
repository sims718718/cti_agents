"""Unit tests for IntelSummarizerAgent."""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agents.intel_summarizer import IntelSummarizerAgent


@pytest.fixture
def agent(mock_anthropic_client):
    return IntelSummarizerAgent(client=mock_anthropic_client, model="test-model")


class TestRun:
    def test_success_returns_parsed_summary(self, agent, mock_anthropic_client, sample_raw_intel, sample_intel_summary):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(sample_intel_summary))
        ]
        result = agent.run(sample_raw_intel)
        assert result["parse_error"] is False
        assert result["executive_summary"] == sample_intel_summary["executive_summary"]

    def test_parse_failure_returns_typed_fallback(self, agent, mock_anthropic_client, sample_raw_intel):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text="not valid json")
        ]
        result = agent.run(sample_raw_intel, iteration=2)
        assert result["parse_error"] is True
        # No more magic-string sniffing needed by callers — but the message is
        # still present for human debugging.
        assert "Parse error on iteration 2" in result["executive_summary"]
        assert result["threat_landscape"]["primary_threats"] == []
        assert "raw_response" in result

    def test_feedback_is_prepended_to_user_content(self, agent, mock_anthropic_client, sample_raw_intel, sample_intel_summary):
        mock_anthropic_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(sample_intel_summary))
        ]
        agent.run(sample_raw_intel, feedback="Be more specific about IOCs.")
        _, kwargs = mock_anthropic_client.messages.create.call_args
        user_content = kwargs["messages"][0]["content"]
        assert "Lead Analyst Feedback" in user_content
        assert "Be more specific about IOCs." in user_content
