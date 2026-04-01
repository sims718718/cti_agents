"""Unit tests for BaseAgent helpers."""
from __future__ import annotations

import pytest

from agents.base_agent import BaseAgent


@pytest.fixture
def agent(mock_anthropic_client):
    return BaseAgent(client=mock_anthropic_client, model="test-model")


# ── _extract_first_json_object ─────────────────────────────────────────────────

class TestExtractFirstJsonObject:
    def test_simple_object(self):
        assert BaseAgent._extract_first_json_object('{"a": 1}', "{", "}") == '{"a": 1}'

    def test_simple_array(self):
        assert BaseAgent._extract_first_json_object("[1, 2, 3]", "[", "]") == "[1, 2, 3]"

    def test_embedded_in_text(self):
        text = 'Here is the result: {"key": "value"} done.'
        assert BaseAgent._extract_first_json_object(text, "{", "}") == '{"key": "value"}'

    def test_nested_object(self):
        text = '{"outer": {"inner": 42}}'
        assert BaseAgent._extract_first_json_object(text, "{", "}") == text

    def test_returns_first_when_multiple(self):
        text = '{"first": 1} some text {"second": 2}'
        result = BaseAgent._extract_first_json_object(text, "{", "}")
        assert result == '{"first": 1}'

    def test_no_match_returns_none(self):
        assert BaseAgent._extract_first_json_object("no braces here", "{", "}") is None

    def test_unbalanced_returns_none(self):
        assert BaseAgent._extract_first_json_object('{"unclosed": 1', "{", "}") is None

    def test_deeply_nested(self):
        text = '{"a": {"b": {"c": [1, 2, 3]}}}'
        result = BaseAgent._extract_first_json_object(text, "{", "}")
        assert result == text


# ── _parse_json ────────────────────────────────────────────────────────────────

class TestParseJson:
    def test_raw_json_dict(self, agent):
        result = agent._parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_raw_json_list(self, agent):
        result = agent._parse_json('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_markdown_fence_json(self, agent):
        text = '```json\n{"extracted": true}\n```'
        result = agent._parse_json(text)
        assert result == {"extracted": True}

    def test_markdown_fence_no_lang_tag(self, agent):
        text = '```\n{"extracted": true}\n```'
        result = agent._parse_json(text)
        assert result == {"extracted": True}

    def test_brace_fallback_with_surrounding_text(self, agent):
        text = 'Here is the analysis:\n{"threats": ["malware"]}\nEnd of analysis.'
        result = agent._parse_json(text)
        assert result == {"threats": ["malware"]}

    def test_multiple_json_blocks_returns_first(self, agent):
        # Previously greedy regex would capture from first { to last }
        text = 'Context: {"first": 1} and also {"second": 2}'
        result = agent._parse_json(text)
        assert result == {"first": 1}

    def test_nested_json_parsed_correctly(self, agent):
        text = '{"outer": {"inner": [1, 2, 3]}}'
        result = agent._parse_json(text)
        assert result["outer"]["inner"] == [1, 2, 3]

    def test_raises_on_no_json(self, agent):
        with pytest.raises(ValueError, match="Could not parse JSON"):
            agent._parse_json("No JSON here whatsoever.")

    def test_raises_on_empty_string(self, agent):
        with pytest.raises(ValueError):
            agent._parse_json("")

    def test_array_fallback(self, agent):
        # When text contains only an array (no competing {} objects), the array is found
        text = 'Result: ["item1", "item2"] complete.'
        result = agent._parse_json(text)
        assert result == ["item1", "item2"]


# ── _truncate ──────────────────────────────────────────────────────────────────

class TestTruncate:
    def test_under_limit_unchanged(self):
        obj = {"key": "value"}
        result = BaseAgent._truncate(obj, max_chars=1000)
        import json
        assert result == json.dumps(obj, indent=2, default=str)

    def test_over_limit_truncated(self):
        obj = {"data": "x" * 200}
        result = BaseAgent._truncate(obj, max_chars=50)
        assert len(result) <= 50 + len("\n  ... [truncated for context limit]")
        assert result.endswith("[truncated for context limit]")

    def test_truncation_marker_present(self):
        big_obj = {"items": list(range(1000))}
        result = BaseAgent._truncate(big_obj, max_chars=100)
        assert "[truncated for context limit]" in result

    def test_exact_limit_not_truncated(self):
        import json
        obj = {"k": "v"}
        serialized = json.dumps(obj, indent=2, default=str)
        result = BaseAgent._truncate(obj, max_chars=len(serialized))
        assert "[truncated" not in result
