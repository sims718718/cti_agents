"""Base agent with shared helpers."""
from __future__ import annotations

import json
import re
from typing import Any

import anthropic


class BaseAgent:
    """Shared utilities for all Claude-powered agents."""

    def __init__(self, client: anthropic.Anthropic, model: str):
        self.client = client
        self.model = model

    def _chat(
        self,
        system: str,
        messages: list[dict],
        max_tokens: int = 4096,
    ) -> str:
        """Send a conversation to Claude and return the text response."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        return response.content[0].text

    def _parse_json(self, text: str) -> dict | list:
        """Extract and parse the first JSON block from a response."""
        # Try raw first (model sometimes returns pure JSON)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Look for ```json ... ``` fences
        match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Last resort: depth-balanced brace/bracket extraction.
        # A greedy regex (r"(\{[\s\S]+\})") would span from the first opener to
        # the very last closer, corrupting responses that contain multiple JSON
        # blocks or prose between braces. The depth counter stops at the first
        # balanced span instead.
        for opener, closer in (("{", "}"), ("[", "]")):
            span = self._extract_first_json_object(text, opener, closer)
            if span:
                try:
                    return json.loads(span)
                except json.JSONDecodeError:
                    continue

        raise ValueError(f"Could not parse JSON from model response:\n{text[:500]}")

    @staticmethod
    def _extract_first_json_object(text: str, opener: str, closer: str) -> str | None:
        """Return the first depth-balanced opener…closer span found in text, or None.

        Walks the string character-by-character, tracking brace/bracket depth, and
        returns the substring from the first opener to the matching closer. Handles
        arbitrarily nested structures correctly.
        """
        depth = 0
        start = None
        for i, ch in enumerate(text):
            if ch == opener:
                if start is None:
                    start = i
                depth += 1
            elif ch == closer and depth > 0:
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        return None

    @staticmethod
    def _truncate(obj: Any, max_chars: int = 60_000) -> str:
        """Serialize obj to JSON, truncating if necessary."""
        serialized = json.dumps(obj, indent=2, default=str)
        if len(serialized) > max_chars:
            serialized = serialized[:max_chars] + "\n  ... [truncated for context limit]"
        return serialized
