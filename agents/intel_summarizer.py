"""Intel Summarizer Agent.

Responsibility: Consume raw OSINT and produce a structured, analyst-ready
threat intelligence summary using Claude.
"""
from __future__ import annotations

import json
from typing import Any

from agents.base_agent import BaseAgent

SYSTEM_PROMPT = """You are a senior Cyber Threat Intelligence (CTI) analyst.
Your role is to analyze raw, multi-source OSINT data and produce a concise,
structured threat intelligence summary for a threat hunt analyst.

Output ONLY valid JSON matching the schema below — no markdown fences, no commentary.
Keep descriptions concise (1-2 sentences max per field). Limit arrays strictly:
- primary_threats: TOP 5 most significant only
- active_campaigns: TOP 3 only
- exploited_vulnerabilities: TOP 5 most critical only
- key_iocs: max 5 per category
- recommended_priorities: max 5 items
- intelligence_gaps: max 3 items

Schema:
{
  "executive_summary": "<3-5 sentence overview of the current threat landscape>",
  "threat_landscape": {
    "primary_threats": [
      {
        "name": "<threat name / actor / malware family>",
        "type": "<ransomware|apt|botnet|phishing|exploit|other>",
        "severity": "<critical|high|medium|low>",
        "description": "<1-2 sentence description>",
        "affected_sectors": ["<sector>"],
        "iocs": ["<sample IOC values if available>"],
        "mitre_techniques": ["<TXXXX – Technique Name>"],
        "sources": ["<source names>"]
      }
    ],
    "active_campaigns": [
      {
        "name": "<campaign name>",
        "description": "<1-2 sentence description>",
        "targets": ["<targeted sectors/regions>"],
        "ttps": ["<observed TTPs>"],
        "confidence": "<high|medium|low>"
      }
    ],
    "exploited_vulnerabilities": [
      {
        "cve_id": "<CVE-YYYY-NNNNN>",
        "product": "<vendor product>",
        "description": "<brief impact>",
        "date_added": "<date>",
        "required_action": "<mitigation>"
      }
    ]
  },
  "key_iocs": {
    "ips": ["<ip:port or ip>"],
    "urls": ["<url>"],
    "hashes": ["<sha256>"],
    "domains": ["<domain>"]
  },
  "recommended_priorities": [
    "<ranked action items for the hunt team, most urgent first>"
  ],
  "intelligence_gaps": [
    "<areas where intel is lacking or unclear>"
  ]
}"""


class IntelSummarizerAgent(BaseAgent):
    """LLM-powered agent that summarizes raw OSINT into structured intel."""

    def run(
        self,
        raw_intel: dict[str, Any],
        feedback: str = "",
        iteration: int = 1,
    ) -> dict[str, Any]:
        """Produce a structured threat intelligence summary.

        Args:
            raw_intel: Raw collection output from IntelCollectorAgent.
            feedback: Lead analyst feedback from a previous iteration (if any).
            iteration: Current iteration number for context.

        Returns:
            Parsed JSON dict matching the schema above.
        """
        raw_text = self._truncate(raw_intel, max_chars=55_000)

        user_content = f"# Raw OSINT Data (Iteration {iteration})\n\n{raw_text}"

        if feedback:
            user_content = (
                f"# Lead Analyst Feedback (please address this in your revision)\n\n"
                f"{feedback}\n\n"
                f"---\n\n"
                f"{user_content}"
            )

        messages = [{"role": "user", "content": user_content}]
        raw_response = self._chat(SYSTEM_PROMPT, messages, max_tokens=8192)

        try:
            return self._parse_json(raw_response)
        except ValueError as exc:
            # Return a minimal structure so the pipeline can continue
            return {
                "executive_summary": f"[Parse error on iteration {iteration}] {exc}",
                "raw_response": raw_response[:2000],
                "threat_landscape": {
                    "primary_threats": [],
                    "active_campaigns": [],
                    "exploited_vulnerabilities": [],
                },
                "key_iocs": {"ips": [], "urls": [], "hashes": [], "domains": []},
                "recommended_priorities": [],
                "intelligence_gaps": ["Response parse failure"],
            }
