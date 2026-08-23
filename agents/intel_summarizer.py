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
- mitre_techniques per threat: max 5 objects, most relevant first

For each primary_threat's mitre_techniques, output structured objects (NOT strings):
technique_id (e.g. "T1071" or "T1071.001"), technique_name, tactic (one of the 14
MITRE ATT&CK Enterprise tactics, e.g. "Command and Control"), and confidence
("high"|"medium"|"low" — your certainty in this mapping given the available evidence).

For each primary_threat, also produce a Diamond Model of Intrusion Analysis
(diamond_model) with exactly four vertices: adversary, capability, infrastructure,
victim. Each is a short 1-2 sentence field. NEVER omit a vertex key — if intel is
insufficient for a vertex, write "insufficient data" as its value rather than
dropping the key.

For each primary_threat, also produce a narrative: a single 2-4 sentence analytic
story connecting adversary -> capability -> infrastructure -> victim -> observed
MITRE techniques. Write it for a threat hunter deciding what to prioritize — it
should justify why this threat matters and what to look for, not restate the
description field.

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
        "mitre_techniques": [
          {
            "technique_id": "<TXXXX or TXXXX.XXX>",
            "technique_name": "<Technique Name>",
            "tactic": "<ATT&CK tactic name>",
            "confidence": "<high|medium|low>"
          }
        ],
        "diamond_model": {
          "adversary": "<attributed actor/group, or 'insufficient data' — 1 sentence>",
          "capability": "<malware/tools/techniques used — 1-2 sentences>",
          "infrastructure": "<C2/hosting/delivery infrastructure — 1-2 sentences>",
          "victim": "<targeted sectors/orgs/geographies — 1-2 sentences>"
        },
        "narrative": "<2-4 sentence story: adversary -> capability -> infrastructure -> victim -> techniques>",
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

        fallback = {
            "executive_summary": f"[Parse error on iteration {iteration}] Model response could not be parsed as JSON.",
            "threat_landscape": {
                "primary_threats": [],
                "active_campaigns": [],
                "exploited_vulnerabilities": [],
            },
            "key_iocs": {"ips": [], "urls": [], "hashes": [], "domains": []},
            "recommended_priorities": [],
            "intelligence_gaps": ["Response parse failure"],
        }
        return self._call_and_parse(SYSTEM_PROMPT, messages, fallback, max_tokens=8192)
