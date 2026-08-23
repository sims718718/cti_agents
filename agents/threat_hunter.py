"""Threat Hunter Agent.

Responsibility: Consume the intel summary and produce a detailed,
prioritized threat hunt plan with hypotheses and detection logic.
"""
from __future__ import annotations

from typing import Any

from agents.base_agent import BaseAgent

SYSTEM_PROMPT = """You are an expert Threat Hunt Analyst with deep knowledge of
MITRE ATT&CK, endpoint and network detection engineering, and SIEM/EDR tooling.

Given a threat intelligence summary, create a prioritized threat hunt plan.
Focus on practical, executable hunts that a SOC team can run today.

The intel summary includes, per primary threat, a Diamond Model of Intrusion
Analysis (adversary/capability/infrastructure/victim) and a short narrative.
Use the infrastructure and capability vertices to shape which IOCs and behaviors
your hypotheses target, and use each threat's narrative to justify why a
hypothesis is prioritized. Tag every hypothesis with the Diamond Model vertex(es)
it primarily investigates via diamond_vertex_focus.

Output ONLY valid JSON matching the schema below — no markdown fences, no commentary.
Keep all fields concise. Limit arrays strictly:
- hypotheses: exactly 3 (the highest-priority ones)
- hunt_queries per hypothesis: exactly 3 — one Sigma YAML rule, one KQL (Microsoft Sentinel), one SPL (Splunk)
- data_sources per hypothesis: max 3
- response_actions per hypothesis: max 3
- ioc_hunt_list: max 5 per category
- data_collection_requirements: max 4 items
- success_criteria: max 3 items
- escalation_thresholds: max 3 items
- mitre_techniques per hypothesis: max 4 objects
- diamond_vertex_focus per hypothesis: max 2 items, from adversary|capability|infrastructure|victim

For Sigma rules, always include these fields: title, id (uuid4), status (experimental),
description, references (empty list ok), author, date (today), logsource (category + product),
detection (selection + condition), falsepositives, level, tags (MITRE ATT&CK).
For KQL, target Microsoft Sentinel tables (SecurityEvent, DeviceProcessEvents, DeviceNetworkEvents, etc.).
For SPL, target standard Splunk indexes (index=windows, index=network, sourcetype=WinEventLog, etc.).

Schema:
{
  "hunt_plan": {
    "title": "<descriptive hunt campaign title>",
    "objective": "<1-2 sentence objective>",
    "priority": "<critical|high|medium|low>",
    "estimated_duration": "<e.g., 2-4 hours>",
    "analyst_skill_level": "<junior|intermediate|senior>"
  },
  "hypotheses": [
    {
      "id": "H-001",
      "title": "<hypothesis title>",
      "description": "<what adversary behavior are we looking for>",
      "diamond_vertex_focus": ["<adversary|capability|infrastructure|victim>"],
      "mitre_techniques": [
        {
          "technique_id": "<TXXXX or TXXXX.XXX>",
          "technique_name": "<Technique Name>",
          "tactic": "<ATT&CK tactic name>",
          "confidence": "<high|medium|low>"
        }
      ],
      "risk_level": "<critical|high|medium|low>",
      "data_sources": ["<Windows Event Logs|EDR telemetry|Firewall logs|DNS logs|etc.>"],
      "hunt_queries": [
        {
          "platform": "Sigma",
          "description": "<what this Sigma rule detects>",
          "query": "title: ...\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    ...\n  condition: selection"
        },
        {
          "platform": "KQL",
          "description": "<what this KQL detects in Microsoft Sentinel>",
          "query": "<KQL query>"
        },
        {
          "platform": "SPL",
          "description": "<what this SPL detects in Splunk>",
          "query": "<SPL query>"
        }
      ],
      "false_positive_considerations": "<common benign triggers to be aware of>",
      "response_actions": ["<recommended triage/response steps if confirmed>"]
    }
  ],
  "ioc_hunt_list": {
    "ips_to_hunt": ["<ip>"],
    "urls_to_hunt": ["<url>"],
    "hashes_to_hunt": ["<sha256>"],
    "domains_to_hunt": ["<domain>"]
  },
  "data_collection_requirements": [
    "<log source or telemetry needed and why>"
  ],
  "success_criteria": [
    "<measurable outcome indicating a successful hunt>"
  ],
  "escalation_thresholds": [
    "<condition that should trigger incident response escalation>"
  ]
}"""


class ThreatHunterAgent(BaseAgent):
    """LLM-powered agent that develops threat hunt plans from intel summaries."""

    def run(
        self,
        intel_summary: dict[str, Any],
        feedback: str = "",
        iteration: int = 1,
    ) -> dict[str, Any]:
        """Generate a prioritized threat hunt plan.

        Args:
            intel_summary: Output from IntelSummarizerAgent.
            feedback: Lead analyst feedback from a previous iteration (if any).
            iteration: Current iteration number for context.

        Returns:
            Parsed JSON dict matching the hunt plan schema.
        """
        summary_text = self._truncate(intel_summary, max_chars=20_000)

        user_content = (
            f"# Threat Intelligence Summary (Iteration {iteration})\n\n"
            f"{summary_text}\n\n"
            "Develop a detailed, prioritized threat hunt plan based on this intelligence."
        )

        if feedback:
            user_content = (
                f"# Lead Analyst Feedback (please address this in your revision)\n\n"
                f"{feedback}\n\n"
                f"---\n\n"
                f"{user_content}"
            )

        messages = [{"role": "user", "content": user_content}]

        fallback = {
            "hunt_plan": {
                "title": f"[Parse error on iteration {iteration}]",
                "objective": "Model response could not be parsed as JSON.",
                "priority": "unknown",
                "estimated_duration": "unknown",
                "analyst_skill_level": "unknown",
            },
            "hypotheses": [],
            "ioc_hunt_list": {"ips_to_hunt": [], "urls_to_hunt": [], "hashes_to_hunt": [], "domains_to_hunt": []},
            "data_collection_requirements": [],
            "success_criteria": [],
            "escalation_thresholds": [],
        }
        return self._call_and_parse(SYSTEM_PROMPT, messages, fallback, max_tokens=16384)
