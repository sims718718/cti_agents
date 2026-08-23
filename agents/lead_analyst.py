"""Lead Analyst Agent.

Responsibility: Peer-review the intel summary and hunt plan, score quality,
provide structured feedback, and orchestrate iterative improvement cycles.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from agents.base_agent import BaseAgent
from utils import events

if TYPE_CHECKING:
    from agents.intel_summarizer import IntelSummarizerAgent
    from agents.threat_hunter import ThreatHunterAgent
    from utils.display import Display

HUNT_REVIEW_SYSTEM_PROMPT = """You are a Lead CTI Analyst specialising in adversary simulation and threat hunting.

Your task is to review ONLY the hunt plan produced by the Threat Hunter.
The intel summary is provided as context so you can assess coverage and relevance.

Evaluate the hunt plan against these criteria:
- Hypothesis quality: Are hypotheses testable, specific, and tied to real TTPs?
- Query quality: Are detection queries syntactically correct, specific, and executable?
- IOC coverage: Are the most critical IOCs from the summary included in the hunt list?
- Data source requirements: Are the required data sources realistic and clearly specified?
- Coverage gaps: Are there significant threats from the intel summary not addressed?
- Diamond Model alignment: Do hypotheses reflect the Diamond Model vertices (especially infrastructure/capability) and narrative context from the intel summary, rather than ignoring them?

Output ONLY valid JSON:
{
  "hunt_score": <1-10>,
  "hunt_approved": <true if hunt_score >= 7 else false>,
  "hunter_feedback": "<specific, actionable instructions for the Threat Hunter to improve the plan>",
  "hunt_strengths": ["<what was done well>"],
  "hunt_gaps": ["<specific missing or weak areas>"]
}"""

REVIEW_SYSTEM_PROMPT = """You are a Lead CTI Analyst responsible for quality-assuring
threat intelligence products before they reach the hunt team.

Critically evaluate the intel summary AND the hunt plan against these criteria:

INTEL SUMMARY criteria:
- Completeness: Are all significant threats identified and characterized?
- Accuracy: Are MITRE technique mappings correct and specific (technique_id, tactic, confidence all populated and plausible)?
- Actionability: Are IOCs and priorities clear and usable?
- Context: Is the threat landscape appropriately contextualized?
- Diamond Model & narrative quality: Are adversary/capability/infrastructure/victim vertices specific and evidence-based (not generic placeholders), and does each narrative logically connect them to the observed techniques?

HUNT PLAN criteria:
- Hypothesis quality: Are hypotheses testable and tied to real TTPs?
- Query quality: Are detection queries specific, executable, and correct?
- Coverage: Do hypotheses cover the most critical threats in the summary?
- Practicality: Are data source requirements realistic?

Score each area 1-10 and compute an overall score.
If overall < 7, identify specific, actionable improvements.

Output ONLY valid JSON:
{
  "overall_score": <1-10>,
  "approved": <true if overall_score >= 7 else false>,
  "scores": {
    "intel_completeness": <1-10>,
    "intel_accuracy": <1-10>,
    "intel_actionability": <1-10>,
    "intel_diamond_narrative_quality": <1-10>,
    "hunt_hypothesis_quality": <1-10>,
    "hunt_query_quality": <1-10>,
    "hunt_coverage": <1-10>
  },
  "strengths": ["<what was done well>"],
  "critical_gaps": ["<specific missing or incorrect items>"],
  "summarizer_feedback": "<specific instructions for the intel summarizer to improve>",
  "hunter_feedback": "<specific instructions for the threat hunter to improve>",
  "reviewer_notes": "<overall qualitative assessment>"
}"""


class LeadAnalystAgent(BaseAgent):
    """Orchestrates the full CTI pipeline and peer-reviews agent outputs."""

    def review(
        self,
        intel_summary: dict[str, Any],
        hunt_plan: dict[str, Any],
        iteration: int = 1,
    ) -> dict[str, Any]:
        """Peer-review both outputs and return structured feedback.

        Args:
            intel_summary: Output from IntelSummarizerAgent.
            hunt_plan: Output from ThreatHunterAgent.
            iteration: Current iteration number.

        Returns:
            Review dict with scores, approval flag, and feedback.
        """
        combined = {
            "intel_summary": intel_summary,
            "hunt_plan": hunt_plan,
        }
        combined_text = self._truncate(combined, max_chars=40_000)

        messages = [
            {
                "role": "user",
                "content": (
                    f"# Review Request – Iteration {iteration}\n\n"
                    f"Please review the following intel summary and hunt plan:\n\n"
                    f"{combined_text}"
                ),
            }
        ]

        fallback = {
            "overall_score": 5,
            "approved": False,
            "scores": {},
            "strengths": [],
            "critical_gaps": ["Could not parse lead analyst review."],
            "summarizer_feedback": "Please ensure output is complete and well-structured.",
            "hunter_feedback": "Please ensure detection queries are specific and executable.",
            "reviewer_notes": "",
        }
        return self._call_and_parse(REVIEW_SYSTEM_PROMPT, messages, fallback, max_tokens=4096)

    def _review_hunt_plan(
        self,
        intel_summary: dict,
        hunt_plan: dict,
        iteration: int = 1,
    ) -> dict:
        """Review only the hunt plan quality using HUNT_REVIEW_SYSTEM_PROMPT.

        Args:
            intel_summary: Used as context (not scored, just provided for coverage assessment).
            hunt_plan: Output from ThreatHunterAgent to be reviewed.
            iteration: Current refinement iteration number.

        Returns:
            Hunt review dict with hunt_score, hunt_approved, hunter_feedback, etc.
        """
        combined = {
            "intel_summary_context": intel_summary,
            "hunt_plan": hunt_plan,
        }
        combined_text = self._truncate(combined, max_chars=30_000)

        messages = [
            {
                "role": "user",
                "content": (
                    f"# Hunt Plan Review – Refinement Iteration {iteration}\n\n"
                    f"Please review the following hunt plan (intel summary provided as context only):\n\n"
                    f"{combined_text}"
                ),
            }
        ]

        fallback = {
            "hunt_score": 5,
            "hunt_approved": False,
            "hunter_feedback": "Please ensure hunt plan is complete and queries are executable.",
            "hunt_strengths": [],
            "hunt_gaps": ["Could not parse hunt review."],
        }
        return self._call_and_parse(HUNT_REVIEW_SYSTEM_PROMPT, messages, fallback, max_tokens=2048)

    @staticmethod
    def _meets_threshold(score: Any, approved: Any, threshold: int) -> bool:
        """Shared pass/fail decision for the main QA loop and the hunter-only
        refinement loop.

        Previously each loop reimplemented this check independently
        (`review.get("approved") or review.get("overall_score", 0) >= threshold`
        vs. the hunt-only equivalent), risking silent drift between the two.
        """
        return bool(approved) or (score or 0) >= threshold

    def _run_main_pass(
        self,
        raw_intel: dict[str, Any],
        summarizer: "IntelSummarizerAgent",
        hunter: "ThreatHunterAgent",
        previous_review: dict,
        iteration: int,
        display: "Display | None",
        _cb: Callable[[dict], None],
        quality_threshold: int,
    ) -> tuple[dict, dict, dict]:
        """Run one summarizer -> hunter -> lead-analyst-review pass.

        Feedback from `previous_review` (empty on the first iteration) is
        threaded into the summarizer/hunter calls so each pass can act on the
        prior iteration's critique.

        Returns:
            (intel_summary, hunt_plan, review) produced by this pass.
        """
        # ── Step A: Intel Summarizer ───────────────────────────────────────
        _cb(events.agent_started("summarizer"))
        if display:
            display.agent_step("IntelSummarizerAgent", "Analyzing and summarizing OSINT…")
        summarizer_feedback = previous_review.get("summarizer_feedback", "") if previous_review else ""
        intel_summary = summarizer.run(
            raw_intel,
            feedback=summarizer_feedback,
            iteration=iteration,
        )
        if intel_summary.get("parse_error"):
            _cb(events.parse_error("summarizer"))
            if display:
                display.parse_error_warning("IntelSummarizerAgent")
        n_threats = len(intel_summary.get("threat_landscape", {}).get("primary_threats", []))
        _cb(events.summarizer_done(n_threats))
        if display:
            display.agent_done(
                "IntelSummarizerAgent",
                f"{n_threats} primary threats identified",
            )

        # ── Step B: Threat Hunter ──────────────────────────────────────────
        _cb(events.agent_started("hunter"))
        if display:
            display.agent_step("ThreatHunterAgent", "Developing threat hunt hypotheses and plan…")
        hunter_feedback = previous_review.get("hunter_feedback", "") if previous_review else ""
        hunt_plan = hunter.run(
            intel_summary,
            feedback=hunter_feedback,
            iteration=iteration,
        )
        if hunt_plan.get("parse_error"):
            _cb(events.parse_error("hunter"))
            if display:
                display.parse_error_warning("ThreatHunterAgent")
        n_hyp = len(hunt_plan.get("hypotheses", []))
        _cb(events.hunter_done(n_hyp))
        if display:
            display.agent_done(
                "ThreatHunterAgent",
                f"{n_hyp} hunt hypotheses generated",
            )

        # ── Step C: Lead Analyst Review ────────────────────────────────────
        _cb(events.agent_started("lead_analyst"))
        if display:
            display.agent_step("LeadAnalystAgent", "Peer-reviewing intel summary and hunt plan…")
        review = self.review(intel_summary, hunt_plan, iteration=iteration)
        score = review.get("overall_score", 0)
        _cb(events.review_done(score))
        if display:
            display.review_result(review, quality_threshold)

        return intel_summary, hunt_plan, review

    def orchestrate(
        self,
        raw_intel: dict[str, Any],
        summarizer: "IntelSummarizerAgent",
        hunter: "ThreatHunterAgent",
        display: "Display | None" = None,
        max_iterations: int = 3,
        quality_threshold: int = 7,
        progress_callback: Callable[[dict], None] | None = None,
        hunt_refinement_iters: int = 2,
    ) -> dict[str, Any]:
        """Run the full multi-agent pipeline with iterative improvement.

        Workflow:
          1. Summarizer produces intel summary from raw data.
          2. Hunter produces hunt plan from intel summary.
          3. Lead analyst reviews both.
          4. If approved (score >= threshold) → done.
          5. Else provide feedback and repeat up to max_iterations.

        Args:
            display: Optional rich Display instance (CLI only).
            progress_callback: Optional callable receiving typed event dicts
                (see utils/events.py).

        Returns:
            Final consolidated report dict.
        """
        def _cb(event: dict) -> None:
            if progress_callback:
                progress_callback(event)

        intel_summary: dict = {}
        hunt_plan: dict = {}
        review: dict = {}
        history: list[dict] = []

        for i in range(1, max_iterations + 1):
            _cb(events.iteration(i))
            if display:
                display.iteration_header(i, max_iterations)

            intel_summary, hunt_plan, review = self._run_main_pass(
                raw_intel, summarizer, hunter, review, i, display, _cb, quality_threshold,
            )

            history.append(
                {
                    "iteration": i,
                    "score": review.get("overall_score"),
                    "approved": review.get("approved"),
                    "review": review,
                }
            )

            if self._meets_threshold(review.get("overall_score", 0), review.get("approved"), quality_threshold):
                _cb(events.approved())
                if display:
                    display.approved(review.get("overall_score", "N/A"))
                break
            elif i < max_iterations:
                _cb(events.iterating())
                if display:
                    display.iterating(review)
            else:
                _cb(events.max_iterations_reached())
                if display:
                    display.max_iterations_reached(review.get("overall_score", "N/A"))

        # ── Phase 2: Hunter-only refinement ───────────────────────────────────
        hunt_refinement_history: list[dict] = []
        for j in range(1, hunt_refinement_iters + 1):
            _cb(events.hunt_refinement(j))
            hunt_review = self._review_hunt_plan(intel_summary, hunt_plan, iteration=j)
            hunt_score = hunt_review.get("hunt_score", 0)
            _cb(events.hunt_review_done(hunt_score))
            hunt_refinement_history.append({
                "iteration": j,
                "hunt_score": hunt_score,
                "hunt_approved": hunt_review.get("hunt_approved"),
                "review": hunt_review,
            })
            if self._meets_threshold(hunt_score, hunt_review.get("hunt_approved"), quality_threshold):
                _cb(events.hunt_approved())
                break
            elif j < hunt_refinement_iters:
                _cb(events.hunt_iterating())
                _cb(events.agent_started("hunter"))
                hunt_plan = hunter.run(
                    intel_summary,
                    feedback=hunt_review.get("hunter_feedback", ""),
                    iteration=j,
                )
                n_hyp = len(hunt_plan.get("hypotheses", []))
                _cb(events.hunter_done(n_hyp))
            else:
                _cb(events.hunt_max_iterations_reached())

        return {
            "status": "approved" if review.get("approved") else "max_iterations_reached",
            "total_iterations": len(history),
            "final_score": review.get("overall_score"),
            "intel_summary": intel_summary,
            "hunt_plan": hunt_plan,
            "lead_analyst_review": review,
            "iteration_history": history,
            "hunt_refinement_history": hunt_refinement_history,
            "collection_metadata": {
                "timestamp": raw_intel.get("collection_timestamp"),
                "feed_types": raw_intel.get("feed_types_used"),
            },
        }
