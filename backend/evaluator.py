"""
Deterministic access-change evaluator.

Rules applied per change (each gated by a boolean in the Rules object):
  1. ticket_id_required      – change must have a non-empty ticket_id
  2. approval_exists         – at least one APPROVED approval must exist
  3. approver_title_allowed  – every approver's title must be in the allowed list
  4. no_self_approval        – approver_id must differ from requester_id
  5. approval_timing         – approval must precede the change;
                               emergency changes allow approval within the window
  6. high_risk_two_approvers – is_high_risk_role=true requires ≥ N distinct approvers
  7. contractor_expiry       – user_type=contractor requires expiry_date

The LLM never decides pass/fail.  It only supplies the Rules configuration object.
All rule logic is pure Python driven exclusively by rules_used.
"""

import hashlib
import json
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rules_schema import Rules


# ── constants ─────────────────────────────────────────────────────────────────

ENGINE_VERSION = "mvp-deterministic-1"

ESCALATED_RISK_LEVELS = frozenset({"HIGH", "CRITICAL"})

_SEV_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_RISK_NUM   = {"CRITICAL": 3, "HIGH":  2, "MEDIUM": 1, "LOW":  0}

AI_STOP_REASON = (
    "Materiality/severity assessment and escalation decisions require human judgment."
)

HUMAN_QUEUE_PROMPT = (
    "Assess severity/materiality and whether this indicates a control breakdown "
    "or potential fraud. AI does not make this determination."
)


# ── deterministic risk scoring ────────────────────────────────────────────────

def _is_high_risk(change: Dict) -> bool:
    """Prefer explicit `is_high_risk_role` boolean; fall back to risk_level == 'high'."""
    if "is_high_risk_role" in change:
        return bool(change["is_high_risk_role"])
    return change.get("risk_level", "low").lower() == "high"


def _exception_risk_level(rule: str, change: Dict) -> str:
    """
    Map a failed rule + change context to a risk level string.

    CRITICAL – (approval_exists OR no_self_approval fails) AND is_high_risk_role == true
    HIGH     – core approval control failures; approval_timing on a high-risk change
    MEDIUM   – metadata gaps (ticket, expiry) and timing on non-high-risk changes
    LOW      – residual (should not normally occur with current rule set)
    """
    is_high = _is_high_risk(change)

    if rule in ("approval_exists", "no_self_approval") and is_high:
        return "CRITICAL"

    if rule in ("approval_exists", "no_self_approval",
                "approver_title_allowed", "high_risk_two_approvers"):
        return "HIGH"

    if rule == "approval_timing" and is_high:
        return "HIGH"

    if rule in ("contractor_expiry", "ticket_id_required", "approval_timing"):
        return "MEDIUM"

    return "LOW"


# ── ai triage summaries (deterministic, never state materiality) ──────────────

_TRIAGE_DESC: Dict[str, str] = {
    "ticket_id_required": (
        "This change record lacks a ticket identifier, preventing traceability to an "
        "authorized work order."
    ),
    "approval_exists": (
        "No APPROVED approval record was found for this change, so authorization cannot "
        "be confirmed from available records."
    ),
    "approver_title_allowed": (
        "At least one approver holds a role title not included in the policy-permitted "
        "list, which may not constitute valid authorization."
    ),
    "no_self_approval": (
        "The requester is also listed as an approver, violating segregation-of-duties policy."
    ),
    "approval_timing": (
        "One or more approvals were recorded after the change timestamp outside the "
        "permitted emergency window."
    ),
    "high_risk_two_approvers": (
        "This high-risk change was approved by fewer distinct individuals than the "
        "policy-required minimum."
    ),
    "contractor_expiry": (
        "This contractor access grant is missing an expiry date, leaving access "
        "open-ended without a defined review point."
    ),
}


def _escalation_sentence(risk_level: str, escalated: bool) -> str:
    if escalated:
        return (
            f"Classified {risk_level}; escalated for human review because failures of "
            f"this type at this risk level meet the mandatory escalation threshold."
        )
    return (
        f"Classified {risk_level}; not escalated because this finding does not meet the "
        f"mandatory escalation threshold — human judgment is required to assess materiality."
    )


def _ai_triage_summary(rule: str, risk_level: str, escalated: bool) -> str:
    desc = _TRIAGE_DESC.get(rule, f"Automated evaluation flagged rule '{rule}'.")
    return f"{desc} {_escalation_sentence(risk_level, escalated)}"


def _enrich_exception(exc: Dict, change: Dict) -> Dict:
    """Overwrite severity to match risk_level; add escalation + AI triage fields."""
    risk      = _exception_risk_level(exc["rule"], change)
    escalated = risk in ESCALATED_RISK_LEVELS
    return {
        **exc,
        "severity":                 risk,   # kept for backward compat; always == risk_level
        "risk_level":               risk,
        "escalated_to_human_queue": escalated,
        "ai_triage_summary":        _ai_triage_summary(exc["rule"], risk, escalated),
        "ai_stop_reason":           AI_STOP_REASON,
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def parse_dt(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 string into a naive datetime (timezone stripped)."""
    if not value:
        return None
    try:
        s = re.sub(r"[+-]\d{2}:\d{2}$", "", str(value).replace("Z", ""))
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _exc(rule: str, severity: str, message: str, **evidence) -> Dict:
    """Build a raw exception dict (pre-enrichment)."""
    return {"rule": rule, "severity": severity, "message": message, "evidence": evidence}


# ── per-change evaluation ─────────────────────────────────────────────────────

def evaluate_change(
    change:        Dict,
    all_approvals: List[Dict],
    rules:         Rules,
) -> Dict:
    """
    Evaluate one change against the supplied rules.

    Pass/fail is fully deterministic and driven only by `rules`.
    Boolean fields on Rules gate whether each rule fires at all.
    """
    change_id    = change.get("change_id", "UNKNOWN")
    requester    = change.get("requester_id", "")
    user_type    = change.get("user_type", "employee").lower()
    is_emergency = bool(change.get("is_emergency", False))

    # Config from validated Rules object (not from policy dict)
    allowed_titles   = rules.allowed_approver_titles
    emergency_window = rules.emergency_grace_minutes
    high_risk_min    = rules.high_risk_min_distinct_approvals

    change_approvals = [a for a in all_approvals if a.get("change_id") == change_id]
    approved         = [a for a in change_approvals if a.get("status", "").upper() == "APPROVED"]

    rule_results:   List[Dict] = []
    raw_exceptions: List[Dict] = []

    def record(rule: str, passed: bool, exc: Optional[Dict] = None) -> None:
        rule_results.append({"rule": rule, "passed": passed})
        if not passed and exc:
            raw_exceptions.append(exc)

    # 1. ticket_id required ─────────────────────────────────────────────────
    if rules.require_ticket_id:
        ticket_id  = change.get("ticket_id")
        has_ticket = bool(ticket_id and str(ticket_id).strip())
        record(
            "ticket_id_required", has_ticket,
            _exc("ticket_id_required", "HIGH", "Missing or empty ticket_id",
                 change=change) if not has_ticket else None,
        )

    # 2. approval exists and APPROVED ───────────────────────────────────────
    if rules.require_approved_outcome:
        has_approval = len(approved) > 0
        record(
            "approval_exists", has_approval,
            _exc("approval_exists", "CRITICAL", "No APPROVED approval found",
                 change=change, all_approvals_for_change=change_approvals)
            if not has_approval else None,
        )

    # Rules 3-6 are only meaningful when approved approvals exist
    if approved:

        # 3. approver title allowed (always checked — no toggle in schema) ──
        bad_title = [a for a in approved if a.get("approver_title") not in allowed_titles]
        record(
            "approver_title_allowed", not bad_title,
            _exc("approver_title_allowed", "HIGH",
                 f"Approver(s) have unauthorized title(s): "
                 f"{[a.get('approver_title') for a in bad_title]}",
                 change=change, invalid_approvals=bad_title,
                 allowed_titles=allowed_titles) if bad_title else None,
        )

        # 4. no self-approval ───────────────────────────────────────────────
        if rules.no_self_approval:
            self_approved = [a for a in approved if a.get("approver_id") == requester]
            record(
                "no_self_approval", not self_approved,
                _exc("no_self_approval", "CRITICAL", "Requester approved their own change",
                     change=change, self_approvals=self_approved) if self_approved else None,
            )

        # 5. approval timing ────────────────────────────────────────────────
        if rules.approval_must_be_before_change:
            change_time       = parse_dt(change.get("timestamp"))
            timing_violations = []

            if change_time:
                for appr in approved:
                    appr_time = parse_dt(appr.get("timestamp"))
                    if appr_time and appr_time > change_time:
                        minutes_late = (appr_time - change_time).total_seconds() / 60
                        if is_emergency and minutes_late <= emergency_window:
                            continue  # permitted emergency post-approval
                        timing_violations.append(
                            {"approval": appr, "minutes_after_change": round(minutes_late, 1)}
                        )

            record(
                "approval_timing", not timing_violations,
                _exc("approval_timing", "HIGH",
                     "Approval(s) recorded after the change outside the emergency window",
                     change=change, violations=timing_violations,
                     emergency_window_minutes=emergency_window)
                if timing_violations else None,
            )

        # 6. high-risk requires N distinct approvers (always checked) ───────
        if _is_high_risk(change):
            distinct = len({a.get("approver_id") for a in approved})
            ok       = distinct >= high_risk_min
            record(
                "high_risk_two_approvers", ok,
                _exc("high_risk_two_approvers", "HIGH",
                     f"High-risk change needs {high_risk_min} distinct approvers; "
                     f"found {distinct}",
                     change=change, approved_approvals=approved) if not ok else None,
            )

    # 7. contractor requires expiry_date ────────────────────────────────────
    if user_type == "contractor" and rules.contractor_requires_expiry:
        has_expiry = bool(change.get("expiry_date", ""))
        record(
            "contractor_expiry", has_expiry,
            _exc("contractor_expiry", "MEDIUM",
                 "Contractor access grant is missing expiry_date",
                 change=change) if not has_expiry else None,
        )

    # Enrich each exception with risk scoring + AI triage fields
    exceptions   = [_enrich_exception(e, change) for e in raw_exceptions]
    passed       = all(r["passed"] for r in rule_results)
    needs_human  = any(e["escalated_to_human_queue"] for e in exceptions)

    return {
        "change_id":          change_id,
        "passed":             passed,
        "needs_human_review": needs_human,
        "rule_results":       rule_results,
        "exceptions":         exceptions,
    }


# ── full evaluation run ───────────────────────────────────────────────────────

def run_evaluation(
    policy:               Dict,
    changes:              List[Dict],
    approvals:            List[Dict],
    rules:                Rules,
    rules_source:         str,
    rules_parse_warnings: List[str],
    engine_version:       Optional[str]   = None,
    policy_raw_bytes:     Optional[bytes] = None,
) -> Dict:
    """
    Evaluate all changes and return the full structured audit response.

    The `rules` object is the sole source of truth for evaluation configuration.
    `policy` is retained for archiving and hashing only.
    """

    # ── run metadata ────────────────────────────────────────────────────────
    run_id           = str(uuid.uuid4())
    generated_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if policy_raw_bytes is not None:
        policy_hash = hashlib.sha256(policy_raw_bytes).hexdigest()
    else:
        canonical   = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        policy_hash = hashlib.sha256(canonical).hexdigest()

    run_meta = {
        "run_id":             run_id,
        "generated_at_utc":   generated_at_utc,
        "engine_version":     engine_version or ENGINE_VERSION,
        "policy_hash_sha256": policy_hash,
    }

    rules_dict            = rules.model_dump()
    rules_warnings_clean  = rules_parse_warnings or []

    # ── evaluate ────────────────────────────────────────────────────────────
    change_results: List[Dict] = []
    all_exceptions: List[Dict] = []

    for change in changes:
        result = evaluate_change(change, approvals, rules)
        change_results.append(result)
        all_exceptions.extend(result["exceptions"])

    # ── build human_queue ────────────────────────────────────────────────────
    human_queue: List[Dict] = []
    for r in change_results:
        if not r["needs_human_review"]:
            continue
        escalated = [e for e in r["exceptions"] if e["escalated_to_human_queue"]]
        max_risk  = max(
            (e["risk_level"] for e in escalated),
            key=lambda x: _RISK_NUM.get(x, 0),
            default="HIGH",
        )
        human_queue.append({
            "change_id":    r["change_id"],
            "risk_level":   max_risk,
            "failed_rules": [e["rule"] for e in escalated],
            "prompt":       HUMAN_QUEUE_PROMPT,
        })

    # ── summary ─────────────────────────────────────────────────────────────
    total        = len(changes)
    passed_count = sum(1 for r in change_results if r["passed"])
    risk_counts  = Counter(e["risk_level"] for e in all_exceptions)

    summary = {
        "total_changes":    total,
        "passed":           passed_count,
        "failed":           total - passed_count,
        "exceptions_count": len(all_exceptions),
        "human_queue_count": len(human_queue),
        "exceptions_by_risk_level": {
            "CRITICAL": risk_counts.get("CRITICAL", 0),
            "HIGH":     risk_counts.get("HIGH",     0),
            "MEDIUM":   risk_counts.get("MEDIUM",   0),
            "LOW":      risk_counts.get("LOW",      0),
        },
    }

    evidence_packet = {
        "run_metadata": {
            **run_meta,
            "rules_used":           rules_dict,
            "rules_source":         rules_source,
            "rules_parse_warnings": rules_warnings_clean,
        },
        "policy_applied": policy,
        "access_changes": changes,
        "approvals":      approvals,
        "change_results": change_results,
    }

    memo_md = _build_memo(summary, change_results, all_exceptions, human_queue, rules_source)

    return {
        **run_meta,
        "rules_used":           rules_dict,
        "rules_source":         rules_source,
        "rules_parse_warnings": rules_warnings_clean,
        "summary":              summary,
        "results":              change_results,
        "exceptions":           all_exceptions,
        "human_queue":          human_queue,
        "evidence_packet":      evidence_packet,
        "memo_md":              memo_md,
    }


# ── memo generator ────────────────────────────────────────────────────────────

def _build_memo(
    summary:      Dict,
    results:      List[Dict],
    exceptions:   List[Dict],
    human_queue:  List[Dict],
    rules_source: str = "static_default",
) -> str:
    rbl = summary["exceptions_by_risk_level"]
    lines = [
        "# Access Control Audit Memo",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total changes evaluated | {summary['total_changes']} |",
        f"| Passed | {summary['passed']} |",
        f"| Failed | {summary['failed']} |",
        f"| Total exceptions | {summary['exceptions_count']} |",
        f"| Changes queued for human review | {summary['human_queue_count']} |",
        f"| Rules source | `{rules_source}` |",
        "",
        "### Exceptions by Risk Level",
        "",
        "| Risk Level | Count |",
        "|------------|-------|",
        f"| CRITICAL | {rbl['CRITICAL']} |",
        f"| HIGH     | {rbl['HIGH']}     |",
        f"| MEDIUM   | {rbl['MEDIUM']}   |",
        f"| LOW      | {rbl['LOW']}      |",
        "",
        "## Exceptions",
        "",
    ]

    if not exceptions:
        lines.append("_No exceptions — all changes passed._")
    else:
        sorted_exc = sorted(exceptions, key=lambda e: _SEV_ORDER.get(e["risk_level"], 9))
        for exc in sorted_exc:
            lines.append(f"- **[{exc['risk_level']}]** `{exc['rule']}` — {exc['message']}")

    if human_queue:
        lines += [
            "",
            "## Human Review Queue",
            "",
            "The following changes require manual review before processing:",
            "",
        ]
        for item in human_queue:
            lines.append(
                f"- `{item['change_id']}` [{item['risk_level']}] — rules: {item['failed_rules']}"
            )
    else:
        lines += ["", "## Human Review Queue", "", "_Queue is empty._"]

    lines += ["", "---", "_Generated by Audit AI Monitor (deterministic evaluator)_"]
    return "\n".join(lines)
