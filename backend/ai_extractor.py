"""
ai_extractor.py — extract a validated Rules object from policy text.

Three-tier extraction (in order):
  1. AI (Anthropic Claude) — if ANTHROPIC_API_KEY is set and anthropic package installed
  2. Deterministic parser  — regex extraction of known policy phrases (no API needed)
  3. FALLBACK_RULES        — hardcoded safe defaults when neither above yields results

Returns (rules, rules_source, parse_warnings).

rules_source values:
  "ai_extracted"       – tier 1 succeeded
  "parsed_from_policy" – tier 2 extracted at least one field
  "fallback_default"   – tier 3 (no extraction possible)

Tier 2 patterns recognised:
  allowed_approver_titles
    e.g. "Approver title must be one of: IT Security, Access Admin"
         "Allowed approver titles: Finance Manager, IT Security"
  high_risk_min_distinct_approvals
    e.g. "High-risk roles require TWO distinct approvals"
         "High-risk roles require 2 approvals"
    (supports digit strings and ONE/TWO/THREE/FOUR/FIVE)
  emergency_grace_minutes
    e.g. "within 30 minutes"
         "within 60 mins"
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from rules_schema import FALLBACK_RULES, Rules

# Soft dependency — graceful if not installed
try:
    import anthropic as _anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

_MODEL = "claude-haiku-4-5-20251001"

_SYSTEM_PROMPT = """\
You are a compliance rule extractor.

Given a policy document, extract rule configuration values and output ONLY a \
valid JSON object with this exact schema — no prose, no markdown fences:

{
  "allowed_approver_titles": ["string", ...],
  "high_risk_min_distinct_approvals": <integer 1-5>,
  "emergency_grace_minutes": <integer 0-240>,
  "require_ticket_id": <boolean>,
  "require_approved_outcome": <boolean>,
  "no_self_approval": <boolean>,
  "approval_must_be_before_change": <boolean>,
  "contractor_requires_expiry": <boolean>,
  "parse_warnings": ["string", ...]
}

Field guidance:
- allowed_approver_titles: job titles explicitly permitted to approve changes.
- high_risk_min_distinct_approvals: minimum distinct approvers for high-risk changes.
- emergency_grace_minutes: how many minutes after a change an emergency approval \
is still valid.
- approval_must_be_before_change: controls whether the system enforces approval \
timing at all. Set to TRUE whenever the policy mentions ANY timing requirement \
for approvals — including emergency windows such as "within 10 minutes of the \
change." The emergency_grace_minutes field captures the permitted post-change \
window; this field must be TRUE for that window to be enforced. Setting this to \
false disables all timing enforcement entirely. Only set FALSE if the policy \
explicitly states there are no timing requirements whatsoever.
- Boolean fields: true = the policy requires this control. For all boolean \
fields, the conservative default is TRUE — setting a field to false disables \
a safety control entirely, which is never the safe choice. Only set a boolean \
to false if the policy explicitly states that control does not apply.
- require_approved_outcome: set TRUE whenever the policy indicates that approvals \
are required or mandatory in any form. Only set FALSE if the policy explicitly \
states no approval is needed.
- parse_warnings: note any ambiguities or fields not explicitly addressed; \
empty list if none.
- If the policy is silent or ambiguous on a field, choose a conservative default \
and add a parse_warning for that field.

Output ONLY the JSON object.\
"""

# Word-to-integer mapping for tier-2 parser
_WORD_TO_NUM: Dict[str, int] = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
}


# ── tier 2: deterministic regex parser ────────────────────────────────────────

def parse_rules_from_policy_text(policy_text: str) -> Tuple[dict, List[str]]:
    """
    Deterministic regex extraction of rule configuration from policy prose.

    Scans `policy_text` for recognised phrases and returns:
        (extracted_fields, warnings)

    `extracted_fields` contains only the fields that were found; callers merge
    with FALLBACK_RULES defaults for any missing fields.
    `warnings` contains one human-readable message per extracted field describing
    what was found and from which snippet.

    Does NOT import or validate against the Rules schema — returns a plain dict.
    """
    extracted: dict = {}
    warnings: List[str] = []

    # ── allowed_approver_titles ──────────────────────────────────────────────
    # Matches:  "Approver title must be one of: X, Y"
    #           "Allowed approver titles: X, Y"
    m = re.search(
        r"(?:approver\s+titles?\s+must\s+be\s+one\s+of"
        r"|allowed\s+approver\s+titles?)"
        r"\s*[:\-]\s*(.+?)(?:\n|$)",
        policy_text,
        re.IGNORECASE,
    )
    if m:
        snippet = m.group(0).strip()
        titles = [t.strip() for t in m.group(1).split(",") if t.strip()]
        if titles:
            extracted["allowed_approver_titles"] = titles
            warnings.append(
                f"Extracted allowed_approver_titles={titles!r} "
                f"from phrase {snippet!r}"
            )

    # ── high_risk_min_distinct_approvals ─────────────────────────────────────
    # Matches:  "High-risk roles require TWO distinct approvals"
    #           "High-risk roles require 2 approvals"
    m = re.search(
        r"high[\-\s]risk\s+roles?\s+require\s+(\w+)\s+(?:distinct\s+)?approvals?",
        policy_text,
        re.IGNORECASE,
    )
    if m:
        raw = m.group(1)
        snippet = m.group(0).strip()
        val: Optional[int]
        try:
            val = int(raw)
        except ValueError:
            val = _WORD_TO_NUM.get(raw.lower())
        if val is not None and 1 <= val <= 5:
            extracted["high_risk_min_distinct_approvals"] = val
            warnings.append(
                f"Extracted high_risk_min_distinct_approvals={val} "
                f"from phrase {snippet!r}"
            )

    # ── emergency_grace_minutes ───────────────────────────────────────────────
    # Matches:  "within 30 minutes"  /  "within 60 mins"
    m = re.search(
        r"within\s+(\d+)\s+min(?:utes?)?",
        policy_text,
        re.IGNORECASE,
    )
    if m:
        val = int(m.group(1))
        snippet = m.group(0).strip()
        if 0 <= val <= 240:
            extracted["emergency_grace_minutes"] = val
            warnings.append(
                f"Extracted emergency_grace_minutes={val} "
                f"from phrase {snippet!r}"
            )

    return extracted, warnings


# ── public entry point ─────────────────────────────────────────────────────────

def extract_rules_from_policy(policy_text: str) -> Tuple[Rules, str, List[str]]:
    """
    Extract a validated Rules object from policy_text using the three-tier pipeline.

    Returns:
        (rules, rules_source, parse_warnings)
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    collected_warnings: List[str] = []

    # ── Tier 1: AI extraction ─────────────────────────────────────────────────
    if api_key and _ANTHROPIC_AVAILABLE:
        try:
            client = _anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model=_MODEL,
                max_tokens=512,
                system=_SYSTEM_PROMPT,
                messages=[
                    {
                        "role": "user",
                        "content": f"Extract rules from this policy:\n\n{policy_text}",
                    },
                ],
            )
            raw = response.content[0].text or ""
            # Strip markdown fences if present (```json ... ``` or ``` ... ```)
            raw = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
            raw = re.sub(r"\s*```$", "", raw.strip())
            data: dict = json.loads(raw)
            parse_warnings: List[str] = data.pop("parse_warnings", [])
            if not isinstance(parse_warnings, list):
                parse_warnings = [str(parse_warnings)]
            rules = Rules(**data)
            return rules, "ai_extracted", parse_warnings

        except Exception as exc:
            collected_warnings.append(
                f"AI extraction failed ({type(exc).__name__}: {exc}); "
                "trying deterministic policy parser."
            )

    elif not api_key:
        collected_warnings.append(
            "ANTHROPIC_API_KEY is not set; trying deterministic policy parser."
        )
    else:
        # api_key present but anthropic package missing
        collected_warnings.append(
            "The 'anthropic' package is not installed (run: pip install anthropic); "
            "trying deterministic policy parser."
        )

    # ── Tier 2: deterministic regex parser ────────────────────────────────────
    extracted, parse_warnings = parse_rules_from_policy_text(policy_text)
    collected_warnings.extend(parse_warnings)

    if extracted:
        base = FALLBACK_RULES.model_dump()
        base.update(extracted)
        try:
            rules = Rules(**base)
            return rules, "parsed_from_policy", collected_warnings
        except Exception as exc:
            collected_warnings.append(
                f"Deterministic parse result failed schema validation ({exc}); "
                "using fallback_default."
            )
    else:
        collected_warnings.append(
            "No policy fields matched by deterministic parser; using fallback_default."
        )

    # ── Tier 3: hardcoded fallback ────────────────────────────────────────────
    return FALLBACK_RULES, "fallback_default", collected_warnings
