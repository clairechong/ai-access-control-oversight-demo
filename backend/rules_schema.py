"""
rules_schema.py — Pydantic models for the validated rules object and JSON request schema.

Used by:
  ai_extractor.py  – validates LLM output before it reaches the evaluator
  evaluator.py     – evaluate_change() and run_evaluation() receive a Rules instance
  main.py          – builds Rules from policy dict; imports EvaluateJsonRequest
  smoke_test.py    – imports EvaluateJsonRequest for alias validation
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Rules(BaseModel):
    allowed_approver_titles: List[str] = Field(
        default_factory=lambda: ["IT Security", "Access Admin"],
        description="Job titles permitted to approve access changes.",
    )
    high_risk_min_distinct_approvals: int = Field(
        default=2,
        description="Minimum distinct approvers required for high-risk changes (1–5).",
    )
    emergency_grace_minutes: int = Field(
        default=30,
        description="Minutes after a change that emergency approvals are still valid (0–240).",
    )
    require_ticket_id: bool = Field(
        default=True,
        description="Change must reference a ticket identifier.",
    )
    require_approved_outcome: bool = Field(
        default=True,
        description="At least one APPROVED approval must exist.",
    )
    no_self_approval: bool = Field(
        default=True,
        description="Requester may not approve their own change.",
    )
    approval_must_be_before_change: bool = Field(
        default=True,
        description="Approval must precede the change (emergency grace applies).",
    )
    contractor_requires_expiry: bool = Field(
        default=True,
        description="Contractor access grants must include an expiry date.",
    )

    @field_validator("allowed_approver_titles")
    @classmethod
    def titles_non_empty(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("allowed_approver_titles must not be empty")
        return v

    @field_validator("high_risk_min_distinct_approvals")
    @classmethod
    def approvals_in_range(cls, v: int) -> int:
        if not 1 <= v <= 5:
            raise ValueError("high_risk_min_distinct_approvals must be between 1 and 5")
        return v

    @field_validator("emergency_grace_minutes")
    @classmethod
    def grace_in_range(cls, v: int) -> int:
        if not 0 <= v <= 240:
            raise ValueError("emergency_grace_minutes must be between 0 and 240")
        return v


# Singleton used when AI extraction fails or no API key is present.
FALLBACK_RULES = Rules()


class PolicyToRulesRequest(BaseModel):
    """Request schema for POST /policy_to_rules (JSON body)."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "policy_text": (
                    "Approver title must be one of: IT Security, Access Admin\n"
                    "High-risk roles require TWO distinct approvals\n"
                    "Emergency approvals must be submitted within 30 minutes"
                )
            }
        }
    )

    policy_text: str = Field(..., description="Raw policy text (Markdown or prose).")


class EvaluateJsonRequest(BaseModel):
    """Request schema for POST /evaluate_json.

    Preferred key names use the *_csv suffix (clearer for Base44 / UI callers).
    The canonical field names (access_changes, approvals) are also accepted
    via populate_by_name so older clients keep working.

    Fields:
      policy_text          — raw policy file text (.md format); omit to use bundled defaults.
      access_changes_csv   — CSV text of change records (required).
      approvals_csv        — CSV text of approval records (required).
      rules_config         — pre-validated Rules object dict; takes highest precedence.
      use_ai_rules         — if true (and rules_config absent), call AI extraction.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "policy_text": (
                    "## allowed_approver_titles\n"
                    "- IT Security\n"
                    "- Access Admin\n\n"
                    "## high_risk_min_approvers\n"
                    "2\n\n"
                    "## emergency_window_minutes\n"
                    "30"
                ),
                "access_changes_csv": (
                    "change_id,ticket_id,requester_id,user_id,user_type,"
                    "risk_level,is_high_risk_role,change_type,timestamp,is_emergency,expiry_date\n"
                    "CHG-001,TICK-1001,USR-101,USR-200,employee,low,,add_role,"
                    "2024-01-15T10:00:00,false,"
                ),
                "approvals_csv": (
                    "approval_id,change_id,approver_id,approver_title,status,timestamp\n"
                    "APR-001,CHG-001,USR-999,IT Security,APPROVED,2024-01-15T09:30:00"
                ),
                "rules_config": None,
                "use_ai_rules": False,
            }
        },
    )

    policy_text: str = ""
    access_changes: str = Field(..., alias="access_changes_csv")
    approvals: str = Field(..., alias="approvals_csv")
    rules_config: Optional[dict] = None
    use_ai_rules: bool = False


def rules_from_policy_dict(policy: Dict[str, Any]) -> Rules:
    """Build a Rules object from the parsed policy dict (static_default path).

    Maps legacy policy key names to Rules field names.  All boolean controls
    default to True (conservative) since the policy dict only carries numeric
    and list configuration — it does not encode enable/disable toggles.
    """
    return Rules(
        allowed_approver_titles=policy.get(
            "allowed_approver_titles",
            FALLBACK_RULES.allowed_approver_titles,
        ),
        high_risk_min_distinct_approvals=policy.get(
            # accept both the legacy key and the new canonical name
            "high_risk_min_approvers",
            policy.get(
                "high_risk_min_distinct_approvals",
                FALLBACK_RULES.high_risk_min_distinct_approvals,
            ),
        ),
        emergency_grace_minutes=policy.get(
            "emergency_window_minutes",
            policy.get(
                "emergency_grace_minutes",
                FALLBACK_RULES.emergency_grace_minutes,
            ),
        ),
        require_ticket_id=True,
        require_approved_outcome=True,
        no_self_approval=True,
        approval_must_be_before_change=True,
        contractor_requires_expiry=True,
    )
