# Audit AI Monitor — Project Guide

## What this is
Deterministic access-change compliance evaluator. Accepts a policy file, a list of access changes, and a list of approvals. Returns a structured audit report with per-change pass/fail, exceptions with embedded evidence, a human review queue, and a Markdown memo.

No AI model is involved in evaluation. All rule logic is explicit and auditable Python.

---

## File map

```
audit-ai-monitor/
  CLAUDE.md                     ← this file
  backend/
    main.py                     ← FastAPI app; /health, /policy_to_rules, /evaluate
    evaluator.py                ← ALL rule logic; imports only stdlib + rules_schema
    rules_schema.py             ← Pydantic Rules model + FALLBACK_RULES + rules_from_policy_dict()
    ai_extractor.py             ← extract_rules_from_policy(); OpenAI call + graceful fallback
    parsers.py                  ← File format adapters: .md, .csv, .json → dicts/lists
    smoke_test.py               ← Direct evaluator test (no HTTP); enforces all invariants
    requirements.txt
    README.md
    sample_data/
      policy.md                 ← Authoritative policy (MD is canonical; JSON deleted)
      access_changes.csv        ← 9 sample changes with intentional violations
      approvals.csv             ← Corresponding approvals
      rules_default.json        ← Bundled rule config (validated by Rules pydantic model)
```

---

## How to run

```bash
cd backend

# Install
pip install -r requirements.txt

# Smoke test (no server needed)
python smoke_test.py

# Server
uvicorn main:app --reload --port 8000

# Curl test — bundled defaults (path 3)
curl -s -X POST http://localhost:8000/evaluate \
  -F "policy=@sample_data/policy.md;type=text/markdown" \
  -F "access_changes=@sample_data/access_changes.csv;type=text/csv" \
  -F "approvals=@sample_data/approvals.csv;type=text/csv" \
  | python -m json.tool

# Curl test — approved rules config (path 1)
curl -s -X POST http://localhost:8000/evaluate \
  -F "policy=@sample_data/policy.md;type=text/markdown" \
  -F "access_changes=@sample_data/access_changes.csv;type=text/csv" \
  -F "approvals=@sample_data/approvals.csv;type=text/csv" \
  -F "rules_config=@sample_data/rules_default.json;type=application/json" \
  | python -m json.tool
```

### Rules precedence for /evaluate

| Priority | Condition | `rules_source` |
|----------|-----------|----------------|
| 1 (highest) | `rules_config` file uploaded | `approved_config` |
| 2 | `use_ai_rules=true` + API key set | `ai_extracted` |
| 2 | `use_ai_rules=true` + no API key | `fallback_default` |
| 3 (default) | neither of the above | `bundled_default_config` |

---

## Rules (evaluator.py)

| # | Rule ID | Condition |
|---|---------|-----------|
| 1 | `ticket_id_required` | change must have a non-empty `ticket_id` |
| 2 | `approval_exists` | at least one approval with `status == APPROVED` |
| 3 | `approver_title_allowed` | every approver's title must be in `allowed_approver_titles` |
| 4 | `no_self_approval` | `approver_id` must differ from `requester_id` |
| 5 | `approval_timing` | approval timestamp ≤ change timestamp; emergency allows within window |
| 6 | `high_risk_two_approvers` | `is_high_risk_role=true` requires ≥ 2 distinct approvers |
| 7 | `contractor_expiry` | `user_type=contractor` requires `expiry_date` |

Rules 3–6 are **skipped** when there are no approved approvals (rule 2 already fires).

---

## Risk scoring (non-negotiable)

```
CRITICAL  →  (approval_exists OR no_self_approval fails) AND is_high_risk_role == true
HIGH      →  approval_exists, no_self_approval, approver_title_allowed,
             high_risk_two_approvers, OR approval_timing on a high-risk change
MEDIUM    →  ticket_id_required, contractor_expiry, OR approval_timing on non-high-risk
LOW       →  anything else (should not normally occur)
```

**`is_high_risk_role` (boolean field on the change) is the CRITICAL gate.**
Falling back to `risk_level == "high"` is only used when `is_high_risk_role` is absent.

Escalated to `human_queue` if and only if: `risk_level in {HIGH, CRITICAL}`.

---

## Hard invariants — smoke_test.py enforces both

1. **`severity == risk_level`** for every exception object.
   `severity` exists for backward compatibility; it must always be overwritten to match `risk_level` in `_enrich_exception()`.

2. **`escalated_count == count(HIGH + CRITICAL exceptions)`**
   Every HIGH/CRITICAL exception must have `escalated_to_human_queue = true`, and no MEDIUM/LOW exception may be escalated.

---

## AI triage summary rules (ai_triage_summary field)

- **One factual sentence** describing what the rule found (from `_TRIAGE_DESC`).
- **One escalation sentence** stating the `risk_level` and whether it was escalated, using `_escalation_sentence()`.
- **Never**: assert materiality, call something a "control weakness", or decide whether fraud occurred.
- **Never**: vary the stop reason. `ai_stop_reason` is always the fixed string: `"Materiality/severity assessment and escalation decisions require human judgment."`

---

## Module boundaries

| Module | May import | Must NOT import |
|--------|-----------|-----------------|
| `rules_schema.py` | `pydantic`, stdlib | `fastapi`, `evaluator`, `parsers`, `ai_extractor` |
| `ai_extractor.py` | `rules_schema`, `openai` (soft), stdlib | `fastapi`, `evaluator`, `parsers` |
| `evaluator.py` | `rules_schema`, stdlib | `fastapi`, `parsers`, `ai_extractor` |
| `parsers.py` | stdlib only (`csv`, `io`, `json`) | everything else |
| `main.py` | `fastapi`, `evaluator`, `parsers`, `rules_schema`, `ai_extractor` | — |
| `smoke_test.py` | `evaluator`, `parsers`, `rules_schema`, `ai_extractor`, stdlib | `fastapi` |

**Key invariant**: The LLM (in `ai_extractor.py`) never touches `evaluator.py`.
It only produces a `Rules` object.  All pass/fail logic lives exclusively in `evaluator.py`.

---

## Sample data

`sample_data/` CSV and MD files are **authoritative**. JSON files were deleted.
Do not add a JSON fallback curl example to README — it implies the JSON files still exist.

### Violation map

| Change | Violation | Risk level | Escalated |
|--------|-----------|-----------|-----------|
| CHG-001 | none (clean pass) | — | no |
| CHG-002 | `ticket_id` is null | MEDIUM | no |
| CHG-003 | no approvals + `is_high_risk_role=true` | CRITICAL | yes |
| CHG-004 | approver title = "Manager" | HIGH | yes |
| CHG-005 | self-approval (low-risk change) | HIGH | yes |
| CHG-006 | approval 65 min late, non-emergency | MEDIUM | no |
| CHG-007 | high-risk, only 1 approver | HIGH | yes |
| CHG-008 | contractor missing `expiry_date` | MEDIUM | no |
| CHG-009 | none (emergency + 2 approvers in window) | — | no |
