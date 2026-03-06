# Audit AI Monitor

A prototype continuous control monitor that evaluates access changes against compliance policy, flags exceptions for human review, and generates audit evidence — expanding human oversight without replacing human judgment.

## Live demo

**UI:** https://control-scan-pro.base44.app

> The UI requires the backend to be running and accessible via a public URL (e.g. ngrok).
> Start the backend locally and run `ngrok http 8000`, then configure the Base44 app to point to the ngrok URL.

## Architecture

**Frontend** — Base44 interface for demo workflow

**Backend** — FastAPI service providing evaluation and policy translation

**Core endpoints:**

| Endpoint | Purpose |
|----------|---------|
| `GET /sample_payload` | Initializes the demo environment |
| `POST /policy_to_rules` | Translates policy text into structured rule configuration |
| `POST /evaluate_json` | Evaluates access changes against approved rules |

## Design Philosophy

The goal of this system is not to automate human judgment.

Instead it expands what humans can oversee by enabling
continuous evaluation of the full population of access activity.

AI assists with interpretation and triage,
while governance and accountability remain human responsibilities.

## Demo Workflow

1. Load Demo Environment
2. Run baseline evaluation against existing rules
3. Review flagged exceptions and AI triage summaries
4. Introduce new policy requirement
5. Generate proposed rule configuration
6. Approve rule configuration
7. Re-run evaluation
8. Observe previously valid change now failing
9. Generate audit memo and evidence output

## Rules enforced

| # | Rule | Risk level |
|---|------|------------|
| 1 | `ticket_id` must be present and non-empty | MEDIUM |
| 2 | At least one `APPROVED` approval must exist | CRITICAL (if `is_high_risk_role`), else HIGH |
| 3 | Every approver's `approver_title` must be in the allowed list | HIGH |
| 4 | `approver_id` must not equal `requester_id` (no self-approval) | CRITICAL (if `is_high_risk_role`), else HIGH |
| 5 | Approval must precede the change; emergency: allowed within 30 min after | HIGH (if `is_high_risk_role`), else MEDIUM |
| 6 | `is_high_risk_role=true` requires ≥ 2 distinct approvers | HIGH |
| 7 | `user_type=contractor` must include `expiry_date` | MEDIUM |

Escalated to `human_queue` when risk level is HIGH or CRITICAL.

## Setup

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Interactive docs: http://localhost:8000/docs

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| GET | `/sample_payload` | Returns a pre-filled /evaluate_json request body used by the UI "Load Demo Environment" action. |
| GET | `/ui_contract` | Frontend contract — endpoint keys, field types, and precedence rules |
| GET | `/demo_policy_examples` | Three minimal policy text snippets for demo and testing |
| POST | `/policy_to_rules` | Extract a validated Rules object from policy text |
| POST | `/evaluate` | Multipart upload: `policy`, `access_changes`, `approvals` (+ optional `rules_config`) |
| POST | `/evaluate_json` | JSON-body alternative to `/evaluate`; preferred for Base44 and UI clients |

### GET /sample_payload

Returns a ready-to-use JSON object populated from sample_data/. Used by the UI's "Load Demo Environment" action to initialize the demo dataset and baseline rule configuration.

### GET /ui_contract

Returns the stable request/response contract for UI clients — endpoint paths, required and
optional field names with types, field aliases, and rules-source precedence notes. Use this
to keep the frontend in sync without reading source code.

Key sections in the response:
- **endpoints** — `sample_payload`, `evaluate_json`, `policy_to_rules` with their request and response keys
- **precedence_notes** — resolution order and the recommended AI flow:
  `POST /policy_to_rules` → review `rules` object → pass as `rules_config` in `POST /evaluate_json`

### GET /demo_policy_examples

Returns three minimal policy text strings, each targeting a specific tier-2 (deterministic)
parser extraction. POST any value as `policy_text` to `/policy_to_rules` to see
`rules_source: "parsed_from_policy"` in action.

| Key | What it demonstrates |
|-----|----------------------|
| `tighten_emergency_window` | Sets `emergency_grace_minutes=10` |
| `require_three_approvals` | Sets `high_risk_min_distinct_approvals=3` |
| `expand_approver_titles` | Adds Finance Manager to `allowed_approver_titles` |

### POST /policy_to_rules

Accepts a JSON body: `{ "policy_text": "..." }`

Uses a **three-tier pipeline** — no API key required for tiers 2 and 3:

| Tier | Condition | `rules_source` |
|------|-----------|----------------|
| 1 | `OPENAI_API_KEY` set and extraction succeeds | `ai_extracted` |
| 2 | Recognised phrases found in policy text | `parsed_from_policy` |
| 3 | Nothing extracted | `fallback_default` |

Tier-2 phrases recognised:

| Field | Example phrase |
|-------|---------------|
| `allowed_approver_titles` | `"Approver title must be one of: IT Security, Finance Manager"` |
| `high_risk_min_distinct_approvals` | `"High-risk roles require TWO distinct approvals"` |
| `emergency_grace_minutes` | `"within 30 minutes"` |

Returns `rules`, `rules_source`, `policy_hash_sha256`, `generated_at_utc`, and `parse_warnings`.
`parse_warnings` includes one message per extracted field showing the matched snippet.

### POST /evaluate (multipart)

```
policy          .md / .csv / .json   required
access_changes  .csv / .json         required
approvals       .csv / .json         required
rules_config    .json                optional — takes highest precedence
use_ai_rules    bool (form field)    optional — default false
```

### POST /evaluate_json (JSON body — preferred for Base44)

```json
{
  "policy_text":        "## allowed_approver_titles\n- IT Security\n...",
  "access_changes_csv": "change_id,ticket_id,...\nCHG-001,...",
  "approvals_csv":      "approval_id,change_id,...\nAPR-001,...",
  "rules_config":       null,
  "use_ai_rules":       false
}
```

Field aliases: `access_changes` is accepted in place of `access_changes_csv`, and `approvals`
in place of `approvals_csv`.

**Rules precedence** (same for both evaluate endpoints):

| Priority | Condition | `rules_source` |
|----------|-----------|----------------|
| 1 (highest) | `rules_config` provided | `approved_config` |
| 2 | `use_ai_rules=true` + API key set | `ai_extracted` |
| 2 | `use_ai_rules=true` + no API key | `fallback_default` |
| 3 (default) | neither | `bundled_default_config` |

## Response shape

Both `/evaluate` and `/evaluate_json` return the same structure:

```json
{
  "run_id":               "uuid-v4",
  "generated_at_utc":    "2024-01-15T10:00:00Z",
  "engine_version":      "mvp-deterministic-1",
  "policy_hash_sha256":  "sha256hex",
  "rules_used":          { ... },
  "rules_source":        "bundled_default_config",
  "rules_parse_warnings": [],
  "summary": {
    "total_changes": 9, "passed": 2, "failed": 7,
    "exceptions_count": 7, "human_queue_count": 4,
    "exceptions_by_risk_level": { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 3, "LOW": 0 }
  },
  "results":         [ { "change_id": "CHG-001", "passed": true, "rule_results": [...], "exceptions": [...] } ],
  "exceptions":      [ { "rule": "...", "severity": "HIGH", "risk_level": "HIGH",
                         "escalated_to_human_queue": true,
                         "ai_triage_summary": "...", "ai_stop_reason": "...",
                         "evidence": { ... } } ],
  "human_queue":     [ { "change_id": "CHG-003", "risk_level": "CRITICAL", "failed_rules": [...] } ],
  "evidence_packet": { "run_metadata": {}, "policy_applied": {}, "access_changes": [], "approvals": [], "change_results": [] },
  "memo_md":         "# Access Control Audit Memo\n..."
}
```

## Curl examples

```bash
# Health check
curl http://localhost:8000/health

# Frontend contract (field names, types, precedence notes)
curl -s http://localhost:8000/ui_contract | python -m json.tool

# Demo policy snippets (paste any value into POST /policy_to_rules)
curl -s http://localhost:8000/demo_policy_examples | python -m json.tool

# Load sample payload (for Base44 / manual testing)
curl -s http://localhost:8000/sample_payload | python -m json.tool

# Evaluate via JSON body (Base44-style)
curl -s -X POST http://localhost:8000/evaluate_json \
  -H "Content-Type: application/json" \
  -d "$(curl -s http://localhost:8000/sample_payload)" \
  | python -m json.tool

# Evaluate via multipart upload
curl -s -X POST http://localhost:8000/evaluate \
  -F "policy=@backend/sample_data/policy.md;type=text/markdown" \
  -F "access_changes=@backend/sample_data/access_changes.csv;type=text/csv" \
  -F "approvals=@backend/sample_data/approvals.csv;type=text/csv" \
  | python -m json.tool

# Evaluate with approved rules config (multipart)
curl -s -X POST http://localhost:8000/evaluate \
  -F "policy=@backend/sample_data/policy.md;type=text/markdown" \
  -F "access_changes=@backend/sample_data/access_changes.csv;type=text/csv" \
  -F "approvals=@backend/sample_data/approvals.csv;type=text/csv" \
  -F "rules_config=@backend/sample_data/rules_default.json;type=application/json" \
  | python -m json.tool

# Extract rules from policy text — tier-2 deterministic parser (no API key needed)
curl -s -X POST http://localhost:8000/policy_to_rules \
  -H "Content-Type: application/json" \
  -d "{\"policy_text\": \"Approver title must be one of: IT Security, Finance Manager\nHigh-risk roles require TWO distinct approvals\nwithin 30 minutes\"}" \
  | python -m json.tool
# -> rules_source: "parsed_from_policy", parse_warnings show extracted snippets

# Extract just the audit memo
curl -s -X POST http://localhost:8000/evaluate \
  -F "policy=@backend/sample_data/policy.md;type=text/markdown" \
  -F "access_changes=@backend/sample_data/access_changes.csv;type=text/csv" \
  -F "approvals=@backend/sample_data/approvals.csv;type=text/csv" \
  | python -c "import sys,json; print(json.load(sys.stdin)['memo_md'])"
```

## Sample data violations map

| Change | Intentional violation | Risk | Escalated |
|--------|-----------------------|------|-----------|
| CHG-001 | Clean pass | — | no |
| CHG-002 | `ticket_id` is null | MEDIUM | no |
| CHG-003 | No approvals + `is_high_risk_role=true` | CRITICAL | yes |
| CHG-004 | Approver title = "Manager" (not in allowed list) | HIGH | yes |
| CHG-005 | Requester approves their own change | HIGH | yes |
| CHG-006 | Approval arrives 65 min after non-emergency change | MEDIUM | no |
| CHG-007 | High-risk change with only 1 approver | HIGH | yes |
| CHG-008 | Contractor access missing `expiry_date` | MEDIUM | no |
| CHG-009 | Clean pass — emergency high-risk: 2 approvals within 30 min window | — | no |
