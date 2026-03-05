"""
Audit AI Monitor — FastAPI backend

Endpoints:
  GET  /health          – liveness check
  GET  /sample_payload  – pre-filled /evaluate_json body (Base44 "Load Sample Data")
  POST /policy_to_rules – extract validated Rules from policy text or file (AI or fallback)
  POST /evaluate        – multipart upload: policy, access_changes, approvals[, rules_config]
  POST /evaluate_json   – JSON body alternative to /evaluate (preferred for Base44)
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ai_extractor import extract_rules_from_policy
from evaluator import run_evaluation
from parsers import load_file, parse_csv, parse_policy_md
from rules_schema import EvaluateJsonRequest, PolicyToRulesRequest, Rules, rules_from_policy_dict

logger = logging.getLogger("audit_monitor")

BUNDLED_RULES_PATH = Path(__file__).parent / "sample_data" / "rules_default.json"
SAMPLE_DATA_DIR    = Path(__file__).parent / "sample_data"


def _load_bundled_rules() -> Rules:
    """Load and validate the bundled rules_default.json; return FALLBACK_RULES on any error."""
    from rules_schema import FALLBACK_RULES
    try:
        data = json.loads(BUNDLED_RULES_PATH.read_bytes())
        return Rules(**data)
    except Exception:
        return FALLBACK_RULES


def _resolve_rules(
    rules_config_dict: Optional[dict],
    use_ai_rules: bool,
    policy_text: str,
):
    """
    Apply rules-source precedence and return (rules, rules_source, rules_warnings).

    Priority:
      1. rules_config dict provided   → "approved_config"
      2. use_ai_rules=true            → "ai_extracted" | "fallback_default"
      3. default                      → "bundled_default_config"
    """
    if rules_config_dict is not None:
        try:
            rules = Rules(**rules_config_dict)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"'rules_config' is invalid: {exc}")
        return rules, "approved_config", []

    if use_ai_rules:
        rules, source, warnings = extract_rules_from_policy(policy_text)
        if source == "fallback_default" and not warnings:
            warnings = ["AI extraction unavailable; applied hardcoded fallback defaults."]
        return rules, source, warnings

    return _load_bundled_rules(), "bundled_default_config", []


app = FastAPI(
    title="Audit AI Monitor",
    description="Deterministic access-change compliance evaluator with AI-native policy parsing",
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── shared helper ─────────────────────────────────────────────────────────────

async def _load_upload(upload: UploadFile, label: str):
    """Read an uploaded file and dispatch to the correct parser by extension."""
    raw = await upload.read()
    if not raw:
        raise HTTPException(status_code=400, detail=f"'{label}' file is empty")
    try:
        return load_file(raw, upload.filename or ""), raw
    except Exception as exc:
        raise HTTPException(
            status_code=400, detail=f"'{label}' could not be parsed: {exc}"
        )


# ── endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", summary="Liveness check")
def health():
    return {"status": "ok"}


@app.get("/ui_contract", summary="Frontend contract — endpoint keys and precedence rules")
def ui_contract():
    """
    Describes the stable request/response contract for UI clients.

    Use this to reduce frontend drift: key names, field types, and precedence
    rules are all declared here so the UI can stay in sync without reading source code.

    Fields covered:
    - **endpoints** — path, method, request keys, and response keys for each UI-facing endpoint
    - **precedence_notes** — rules-source resolution order and the recommended AI flow
    """
    return JSONResponse({
        "endpoints": {
            "sample_payload": {
                "method": "GET",
                "path": "/sample_payload",
                "description": (
                    "Returns a pre-filled /evaluate_json request body "
                    "loaded from bundled sample data. Use for Load Sample Data."
                ),
            },
            "evaluate_json": {
                "method": "POST",
                "path": "/evaluate_json",
                "content_type": "application/json",
                "request_keys": {
                    "policy_text":        "string (optional) — raw policy Markdown; omit to use bundled defaults",
                    "access_changes_csv": "string (required) — CSV text of change records",
                    "approvals_csv":      "string (required) — CSV text of approval records",
                    "rules_config":       "object|null (optional) — pre-validated Rules dict; highest precedence",
                    "use_ai_rules":       "bool (optional, default false) — call AI extraction when no rules_config",
                },
                "key_aliases": {
                    "access_changes": "accepted in place of access_changes_csv",
                    "approvals":      "accepted in place of approvals_csv",
                },
            },
            "policy_to_rules": {
                "method": "POST",
                "path": "/policy_to_rules",
                "content_type": "application/json",
                "request_keys": {
                    "policy_text": "string (required) — raw policy text (Markdown or prose)",
                },
                "response_keys": {
                    "rules":              "object — validated Rules configuration",
                    "rules_source":       "string — 'ai_extracted' | 'parsed_from_policy' | 'fallback_default'",
                    "parse_warnings":     "array[string] — one message per extracted field or tier failure",
                    "policy_hash_sha256": "string — SHA-256 of policy_text bytes",
                    "generated_at_utc":   "string — ISO-8601 timestamp",
                },
            },
        },
        "precedence_notes": [
            "rules_config provided in /evaluate_json => rules_source='approved_config'; use_ai_rules is ignored",
            "use_ai_rules=true (no rules_config) => rules_source='ai_extracted' or 'fallback_default'",
            "neither => rules_source='bundled_default_config' (from bundled rules_default.json)",
            "recommended AI flow: POST /policy_to_rules -> review rules object -> pass as rules_config in /evaluate_json",
        ],
    })


@app.get("/demo_policy_examples", summary="Minimal policy text snippets for demo and testing")
def demo_policy_examples():
    """
    Returns three minimal policy text strings, each targeting a specific
    tier-2 (deterministic) parser extraction.

    POST any value directly to **POST /policy_to_rules** `policy_text` to see
    `rules_source: "parsed_from_policy"` and the extracted field in `parse_warnings`.

    Examples:
    - **tighten_emergency_window** — sets `emergency_grace_minutes=10`
    - **require_three_approvals** — sets `high_risk_min_distinct_approvals=3`
    - **expand_approver_titles** — sets `allowed_approver_titles` to include Finance Manager
    """
    return JSONResponse({
        "tighten_emergency_window": (
            "Approver title must be one of: IT Security, Access Admin\n"
            "High-risk roles require TWO approvals\n"
            "Emergency approvals must be submitted within 10 minutes"
        ),
        "require_three_approvals": (
            "Approver title must be one of: IT Security, Access Admin\n"
            "High-risk roles require THREE approvals"
        ),
        "expand_approver_titles": (
            "Approver title must be one of: IT Security, Access Admin, Finance Manager\n"
            "High-risk roles require TWO approvals\n"
            "Emergency approvals must be submitted within 30 minutes"
        ),
    })


@app.get(
    "/sample_payload",
    summary="Get a pre-filled /evaluate_json request body",
    response_description="JSON object ready to POST to /evaluate_json",
)
def sample_payload():
    """
    Returns a JSON object pre-populated with the bundled sample data, ready to
    paste into **POST /evaluate_json**.

    Intended for the **Load Sample Data** button in Base44 or any frontend.

    Response keys match the preferred /evaluate_json field names:
    - **policy_text** — raw contents of `sample_data/policy.md`
    - **access_changes_csv** — raw CSV text of `sample_data/access_changes.csv` (line breaks preserved)
    - **approvals_csv** — raw CSV text of `sample_data/approvals.csv` (line breaks preserved)
    - **rules_config** — parsed `sample_data/rules_default.json` as an object
    - **use_ai_rules** — always `false` in the sample payload
    """
    try:
        policy_text        = (SAMPLE_DATA_DIR / "policy.md").read_text(encoding="utf-8")
        access_changes_csv = (SAMPLE_DATA_DIR / "access_changes.csv").read_text(encoding="utf-8")
        approvals_csv      = (SAMPLE_DATA_DIR / "approvals.csv").read_text(encoding="utf-8")
        rules_config       = json.loads((SAMPLE_DATA_DIR / "rules_default.json").read_bytes())
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"Sample data file not found: {exc}")

    return JSONResponse({
        "policy_text":        policy_text,
        "access_changes_csv": access_changes_csv,
        "approvals_csv":      approvals_csv,
        "rules_config":       rules_config,
        "use_ai_rules":       False,
    })


@app.post("/policy_to_rules", summary="Extract validated rules from policy text")
async def policy_to_rules(req: PolicyToRulesRequest):
    """
    Extract a validated **Rules** object from policy text.

    Send a JSON body: `{ "policy_text": "..." }`

    Extraction uses a three-tier pipeline:
    1. **AI (OpenAI)** — if `OPENAI_API_KEY` is set; LLM outputs JSON validated by Pydantic.
    2. **Deterministic parser** — regex extraction of recognised policy phrases
       (e.g. `"Approver title must be one of: X, Y"`, `"High-risk roles require TWO approvals"`,
       `"within 30 minutes"`). Works without any API key.
    3. **Fallback defaults** — hardcoded safe defaults when neither tier yields a result.

    Any failure at tier 1 or 2 falls through gracefully.
    Enforcement logic is never touched — this endpoint only produces rule *configuration*.

    Response fields:
    - **rules** — validated rules object (Pydantic Rules schema)
    - **rules_source** — `"ai_extracted"` | `"parsed_from_policy"` | `"fallback_default"`
    - **policy_hash_sha256** — SHA-256 of the policy text (UTF-8)
    - **generated_at_utc** — ISO-8601 timestamp
    - **parse_warnings** — one message per extracted field, plus any tier-1 failure notes
    """
    if not req.policy_text.strip():
        raise HTTPException(status_code=400, detail="'policy_text' must not be empty.")

    policy_raw = req.policy_text.encode("utf-8")
    rules, source, warnings = extract_rules_from_policy(req.policy_text)
    policy_hash      = hashlib.sha256(policy_raw).hexdigest()
    generated_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return JSONResponse({
        "rules":              rules.model_dump(),
        "rules_source":       source,
        "policy_hash_sha256": policy_hash,
        "generated_at_utc":   generated_at_utc,
        "parse_warnings":     warnings,
    })


@app.post("/evaluate", summary="Evaluate access changes against policy (multipart)")
async def evaluate(
    policy: UploadFile = File(..., description="Policy file (.md, .csv, or .json)"),
    access_changes: UploadFile = File(..., description="Access change records (.csv or .json)"),
    approvals: UploadFile = File(..., description="Approval records (.csv or .json)"),
    rules_config: Optional[UploadFile] = File(
        default=None,
        description=(
            "Optional pre-approved rules JSON file. "
            "Takes precedence over use_ai_rules and bundled defaults."
        ),
    ),
    use_ai_rules: bool = Form(
        default=False,
        description=(
            "If true and rules_config is not provided, extract rules from the policy "
            "file via LLM (falls back to defaults if OPENAI_API_KEY is unset)."
        ),
    ),
):
    """
    Upload three required files and receive a full audit report.

    **Accepted formats**: `.md` / `.markdown`, `.csv`, `.json`

    **Rules precedence** (highest to lowest):
    1. `rules_config` uploaded → `rules_source: "approved_config"`
    2. `use_ai_rules=true` → `rules_source: "ai_extracted"` or `"fallback_default"`
    3. Bundled `rules_default.json` → `rules_source: "bundled_default_config"`

    Response includes:
    - **run_id / generated_at_utc / engine_version / policy_hash_sha256** — run metadata
    - **rules_used** — the validated rules object actually applied
    - **rules_source** — `"approved_config"` | `"ai_extracted"` | `"fallback_default"` | `"bundled_default_config"`
    - **rules_parse_warnings** — warnings from AI extraction (empty otherwise)
    - **summary** — aggregate pass/fail counts and exceptions by risk level
    - **results** — per-change evaluation with rule-level detail
    - **exceptions** — violations with embedded evidence and AI triage fields
    - **human_queue** — structured items requiring human review
    - **evidence_packet** — all inputs + results bundled for archiving
    - **memo_md** — human-readable Markdown audit memo
    """
    policy_data,    policy_raw = await _load_upload(policy,         "policy")
    changes_data,   _          = await _load_upload(access_changes, "access_changes")
    approvals_data, _          = await _load_upload(approvals,      "approvals")

    if not isinstance(policy_data, dict):
        raise HTTPException(status_code=400, detail="'policy' must resolve to an object/dict")
    if not isinstance(changes_data, list):
        raise HTTPException(status_code=400, detail="'access_changes' must resolve to an array")
    if not isinstance(approvals_data, list):
        raise HTTPException(status_code=400, detail="'approvals' must resolve to an array")

    rules_config_dict: Optional[dict] = None
    if rules_config is not None:
        raw_cfg = await rules_config.read()
        if not raw_cfg:
            raise HTTPException(status_code=400, detail="'rules_config' file is empty")
        try:
            rules_config_dict = json.loads(raw_cfg)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"'rules_config' is not valid JSON: {exc}")

    policy_text_for_ai = policy_raw.decode("utf-8", errors="replace")
    rules, rules_source, rules_warnings = _resolve_rules(
        rules_config_dict, use_ai_rules, policy_text_for_ai
    )

    result = run_evaluation(
        policy_data,
        changes_data,
        approvals_data,
        rules=rules,
        rules_source=rules_source,
        rules_parse_warnings=rules_warnings,
        policy_raw_bytes=policy_raw,
    )
    return JSONResponse(content=result)


@app.post("/evaluate_json", summary="Evaluate access changes via JSON body (preferred for Base44)")
async def evaluate_json(req: EvaluateJsonRequest):
    """
    JSON-body alternative to **/evaluate** for frontends that cannot send multipart uploads.
    This is the **preferred endpoint for Base44**.

    **Request body** — use the `*_csv` key names (aliases also accepted without suffix):

    | Field | Type | Required | Notes |
    |---|---|---|---|
    | `policy_text` | string | no | Raw policy Markdown; omit to use bundled defaults. |
    | `access_changes_csv` | string | **yes** | CSV text of change records. |
    | `approvals_csv` | string | **yes** | CSV text of approval records. |
    | `rules_config` | object | no | Pre-validated Rules dict; highest precedence. |
    | `use_ai_rules` | bool | no | If true (and no rules_config), call AI extraction. |

    **Rules precedence** (same as /evaluate):
    1. `rules_config` provided → `rules_source: "approved_config"`
    2. `use_ai_rules=true` → `rules_source: "ai_extracted"` or `"fallback_default"`
    3. Default → `rules_source: "bundled_default_config"`

    Returns the **same response shape** as /evaluate.
    """
    # ── logging (lengths + first line only; never log full CSV content) ────────
    _ch_first = req.access_changes.split("\n", 1)[0][:120]
    _ap_first = req.approvals.split("\n", 1)[0][:120]
    logger.info(
        "/evaluate_json: changes=%d chars (hdr: %r), approvals=%d chars (hdr: %r), "
        "rules_config=%s, use_ai_rules=%s",
        len(req.access_changes), _ch_first,
        len(req.approvals), _ap_first,
        "provided" if req.rules_config else "absent",
        req.use_ai_rules,
    )

    # ── parse CSV strings → typed lists ───────────────────────────────────────
    try:
        changes_data = parse_csv(req.access_changes.encode("utf-8"))
    except Exception as exc:
        first_line = req.access_changes.split("\n", 1)[0][:200]
        raise HTTPException(
            status_code=400,
            detail=(
                f"'access_changes_csv' could not be parsed: {exc}. "
                f"First line received: {first_line!r}"
            ),
        )
    try:
        approvals_data = parse_csv(req.approvals.encode("utf-8"))
    except Exception as exc:
        first_line = req.approvals.split("\n", 1)[0][:200]
        raise HTTPException(
            status_code=400,
            detail=(
                f"'approvals_csv' could not be parsed: {exc}. "
                f"First line received: {first_line!r}"
            ),
        )

    # ── parse policy text → dict (for archiving) + raw bytes (for hash) ───────
    policy_data      = parse_policy_md(req.policy_text) if req.policy_text.strip() else {}
    policy_raw_bytes = req.policy_text.encode("utf-8") if req.policy_text.strip() else None

    # ── resolve rules (precedence enforced in helper) ─────────────────────────
    rules, rules_source, rules_warnings = _resolve_rules(
        req.rules_config, req.use_ai_rules, req.policy_text
    )

    result = run_evaluation(
        policy_data,
        changes_data,
        approvals_data,
        rules=rules,
        rules_source=rules_source,
        rules_parse_warnings=rules_warnings,
        policy_raw_bytes=policy_raw_bytes,
    )
    return JSONResponse(content=result)
