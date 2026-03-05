#!/usr/bin/env python3
"""
smoke_test.py — evaluator unit tests + HTTP integration tests.

Unit paths (no server required):
  A. bundled_default_config  (rules_config not provided, use_ai_rules=False)
  B. approved_config         (rules_config provided as rules_default.json)
  C. fallback_default        (use_ai_rules=True, no API key -> fallback)
  D. evaluate_json *_csv aliases (model_validate round-trip)

Policy parser unit tests (G1-G3, no API key, no server):
  G1. Prose titles pattern  -> rules_source="parsed_from_policy", titles correct
  G2. Prose high-risk word  -> high_risk_min_distinct_approvals=3
  G3. No recognised phrases -> rules_source="fallback_default"

HTTP integration (via FastAPI TestClient, requires httpx):
  F. GET /sample_payload -> 200 with expected keys + line breaks preserved
  F. POST /evaluate_json with sample payload -> 200, total_changes==9
  F. Three paths via /evaluate_json produce identical pass/fail
  F. Invariants via HTTP: severity==risk_level, escalated_count==HIGH+CRITICAL

Invariant checks (unit):
  A. Identical pass/fail (all 3 unit paths)
  B. rules_source values correct
  C. severity == risk_level for every exception (path A)
  D. escalated_count == count(HIGH + CRITICAL exceptions) (path A)
  E. evaluate_json *_csv aliases work + path D matches path A
  G. Policy parser: G1/G2/G3 all pass

Exit codes:
  0 – all checks pass
  1 – one or more checks fail
  2 – sample file not found
"""

import json
import sys
from pathlib import Path

BASE = Path(__file__).parent / "sample_data"


def load(filename: str):
    path = BASE / filename
    if not path.exists():
        print(f"ERROR: sample file not found: {path}", file=sys.stderr)
        sys.exit(2)
    from parsers import load_file
    return load_file(path.read_bytes(), filename)


# ── load sample data ──────────────────────────────────────────────────────────
policy     = load("policy.md")
changes    = load("access_changes.csv")
approvals  = load("approvals.csv")
policy_raw = (BASE / "policy.md").read_bytes()

from ai_extractor import extract_rules_from_policy, parse_rules_from_policy_text  # noqa: E402
from evaluator import run_evaluation                        # noqa: E402
from parsers import parse_csv                               # noqa: E402
from rules_schema import FALLBACK_RULES, Rules, EvaluateJsonRequest  # noqa: E402


# ── path A: bundled_default_config ────────────────────────────────────────────
rules_default_path = BASE / "rules_default.json"
if not rules_default_path.exists():
    print(f"ERROR: sample file not found: {rules_default_path}", file=sys.stderr)
    sys.exit(2)

bundled_rules  = Rules(**json.loads(rules_default_path.read_bytes()))
result_bundled = run_evaluation(
    policy, changes, approvals,
    rules=bundled_rules,
    rules_source="bundled_default_config",
    rules_parse_warnings=[],
    policy_raw_bytes=policy_raw,
)

# ── path B: approved_config (same file, simulating an upload) ─────────────────
approved_rules  = Rules(**json.loads(rules_default_path.read_bytes()))
result_approved = run_evaluation(
    policy, changes, approvals,
    rules=approved_rules,
    rules_source="approved_config",
    rules_parse_warnings=[],
    policy_raw_bytes=policy_raw,
)

# ── path C: ai path (no key -> fallback_default) ───────────────────────────────
policy_text                      = policy_raw.decode("utf-8")
ai_rules, ai_source, ai_warns   = extract_rules_from_policy(policy_text)
result_ai = run_evaluation(
    policy, changes, approvals,
    rules=ai_rules,
    rules_source=ai_source,
    rules_parse_warnings=ai_warns,
    policy_raw_bytes=policy_raw,
)


# ── path D: simulate /evaluate_json with *_csv key names ──────────────────────
# Read sample CSVs as raw text strings, exactly as a UI client would send them.
_changes_csv_str   = (BASE / "access_changes.csv").read_text(encoding="utf-8")
_approvals_csv_str = (BASE / "approvals.csv").read_text(encoding="utf-8")

# Both the alias (*_csv) and the field name must populate the same field.
_req_via_alias = EvaluateJsonRequest.model_validate({
    "access_changes_csv": _changes_csv_str,
    "approvals_csv":      _approvals_csv_str,
})
_req_via_name = EvaluateJsonRequest.model_validate({
    "access_changes": _changes_csv_str,
    "approvals":      _approvals_csv_str,
})

_changes_d   = parse_csv(_req_via_alias.access_changes.encode("utf-8"))
_approvals_d = parse_csv(_req_via_alias.approvals.encode("utf-8"))
result_eval_json = run_evaluation(
    policy, _changes_d, _approvals_d,
    rules=bundled_rules,
    rules_source="bundled_default_config",
    rules_parse_warnings=[],
    policy_raw_bytes=policy_raw,
)


# ── helpers ───────────────────────────────────────────────────────────────────
def _section(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


# ── print path A details ──────────────────────────────────────────────────────
_section("RUN METADATA  (bundled_default_config path)")
r = result_bundled
print(f"  run_id           : {r['run_id']}")
print(f"  engine_version   : {r['engine_version']}")
print(f"  generated_at_utc : {r['generated_at_utc']}")
print(f"  policy_hash      : {r['policy_hash_sha256']}")
print(f"  rules_source     : {r['rules_source']}")

_section("SUMMARY  (bundled_default_config path)")
s = result_bundled["summary"]
print(f"  total_changes : {s['total_changes']}")
print(f"  passed        : {s['passed']}")
print(f"  failed        : {s['failed']}")
print(f"  exceptions    : {s['exceptions_count']}")
print(f"  human_queue   : {s['human_queue_count']}")
print()
print("  Exceptions by risk_level:")
for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
    print(f"    {lvl:8s}: {s['exceptions_by_risk_level'][lvl]}")

_section("EXCEPTIONS  (bundled_default_config path)")
for exc in result_bundled["exceptions"]:
    flag = "[ESCALATED]" if exc["escalated_to_human_queue"] else "[not escalated]"
    print(f"  [{exc['risk_level']:8s}] {exc['rule']:<30s} {flag}")
    print(f"             {exc['ai_triage_summary'][:88]}...")

_section(f"HUMAN QUEUE  ({len(result_bundled['human_queue'])} items)")
for item in result_bundled["human_queue"]:
    print(f"  [{item['risk_level']:8s}] {item['change_id']}  rules={item['failed_rules']}")


# ── three-path comparison ─────────────────────────────────────────────────────
_section("THREE-PATH COMPARISON")
print(f"  path A  rules_source : {result_bundled['rules_source']}")
print(f"  path B  rules_source : {result_approved['rules_source']}")
print(f"  path C  rules_source : {result_ai['rules_source']}")
if ai_warns:
    print(f"  path C  parse_warnings: {ai_warns}")
print()

bundled_pf  = {r["change_id"]: r["passed"] for r in result_bundled["results"]}
approved_pf = {r["change_id"]: r["passed"] for r in result_approved["results"]}
ai_pf       = {r["change_id"]: r["passed"] for r in result_ai["results"]}
all_ids     = sorted(set(bundled_pf) | set(approved_pf) | set(ai_pf))

print("  change_id   bundled  approved  ai")
print("  ---------   -------  --------  --")
for cid in all_ids:
    b_val = bundled_pf.get(cid, "?")
    p_val = approved_pf.get(cid, "?")
    a_val = ai_pf.get(cid, "?")
    vals  = {b_val, p_val, a_val} - {"?"}
    diff  = " <-- DIFF" if len(vals) > 1 else ""
    print(
        f"  {cid:<11} "
        f"{'PASS' if b_val else 'FAIL':<8} "
        f"{'PASS' if p_val else 'FAIL':<9} "
        f"{'PASS' if a_val else 'FAIL'}"
        f"{diff}"
    )


# ── invariant checks ──────────────────────────────────────────────────────────
_section("INVARIANT CHECKS")

failed = False

# A. Identical pass/fail across all three paths
pf_diffs = [
    cid for cid in all_ids
    if not (bundled_pf.get(cid) == approved_pf.get(cid) == ai_pf.get(cid))
]
print(f"  A. Identical pass/fail (all 3 paths) : {'OK' if not pf_diffs else 'FAIL'}")
if pf_diffs:
    for cid in pf_diffs:
        print(
            f"       {cid}: bundled={bundled_pf.get(cid)} "
            f"approved={approved_pf.get(cid)} ai={ai_pf.get(cid)}",
            file=sys.stderr,
        )
    failed = True

# B. rules_source values correct for each path
expected_ai_source = "fallback_default"   # no API key in test environment
src_ok = (
    result_bundled["rules_source"]  == "bundled_default_config" and
    result_approved["rules_source"] == "approved_config" and
    result_ai["rules_source"]       == expected_ai_source
)
print(f"  B. rules_source values correct       : {'OK' if src_ok else 'FAIL'}")
if not src_ok:
    print(
        f"       expected bundled_default_config / approved_config / {expected_ai_source}",
        file=sys.stderr,
    )
    print(
        f"       got     {result_bundled['rules_source']} / "
        f"{result_approved['rules_source']} / {result_ai['rules_source']}",
        file=sys.stderr,
    )
    failed = True

# C. severity == risk_level for every exception (path A)
exceptions     = result_bundled["exceptions"]
sev_mismatches = [e for e in exceptions if e.get("severity") != e.get("risk_level")]
print(
    f"  C. severity==risk_level ({len(exceptions) - len(sev_mismatches)}/{len(exceptions)} exc)"
    f": {'OK' if not sev_mismatches else 'FAIL'}"
)
if sev_mismatches:
    for e in sev_mismatches:
        print(
            f"       rule={e['rule']} severity={e.get('severity')} "
            f"risk_level={e.get('risk_level')}",
            file=sys.stderr,
        )
    failed = True

# D. escalated_count == HIGH + CRITICAL count (path A)
escalated_count     = sum(1 for e in exceptions if e["escalated_to_human_queue"])
high_critical_count = sum(1 for e in exceptions if e["risk_level"] in ("HIGH", "CRITICAL"))
inv_d_ok = escalated_count == high_critical_count
print(
    f"  D. escalated({escalated_count}) == HIGH+CRITICAL({high_critical_count})"
    f" : {'OK' if inv_d_ok else 'FAIL'}"
)
if not inv_d_ok:
    failed = True

# E. /evaluate_json *_csv aliases work and path D matches path A
eval_json_pf  = {r["change_id"]: r["passed"] for r in result_eval_json["results"]}
alias_names_ok = _req_via_alias.access_changes == _req_via_name.access_changes
pf_match_ok    = all(eval_json_pf.get(cid) == bundled_pf.get(cid) for cid in all_ids)
inv_e_ok       = alias_names_ok and pf_match_ok
print(
    f"  E. evaluate_json *_csv aliases + path D matches path A"
    f" : {'OK' if inv_e_ok else 'FAIL'}"
)
if not inv_e_ok:
    if not alias_names_ok:
        print(
            "       alias ('access_changes_csv') and field name ('access_changes') "
            "produced different values",
            file=sys.stderr,
        )
    if not pf_match_ok:
        for cid in all_ids:
            if eval_json_pf.get(cid) != bundled_pf.get(cid):
                print(
                    f"       {cid}: path_A={bundled_pf.get(cid)}"
                    f" eval_json={eval_json_pf.get(cid)}",
                    file=sys.stderr,
                )
    failed = True

# ── section G: policy parser unit tests (no API key, no server) ───────────────
_section("POLICY PARSER TESTS  (deterministic tier-2 extraction)")

# G1: titles extracted from prose
_g1_text = "Approver title must be one of: IT Security, Finance Manager"
_g1_rules, _g1_src, _g1_warns = extract_rules_from_policy(_g1_text)
_g1_titles_ok  = "Finance Manager" in _g1_rules.allowed_approver_titles
_g1_src_ok     = _g1_src == "parsed_from_policy"
_g1_ok         = _g1_titles_ok and _g1_src_ok
print(f"  G1. Titles prose -> parsed_from_policy + Finance Manager present : {'OK' if _g1_ok else 'FAIL'}")
if not _g1_ok:
    print(f"       rules_source={_g1_src!r}  titles={_g1_rules.allowed_approver_titles}", file=sys.stderr)
    failed = True

# G2: word number extracted for high_risk_min_distinct_approvals
_g2_text = "High-risk roles require THREE distinct approvals within 45 minutes"
_g2_rules, _g2_src, _g2_warns = extract_rules_from_policy(_g2_text)
_g2_min_ok  = _g2_rules.high_risk_min_distinct_approvals == 3
_g2_em_ok   = _g2_rules.emergency_grace_minutes == 45
_g2_src_ok  = _g2_src == "parsed_from_policy"
_g2_ok      = _g2_min_ok and _g2_em_ok and _g2_src_ok
print(f"  G2. Word number + minutes -> parsed_from_policy, min=3, grace=45 : {'OK' if _g2_ok else 'FAIL'}")
if not _g2_ok:
    print(
        f"       rules_source={_g2_src!r}  "
        f"high_risk_min={_g2_rules.high_risk_min_distinct_approvals}  "
        f"grace_min={_g2_rules.emergency_grace_minutes}",
        file=sys.stderr,
    )
    failed = True

# G3: unrecognised policy text -> fallback_default
_g3_text = "All employees must follow internal IT procedures."
_g3_rules, _g3_src, _g3_warns = extract_rules_from_policy(_g3_text)
_g3_ok = _g3_src == "fallback_default"
print(f"  G3. No recognised phrases -> fallback_default               : {'OK' if _g3_ok else 'FAIL'}")
if not _g3_ok:
    print(f"       rules_source={_g3_src!r}", file=sys.stderr)
    failed = True

# Show warnings for G1 and G2 so the extracted snippets are visible
print()
print("  G1 parse_warnings:")
for _w in _g1_warns:
    print(f"    - {_w}")
print("  G2 parse_warnings:")
for _w in _g2_warns:
    print(f"    - {_w}")

# ── section F: HTTP integration tests (require FastAPI TestClient + httpx) ────
_section("HTTP INTEGRATION TESTS  (TestClient)")

try:
    from fastapi.testclient import TestClient  # needs: pip install httpx
    import sys as _sys_mod
    _sys_mod.path.insert(0, str(Path(__file__).parent))
    from main import app as _app  # noqa: E402  (imports fastapi — OK for HTTP tests)
    _client = TestClient(_app, raise_server_exceptions=True)
    _http_ok = True
except ImportError as _ie:
    print(f"  SKIP: TestClient/httpx not available ({_ie})")
    print("        Install httpx to enable HTTP tests: pip install httpx")
    _http_ok = False

if _http_ok:
    _http_failed = False

    # F1. GET /sample_payload ─────────────────────────────────────────────────
    _r = _client.get("/sample_payload")
    _f1_ok = (
        _r.status_code == 200
        and "policy_text"        in _r.json()
        and "access_changes_csv" in _r.json()
        and "approvals_csv"      in _r.json()
        and "\n" in _r.json()["access_changes_csv"]   # line breaks preserved
        and "\n" in _r.json()["approvals_csv"]
    )
    print(f"  F1. GET /sample_payload returns 200 + expected keys : {'OK' if _f1_ok else 'FAIL'}")
    if not _f1_ok:
        print(f"       status={_r.status_code}  body={_r.text[:200]}", file=sys.stderr)
        _http_failed = True

    _sample = _r.json()

    # F2. POST /evaluate_json with sample payload -> 200, 9 changes ───────────
    _r2 = _client.post("/evaluate_json", json=_sample)
    _f2_ok = (
        _r2.status_code == 200
        and _r2.json().get("summary", {}).get("total_changes") == 9
        and "results"       in _r2.json()
        and "exceptions"    in _r2.json()
        and "human_queue"   in _r2.json()
        and "evidence_packet" in _r2.json()
        and "memo_md"       in _r2.json()
        and "rules_used"    in _r2.json()
        and "rules_source"  in _r2.json()
    )
    print(f"  F2. POST /evaluate_json (sample payload) -> 200 + full shape : {'OK' if _f2_ok else 'FAIL'}")
    if not _f2_ok:
        print(f"       status={_r2.status_code}  body={_r2.text[:300]}", file=sys.stderr)
        _http_failed = True

    # F3. Three paths via /evaluate_json produce identical pass/fail ──────────
    _sample_no_cfg = {k: v for k, v in _sample.items() if k != "rules_config"}

    _rb = _client.post("/evaluate_json", json=_sample_no_cfg)                          # bundled
    _ra = _client.post("/evaluate_json", json=_sample)                                 # approved_config
    _rc = _client.post("/evaluate_json", json={**_sample_no_cfg, "use_ai_rules": True}) # ai->fallback

    _http_3_ok = _rb.status_code == _ra.status_code == _rc.status_code == 200
    if _http_3_ok:
        _pf_b = {r["change_id"]: r["passed"] for r in _rb.json()["results"]}
        _pf_a = {r["change_id"]: r["passed"] for r in _ra.json()["results"]}
        _pf_c = {r["change_id"]: r["passed"] for r in _rc.json()["results"]}
        _diffs = [
            cid for cid in _pf_b
            if not (_pf_b[cid] == _pf_a[cid] == _pf_c[cid])
        ]
        _http_3_ok = not _diffs
        if not _http_3_ok:
            for _cid in _diffs:
                print(
                    f"       {_cid}: bundled={_pf_b[_cid]} approved={_pf_a[_cid]} ai={_pf_c[_cid]}",
                    file=sys.stderr,
                )
    print(f"  F3. Three /evaluate_json paths -> identical pass/fail : {'OK' if _http_3_ok else 'FAIL'}")
    if not _http_3_ok:
        _http_failed = True

    # F4. HTTP invariants: severity==risk_level + escalated_count ─────────────
    _http_exc       = _rb.json()["exceptions"]
    _sev_ok_http    = all(e["severity"] == e["risk_level"] for e in _http_exc)
    _esc_http       = sum(1 for e in _http_exc if e["escalated_to_human_queue"])
    _hc_http        = sum(1 for e in _http_exc if e["risk_level"] in ("HIGH", "CRITICAL"))
    _inv_http_ok    = _sev_ok_http and (_esc_http == _hc_http)
    print(
        f"  F4. HTTP invariants (sev==risk_level, esc={_esc_http}==HC={_hc_http})"
        f" : {'OK' if _inv_http_ok else 'FAIL'}"
    )
    if not _inv_http_ok:
        if not _sev_ok_http:
            _bad = [e for e in _http_exc if e["severity"] != e["risk_level"]]
            for _e in _bad:
                print(f"       rule={_e['rule']} sev={_e['severity']} risk={_e['risk_level']}", file=sys.stderr)
        if _esc_http != _hc_http:
            print(f"       escalated={_esc_http} but HIGH+CRITICAL={_hc_http}", file=sys.stderr)
        _http_failed = True

    if _http_failed:
        failed = True

print()
if failed:
    print("RESULT: one or more checks FAILED", file=sys.stderr)
    sys.exit(1)

print("RESULT: all checks passed")
