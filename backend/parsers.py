"""
parsers.py — file-format helpers for policy, access_changes, and approvals.

Supported formats:
  .md / .markdown  → parse_policy_md()  → dict
  .csv             → parse_csv()        → list[dict]
  .json            → json.loads()       → dict or list   (fallback)

Type coercions applied to CSV cells:
  "true" / "false"  → bool
  empty string      → key omitted (treated as absent/null by evaluator)
  all-digit string  → int
  otherwise         → str
"""

import csv
import io
import json
from typing import Any, Dict, List, Union


def parse_policy_md(text: str) -> Dict:
    """Parse a structured Markdown policy file into a plain dict.

    Expected format:
        ## key_name
        scalar_value          <- becomes int or str

        ## list_key
        - item1               <- becomes list[str]
        - item2
    """
    policy: Dict[str, Any] = {}
    current: str | None = None
    pending_list: List[str] = []
    pending_scalar: Any = None

    def flush() -> None:
        if current is None:
            return
        if pending_list:
            policy[current] = list(pending_list)
        elif pending_scalar is not None:
            policy[current] = pending_scalar

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("## "):
            flush()
            current = line[3:].strip()
            pending_list = []
            pending_scalar = None
        elif line.startswith("- ") and current is not None:
            pending_list.append(line[2:].strip())
        elif line and not line.startswith("#") and current is not None and not pending_list:
            try:
                pending_scalar = int(line)
            except ValueError:
                pending_scalar = line

    flush()
    return policy


def parse_csv(raw: bytes) -> List[Dict]:
    """Parse CSV bytes into a list of typed dicts."""
    text = raw.decode("utf-8-sig")  # strip BOM if present
    reader = csv.DictReader(io.StringIO(text))
    rows: List[Dict] = []
    for row in reader:
        record: Dict[str, Any] = {}
        for k, v in row.items():
            if k is None:
                continue
            k = k.strip()
            v = (v or "").strip()
            if v == "":
                continue               # omit absent/null values
            if v.lower() == "true":
                record[k] = True
            elif v.lower() == "false":
                record[k] = False
            else:
                try:
                    record[k] = int(v)
                except ValueError:
                    record[k] = v
        rows.append(record)
    return rows


def load_file(raw: bytes, filename: str) -> Union[Dict, List]:
    """Dispatch to the correct parser based on filename extension."""
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return parse_csv(raw)
    if name.endswith((".md", ".markdown")):
        return parse_policy_md(raw.decode("utf-8"))
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cannot parse '{filename}' as JSON, CSV, or Markdown: {exc}") from exc
