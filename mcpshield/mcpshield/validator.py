"""Strict JSON Schema validation and bounded instruction-like content checks."""

from __future__ import annotations

import copy
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

# ---------------------------------------------------------------------------
# Schema hardening
# ---------------------------------------------------------------------------

_SCHEMA_MAP_KEYS = ("properties", "$defs", "definitions", "patternProperties", "dependentSchemas")
_SCHEMA_SINGLE_KEYS = (
    "items",
    "additionalProperties",
    "unevaluatedProperties",
    "not",
    "if",
    "then",
    "else",
    "contains",
    "propertyNames",
)
_SCHEMA_LIST_KEYS = ("anyOf", "oneOf", "allOf", "prefixItems")


def _types(node: Mapping[str, Any]) -> set[str]:
    t = node.get("type")
    if isinstance(t, str):
        return {t}
    if isinstance(t, list):
        return {x for x in t if isinstance(x, str)}
    return set()


def harden_schema(
    schema: Mapping[str, Any],
    *,
    max_string_length: int = 1024,
    max_array_items: int = 100,
) -> dict[str, Any]:
    """Return a stricter copy of ``schema`` for local enforcement.

    * objects reject properties that are not declared (``additionalProperties: false``),
      unless the schema deliberately describes a map with a sub-schema;
    * strings get a ``maxLength`` no larger than ``max_string_length``;
    * arrays get a ``maxItems`` no larger than ``max_array_items``.

    Limitation: forcing ``additionalProperties: false`` does not compose with
    ``allOf``-style schema inheritance. The demo schemas do not use it.
    """
    hardened = copy.deepcopy(dict(schema))

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        types = _types(node)
        if "object" in types or "properties" in node:
            if not isinstance(node.get("additionalProperties"), dict):
                node["additionalProperties"] = False
        if "string" in types:
            node["maxLength"] = min(int(node.get("maxLength", max_string_length)), max_string_length)
        if "array" in types:
            node["maxItems"] = min(int(node.get("maxItems", max_array_items)), max_array_items)

        for key in _SCHEMA_MAP_KEYS:
            sub = node.get(key)
            if isinstance(sub, dict):
                for child in sub.values():
                    visit(child)
        for key in _SCHEMA_SINGLE_KEYS:
            sub = node.get(key)
            if isinstance(sub, dict):
                visit(sub)
            elif isinstance(sub, list):  # legacy tuple-form "items"
                for child in sub:
                    visit(child)
        for key in _SCHEMA_LIST_KEYS:
            sub = node.get(key)
            if isinstance(sub, list):
                for child in sub:
                    visit(child)

    visit(hardened)
    return hardened


def check_schema(schema: Mapping[str, Any]) -> list[str]:
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return [f"invalid JSON Schema: {exc.message}"]
    return []


def _short(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


_FORMAT_CHECKER = FormatChecker()


def compile_schema(schema: Mapping[str, Any]) -> Draft202012Validator:
    """Check and compile a schema once; raises ValueError if it is not valid JSON Schema."""
    problems = check_schema(schema)
    if problems:
        raise ValueError(problems[0])
    return Draft202012Validator(schema, format_checker=_FORMAT_CHECKER)


def validate(schema: Mapping[str, Any] | Draft202012Validator, instance: Any) -> list[str]:
    """Validate ``instance`` against a schema (or compiled validator); return readable errors."""
    if isinstance(schema, Draft202012Validator):
        validator = schema
    else:
        try:
            validator = compile_schema(schema)
        except ValueError as exc:
            return [str(exc)]
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    out = []
    for err in errors:
        where = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"{where}: {_short(err.message)}")
    return out


# ---------------------------------------------------------------------------
# Instruction-like content detection (bounded heuristics, not a guarantee)
# ---------------------------------------------------------------------------

INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "override-instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
            r"\b(previous|prior|above|earlier|all|any|your|system)\b[^.\n]{0,20}?"
            r"\b(instructions?|prompts?|rules|directions|guidelines|context)\b",
            re.I,
        ),
    ),
    ("role-tag", re.compile(r"<\s*/?\s*(system|assistant|instructions?|important|im_start|im_end)\b", re.I)),
    ("role-prefix", re.compile(r"(^|\n)\s*(system|assistant|developer)\s*:", re.I)),
    (
        "directive-to-model",
        re.compile(
            r"\b(you\s+(must|should|need\s+to|are\s+required\s+to)\s+now"
            r"|as\s+an\s+ai\b|the\s+(assistant|model|ai|agent)\s+(must|should|will))",
            re.I,
        ),
    ),
    (
        "tool-invocation",
        re.compile(r"\b(call|invoke|run|execute|use)\s+(the\s+)?([a-z0-9_]+\s+)?(tool|function)\b", re.I),
    ),
    ("tool-invocation", re.compile(r"\b(call|invoke)\s+[a-z][a-z0-9]*_[a-z0-9_]+\b", re.I)),
    (
        "conceal-from-user",
        re.compile(
            r"\b(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|alert)\b[^.\n]{0,30}?\b(user|human|operator)\b",
            re.I,
        ),
    ),
    (
        "exfiltration",
        re.compile(
            r"\b(send|post|upload|forward|transmit|exfiltrate|email)\b[^\n]{0,80}?(https?://|\bto\s+(this|the\s+following)\s+(url|address|endpoint))",
            re.I,
        ),
    ),
    (
        "secret-access",
        re.compile(
            r"\b(read|cat|open|include|attach|provide|pass)\b[^.\n]{0,40}?"
            r"(\.ssh\b|id_rsa|\.env\b|/etc/passwd|credentials?|api[_ -]?keys?|passwords?|private[_ ]keys?)",
            re.I,
        ),
    ),
]

MAX_SCAN_CHARS = 16_384  # Scanning is bounded; longer strings are only scanned up to this point.


@dataclass(frozen=True)
class Finding:
    path: str
    rule: str
    excerpt: str

    def __str__(self) -> str:
        return f"{self.path}: {self.rule} ({self.excerpt!r})"


def scan_text(text: str, path: str = "<text>") -> list[Finding]:
    sample = text[:MAX_SCAN_CHARS]
    findings = []
    seen = set()
    for rule, pattern in INSTRUCTION_PATTERNS:
        match = pattern.search(sample)
        if match and rule not in seen:
            seen.add(rule)
            findings.append(Finding(path, rule, _short(match.group(0).strip(), 80)))
    return findings


def iter_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json-pointer-ish path, string) for every string and object key in ``value``."""
    if isinstance(value, str):
        yield path or "<root>", value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}/{key}" if path else str(key)
            yield f"{child}#key", str(key)
            yield from iter_strings(item, child)
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            yield from iter_strings(item, f"{path}/{i}" if path else str(i))


def scan_value(value: Any, path: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for p, text in iter_strings(value, path):
        findings.extend(scan_text(text, p))
    return findings
