"""Deterministic JSON canonicalization and hashing of MCP tool definitions.

The canonical form is close to RFC 8785 (JCS): object keys sorted, no
insignificant whitespace, UTF-8 output, integral floats written as integers,
NaN/Infinity rejected. Known deviation: keys are sorted by Unicode code point
rather than UTF-16 code unit, which only differs for characters outside the
Basic Multilingual Plane.

On top of plain canonicalization, `normalize_tool` treats a few JSON Schema
arrays as sets (e.g. ``required``) so that reordering them does not raise an
alert. Everything else, including list order, whitespace inside strings and
Unicode form, is treated as meaningful: a homoglyph swap in a description is a
real change.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from typing import Any

# JSON Schema keywords whose array value has set semantics.
_SET_LIKE_SCHEMA_KEYS = frozenset({"required"})
# Top-level tool fields that contain JSON Schemas.
_SCHEMA_FIELDS = ("inputSchema", "outputSchema")


def _normalize(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity cannot be canonicalized")
        if value.is_integer() and abs(value) < 2**53:
            return int(value)
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"JSON object keys must be strings, got {type(key).__name__}")
            out[key] = _normalize(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    raise TypeError(f"Unsupported type for canonical JSON: {type(value).__name__}")


def canonicalize(value: Any) -> str:
    """Return the canonical JSON text for ``value``."""
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_schema(node: Any) -> Any:
    if isinstance(node, Mapping):
        out = {}
        for key, item in node.items():
            if key in _SET_LIKE_SCHEMA_KEYS and isinstance(item, list) and all(isinstance(x, str) for x in item):
                out[key] = sorted(set(item))
            else:
                out[key] = _normalize_schema(item)
        return out
    if isinstance(node, list):
        return [_normalize_schema(item) for item in node]
    return node


def normalize_tool(tool: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``tool`` with semantically irrelevant variation removed."""
    out = dict(_normalize(tool))
    for field in _SCHEMA_FIELDS:
        if field in out:
            out[field] = _normalize_schema(out[field])
    return out


def tool_hash(tool: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical form of one complete tool definition."""
    return sha256_hex(canonicalize(normalize_tool(tool)))


def manifest_hash(tools: Iterable[Mapping[str, Any]]) -> str:
    """SHA-256 over the sorted (name, tool hash) pairs of a whole server catalog."""
    pairs = sorted((str(t.get("name")), tool_hash(t)) for t in tools)
    return sha256_hex(canonicalize(pairs))


def canonical_equal(a: Any, b: Any) -> bool:
    return canonicalize(a) == canonicalize(b)
