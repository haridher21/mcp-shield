"""Structural diff between approved and current tool definitions, with severity."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_equal, normalize_tool, tool_hash
from .validator import scan_text

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

SENSITIVE_PARAM_RE = re.compile(
    r"pass(word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential"
    r"|auth|cookie|session|ssn|social[_-]?security|credit[_-]?card|card[_-]?(number|no)|cvv|cvc"
    r"|\bpin\b|otp|mnemonic|seed[_-]?phrase|wallet|bank|routing|iban|ssh|file[_-]?path|history",
    re.I,
)


def max_severity(levels) -> str:
    return max(levels, key=lambda s: SEVERITY_ORDER[s], default="info")


@dataclass
class Change:
    path: tuple[str, ...]
    kind: str  # "added" | "removed" | "changed"
    old: Any = None
    new: Any = None
    severity: str = "medium"
    reason: str = ""

    @property
    def category(self) -> str:
        head = self.path[0] if self.path else ""
        return {
            "description": "description",
            "title": "title",
            "inputSchema": "input schema",
            "outputSchema": "output schema",
            "annotations": "annotations",
        }.get(head, head or "definition")

    @property
    def dotted(self) -> str:
        return ".".join(self.path) or "<root>"


@dataclass
class ToolDiff:
    name: str
    status: str  # "added" | "removed" | "modified"
    old_hash: str | None = None
    new_hash: str | None = None
    changes: list[Change] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    severity: str = "medium"


@dataclass
class ManifestDiff:
    added: list[ToolDiff] = field(default_factory=list)
    removed: list[ToolDiff] = field(default_factory=list)
    modified: list[ToolDiff] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def all(self) -> list[ToolDiff]:
        return [*self.added, *self.modified, *self.removed]


# ---------------------------------------------------------------------------


def _walk(old: Any, new: Any, path: tuple[str, ...]) -> list[Change]:
    if canonical_equal(old, new):
        return []
    if isinstance(old, Mapping) and isinstance(new, Mapping):
        out: list[Change] = []
        for key in sorted(set(old) | set(new)):
            p = (*path, str(key))
            if key not in new:
                out.append(Change(p, "removed", old=old[key]))
            elif key not in old:
                out.append(Change(p, "added", new=new[key]))
            else:
                out.extend(_walk(old[key], new[key], p))
        return out
    if path and path[-1] == "required" and isinstance(old, list) and isinstance(new, list):
        out = []
        for item in sorted(set(new) - set(old)):
            out.append(Change((*path, str(item)), "added", new=item))
        for item in sorted(set(old) - set(new)):
            out.append(Change((*path, str(item)), "removed", old=item))
        return out
    return [Change(path, "changed", old=old, new=new)]


def _is_input_property(path: tuple[str, ...]) -> bool:
    return len(path) >= 3 and path[0] == "inputSchema" and path[-2] == "properties"


def _classify(change: Change) -> None:
    path = change.path
    head = path[0] if path else ""
    leaf = path[-1] if path else ""

    if _is_input_property(path) and change.kind == "added":
        if SENSITIVE_PARAM_RE.search(leaf):
            change.severity, change.reason = "high", "new input parameter with a sensitive name"
        else:
            change.severity, change.reason = "medium", "new input parameter"
        return
    if head == "inputSchema" and len(path) >= 2 and path[-2] == "required" and change.kind == "added":
        sensitive = bool(SENSITIVE_PARAM_RE.search(leaf))
        change.severity = "high" if sensitive else "medium"
        change.reason = "parameter became required"
        return
    if leaf == "description" or head == "description":
        text = change.new if isinstance(change.new, str) else ""
        hits = scan_text(text) if text else []
        if hits:
            change.severity = "high"
            change.reason = "instruction-like text: " + ", ".join(sorted({h.rule for h in hits}))
        else:
            change.severity, change.reason = "medium", "description text changed"
        return
    if head == "annotations":
        risky = {
            "readOnlyHint": lambda o, n: o is True and n is not True,
            "destructiveHint": lambda o, n: n is True and o is not True,
            "openWorldHint": lambda o, n: n is True and o is not True,
            "idempotentHint": lambda o, n: o is True and n is not True,
        }
        check = risky.get(leaf)
        if check and check(change.old, change.new):
            change.severity, change.reason = "high", f"{leaf} now claims riskier behaviour"
        else:
            change.severity, change.reason = "low", "annotation changed"
        return
    if head == "title":
        change.severity, change.reason = "low", "title changed"
        return
    if head == "outputSchema":
        change.severity, change.reason = "medium", "output contract changed"
        return
    change.severity, change.reason = "medium", "definition changed"


def _added_tool_notes(tool: Mapping[str, Any]) -> tuple[list[str], str]:
    notes, levels = [], ["medium"]
    desc = tool.get("description") or ""
    hits = scan_text(desc, "description")
    if hits:
        notes.append("description contains instruction-like text: " + ", ".join(sorted({h.rule for h in hits})))
        levels.append("high")
    props = ((tool.get("inputSchema") or {}).get("properties")) or {}
    sensitive = [p for p in props if SENSITIVE_PARAM_RE.search(p)]
    if sensitive:
        notes.append("sensitive input parameters: " + ", ".join(sensitive))
        levels.append("high")
    ann = tool.get("annotations") or {}
    if ann.get("destructiveHint") is True or ann.get("readOnlyHint") is False:
        notes.append("declares side effects (destructive / not read-only)")
    return notes, max_severity(levels)


def diff_tool(old: Mapping[str, Any], new: Mapping[str, Any]) -> ToolDiff:
    changes = _walk(normalize_tool(old), normalize_tool(new), ())
    for change in changes:
        _classify(change)
    return ToolDiff(
        name=str(new.get("name", old.get("name"))),
        status="modified",
        old_hash=tool_hash(old),
        new_hash=tool_hash(new),
        changes=changes,
        severity=max_severity(c.severity for c in changes),
    )


def diff_manifests(approved: Mapping[str, Mapping[str, Any]], current: Mapping[str, Mapping[str, Any]]) -> ManifestDiff:
    result = ManifestDiff()
    for name in sorted(set(approved) | set(current)):
        if name not in current:
            result.removed.append(
                ToolDiff(name, "removed", old_hash=tool_hash(approved[name]), severity="low")
            )
        elif name not in approved:
            notes, sev = _added_tool_notes(current[name])
            result.added.append(
                ToolDiff(name, "added", new_hash=tool_hash(current[name]), notes=notes, severity=sev)
            )
        elif tool_hash(approved[name]) != tool_hash(current[name]):
            result.modified.append(diff_tool(approved[name], current[name]))
        else:
            result.unchanged.append(name)
    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_SYMBOL = {"added": "+", "removed": "-", "changed": "~"}


def _fmt(value: Any, limit: int = 240) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_tool_diff(td: ToolDiff, *, definition: Mapping[str, Any] | None = None) -> str:
    h = lambda x: (x or "")[:12]  # noqa: E731
    lines = [f"[{td.severity.upper()}] {td.status.upper()} tool '{td.name}'  {h(td.old_hash) or '-'} -> {h(td.new_hash) or '-'}"]
    for note in td.notes:
        lines.append(f"    ! {note}")
    if td.status == "added" and definition is not None:
        lines.append(f"    description: {_fmt(definition.get('description', ''))}")
        props = ((definition.get("inputSchema") or {}).get("properties")) or {}
        lines.append(f"    inputs: {', '.join(props) or '(none)'}")
    for c in td.changes:
        lines.append(f"  {_SYMBOL[c.kind]} {c.dotted}   [{c.severity}: {c.reason}]")
        if c.kind in ("removed", "changed"):
            lines.append(f"      - {_fmt(c.old)}")
        if c.kind in ("added", "changed"):
            lines.append(f"      + {_fmt(c.new)}")
    return "\n".join(lines)


def render_manifest_diff(diff: ManifestDiff, current: Mapping[str, Mapping[str, Any]] | None = None) -> str:
    if not diff.has_changes:
        return "No changes: every tool matches its approved definition."
    blocks = [render_tool_diff(td, definition=(current or {}).get(td.name)) for td in diff.all()]
    return "\n\n".join(blocks)
