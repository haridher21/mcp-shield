"""Structural diff between approved and current tool definitions, with severity."""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_equal, normalize_tool, tool_hash
from .validator import Finding, iter_strings, scan_text, scan_value

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


# ---------------------------------------------------------------------------
# Making server text safe to show a reviewer
# ---------------------------------------------------------------------------

_ESCAPES = {"\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_WHITESPACE_OK = frozenset("\n\r\t")


def escape_text(text: str) -> str:
    """Return ``text`` with every character that is not printable ASCII escaped.

    Terminal control sequences (ANSI), bidi overrides, zero-width characters and
    look-alike letters all become visible ``\\xNN`` / ``\\uNNNN`` escapes, and
    newlines become ``\\n``, so server text cannot hide content from the reviewer,
    recolour the terminal, or forge extra diff lines. Backslashes are doubled so
    an escape the server typed literally is never mistaken for one added here.
    """
    out = []
    for ch in text:
        o = ord(ch)
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif o < 0x100:
            out.append(f"\\x{o:02x}")
        elif o < 0x10000:
            out.append(f"\\u{o:04x}")
        else:
            out.append(f"\\U{o:08x}")
    return "".join(out)


def _char_label(ch: str) -> str:
    return f"U+{ord(ch):04X} {unicodedata.name(ch, 'UNNAMED')}"


def unusual_characters(value: Any) -> tuple[list[str], list[str]]:
    """Return labels for (hidden, other non-ASCII) characters in every string and key of ``value``.

    *Hidden* means control, format (bidi, zero-width, tag), private-use, unassigned
    or line/paragraph-separator characters: they change how text displays or carry
    data a reader cannot see. *Other non-ASCII* may be legitimate but may also be a
    look-alike (e.g. Cyrillic 'а' for Latin 'a').
    """
    hidden: dict[str, None] = {}
    other: dict[str, None] = {}
    for _, text in iter_strings(value):
        for ch in text:
            if ch.isascii() and (ch.isprintable() or ch in _WHITESPACE_OK):
                continue
            if unicodedata.category(ch) in ("Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp") and ch not in _WHITESPACE_OK:
                hidden.setdefault(_char_label(ch))
            else:
                other.setdefault(_char_label(ch))
    return list(hidden), list(other)


def _char_summary(labels: list[str], limit: int = 4) -> str:
    more = f" (+{len(labels) - limit} more)" if len(labels) > limit else ""
    return ", ".join(labels[:limit]) + more


def _instruction_summary(findings: list[Finding]) -> str:
    return ", ".join(sorted({f.rule for f in findings}))

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
    _classify_by_location(change)
    if change.kind == "removed":
        return
    # Server text can hide anywhere in the new value (a nested parameter description,
    # a title, an enum value, a property name), not only in a `description` leaf.
    extra: list[str] = []
    # An added key (e.g. a new property name) is new server text too.
    subject = [change.path[-1], change.new] if change.kind == "added" and change.path else change.new
    is_description_text = isinstance(change.new, str) and (change.path[-1:] == ("description",) or change.path[:1] == ("description",))
    if not is_description_text:  # description strings were already scanned above
        hits = scan_value(subject)
        if hits:
            change.severity = "high"
            extra.append("instruction-like text: " + _instruction_summary(hits))
    hidden, other = unusual_characters(subject)
    if hidden:
        change.severity = "high"
        extra.append("hidden/control characters: " + _char_summary(hidden))
    if other:
        extra.append("non-ASCII characters (check for look-alikes): " + _char_summary(other))
    if extra:
        change.reason = "; ".join([change.reason, *extra])


def _classify_by_location(change: Change) -> None:
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
    # Scan every string and key (title, parameter descriptions, enum values, property
    # names, ...), not just the top-level description: the model reads all of them.
    by_path: dict[str, list[Finding]] = {}
    for hit in scan_value(normalize_tool(tool)):
        by_path.setdefault(hit.path, []).append(hit)
    for path, hits in by_path.items():
        where = path.replace("/", ".").replace("#key", " (key)")
        notes.append(f"{where} contains instruction-like text: {_instruction_summary(hits)}")
        levels.append("high")
    hidden, other = unusual_characters(tool)
    if hidden:
        notes.append("hidden/control characters: " + _char_summary(hidden))
        levels.append("high")
    if other:
        notes.append("non-ASCII characters (check for look-alikes): " + _char_summary(other))
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
    """Printable-ASCII rendering of a server value, truncated to about ``limit`` characters.

    Hidden characters past the cut are still reported, because severity and notes
    are computed on the full value, not on this preview.
    """
    is_str = isinstance(value, str)
    # For non-strings, ensure_ascii escapes non-ASCII and control characters and JSON escapes backslashes.
    raw = value if is_str else json.dumps(value, ensure_ascii=True, sort_keys=True)
    truncated = len(raw) > limit
    if truncated:
        raw = raw[: limit - 1]
    text = escape_text(raw) if is_str else raw
    return text + "…" if truncated else text


def render_tool_diff(td: ToolDiff, *, definition: Mapping[str, Any] | None = None) -> str:
    h = lambda x: (x or "")[:12]  # noqa: E731
    lines = [f"[{td.severity.upper()}] {td.status.upper()} tool '{escape_text(td.name)}'  {h(td.old_hash) or '-'} -> {h(td.new_hash) or '-'}"]
    for note in td.notes:
        lines.append(f"    ! {escape_text(note)}")
    if td.status == "added" and definition is not None:
        lines.append(f"    description: {_fmt(definition.get('description', ''))}")
        props = ((definition.get("inputSchema") or {}).get("properties")) or {}
        lines.append(f"    inputs: {', '.join(escape_text(str(p)) for p in props) or '(none)'}")
    for c in td.changes:
        lines.append(f"  {_SYMBOL[c.kind]} {escape_text(c.dotted)}   [{c.severity}: {escape_text(c.reason)}]")
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
