"""Approval and enforcement gate. Pure Python: no MCP SDK dependency.

All tool definitions and results here are plain JSON dicts in MCP wire format
(camelCase keys: ``inputSchema``, ``outputSchema``, ``structuredContent`` ...).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_equal, canonicalize, manifest_hash, tool_hash
from .diff import ManifestDiff, diff_manifests, diff_tool, render_tool_diff
from .store import ApprovedTool, Store
from .validator import (
    Finding,
    check_schema,
    compile_schema,
    harden_schema,
    scan_secrets,
    scan_text,
    scan_value,
    validate,
)


@dataclass
class Policy:
    max_string_length: int = 1024        # cap applied to every string in approved schemas
    max_array_items: int = 100
    max_text_length: int = 8192          # cap on each unstructured text block in a result
    max_structured_bytes: int = 65_536   # cap on the JSON size of structuredContent in a result
    block_suspicious_output: bool = True  # False = flag (log) instruction-like output but let it through
    strict_text_mirror: bool = True      # text blocks must mirror validated structuredContent
    allowed_content_types: tuple[str, ...] = ("text",)
    require_output_schema: bool = False  # reject structuredContent for tools without an approved schema
    recheck_definitions_on_call: bool = True
    block_secrets_in_arguments: bool = True  # block calls whose arguments carry credential-looking strings
    upstream_timeout: float | None = 30.0   # seconds per upstream request; None = wait forever


@dataclass
class Verdict:
    """Outcome of a check.

    ``reasons`` may be shown to the model, so on the result side they never contain
    server-controlled text. ``details`` holds the full explanation for the audit log only.
    """

    allowed: bool
    reasons: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @classmethod
    def ok(cls) -> "Verdict":
        return cls(True)

    @classmethod
    def block(cls, *reasons: str, findings: list[Finding] | None = None, details: list[str] | None = None) -> "Verdict":
        return cls(False, list(reasons), findings or [], details or [])


@dataclass
class ToolStatus:
    name: str
    state: str  # approved | quarantined-new | quarantined-modified | rejected | removed | duplicate
    hash: str | None
    severity: str = "info"


@dataclass
class SyncReport:
    manifest_hash: str
    diff: ManifestDiff
    statuses: list[ToolStatus]
    duplicates: list[str]
    newly_quarantined: list[str]

    @property
    def visible(self) -> list[str]:
        return [s.name for s in self.statuses if s.state == "approved"]

    @property
    def blocked(self) -> list[str]:
        return [s.name for s in self.statuses if s.state not in ("approved", "removed")]


def index_tools(tools: list[Mapping[str, Any]]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    counts = Counter(str(t.get("name")) for t in tools)
    dups = sorted(n for n, c in counts.items() if c > 1)
    return {str(t.get("name")): dict(t) for t in tools if counts[str(t.get("name"))] == 1}, dups


class Shield:
    def __init__(self, store: Store, server_id: str = "default", policy: Policy | None = None, actor: str = "cli"):
        self.store = store
        self.server_id = server_id
        self.policy = policy or Policy()
        self.actor = actor
        self._validators: dict[tuple[str, str], Any] = {}
        self._approved_cache: dict[str, ApprovedTool] | None = None
        self._approved_version: int | None = None

    # ------------------------------------------------------------------ helpers
    def approved(self) -> dict[str, ApprovedTool]:
        """Approved tools, cached until this or another process changes the database."""
        version = self.store.data_version()
        if self._approved_cache is None or version != self._approved_version:
            self._approved_cache = self.store.get_approved(self.server_id)
            self._approved_version = version
        return self._approved_cache

    def _invalidate(self) -> None:
        self._approved_cache = None

    def _validator(self, approved: ApprovedTool, which: str):
        key = (approved.hash + ("" if which == "input" else canonicalize(approved.local_output_schema)), which)
        v = self._validators.get(key)
        if v is None:
            if which == "input":
                schema = self._harden(approved.definition.get("inputSchema") or {"type": "object"})
            else:
                schema = approved.local_output_schema
            v = compile_schema(schema)
            self._validators[key] = v
        return v

    def _harden(self, schema: Mapping[str, Any]) -> dict[str, Any]:
        return harden_schema(
            schema,
            max_string_length=self.policy.max_string_length,
            max_array_items=self.policy.max_array_items,
        )

    def _event(self, kind: str, severity: str, detail: dict[str, Any] | str, tool: str | None = None) -> None:
        self.store.log_event(self.server_id, kind, severity, detail, tool)

    # ------------------------------------------------------------------ definitions
    def sync(self, tools: list[Mapping[str, Any]]) -> SyncReport:
        """Compare a freshly fetched catalog with approved state; quarantine changes."""
        current, dups = index_tools(tools)
        approved = self.approved()
        diff = diff_manifests({n: a.definition for n, a in approved.items()}, current)
        mhash = manifest_hash(current.values())
        new_manifest = self.store.record_manifest(self.server_id, mhash, [dict(t) for t in tools])

        newly: list[str] = []
        for td in [*diff.added, *diff.modified]:
            if self.store.quarantine(self.server_id, td.name, td.new_hash, current[td.name], td.status):
                newly.append(td.name)
                self._event(
                    f"tool_{td.status}",
                    td.severity,
                    {"hash": td.new_hash, "diff": render_tool_diff(td, definition=current[td.name])},
                    td.name,
                )
        if new_manifest:
            for td in diff.removed:
                self._event("tool_removed", "low", {"hash": td.old_hash}, td.name)
            for name in dups:
                self._event("duplicate_tool_name", "high", "server advertised the same tool name more than once", name)

        quarantined = self.store.get_quarantined(self.server_id)
        statuses: list[ToolStatus] = []
        for name in diff.unchanged:
            statuses.append(ToolStatus(name, "approved", approved[name].hash))
        for td in [*diff.added, *diff.modified]:
            q = quarantined.get(td.name)
            if q and q.status == "rejected" and q.hash == td.new_hash:
                state = "rejected"
            else:
                state = f"quarantined-{'new' if td.status == 'added' else 'modified'}"
            statuses.append(ToolStatus(td.name, state, td.new_hash, td.severity))
        for td in diff.removed:
            statuses.append(ToolStatus(td.name, "removed", td.old_hash, "low"))
        for name in dups:
            statuses.append(ToolStatus(name, "duplicate", None, "high"))
        statuses.sort(key=lambda s: s.name)
        return SyncReport(mhash, diff, statuses, dups, newly)

    def visible_tools(self, tools: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Only tools whose current definition hashes to the approved hash are exposed.

        Each exposed tool advertises the hardened input schema that ``check_call``
        enforces, so the model is shown the contract it will actually be held to.
        """
        current, _ = index_tools(tools)
        approved = self.approved()
        visible = []
        for n, t in current.items():
            a = approved.get(n)
            if a is not None and tool_hash(t) == a.hash:
                shown = dict(t)
                shown["inputSchema"] = self._harden(a.definition.get("inputSchema") or {"type": "object"})
                visible.append(shown)
        return visible

    # ------------------------------------------------------------------ decisions
    def pending_diff(self, name: str) -> str:
        q = self.store.get_quarantined(self.server_id, name).get(name)
        if q is None:
            raise KeyError(f"no quarantined definition for '{name}'")
        approved = self.approved().get(name)
        if approved is None:
            diff = diff_manifests({}, {name: q.definition})
            return render_tool_diff(diff.added[0], definition=q.definition)
        return render_tool_diff(diff_tool(approved.definition, q.definition))

    def approve(self, name: str, *, expected_hash: str | None = None, note: str = "") -> str:
        """Approve the quarantined definition of ``name`` exactly as it was recorded."""
        q = self.store.get_quarantined(self.server_id, name).get(name)
        if q is None:
            raise KeyError(f"no quarantined definition for '{name}'")
        if expected_hash and not q.hash.startswith(expected_hash):
            raise ValueError(f"quarantined hash {q.hash[:12]} does not match expected {expected_hash}")
        problems = check_schema(q.definition.get("inputSchema") or {"type": "object"})
        if q.definition.get("outputSchema") is not None:
            problems += check_schema(q.definition["outputSchema"])
        if problems:
            raise ValueError(f"cannot approve '{name}': " + "; ".join(problems))
        out_schema = q.definition.get("outputSchema")
        local = self._harden(out_schema) if out_schema is not None else None
        self.store.set_approved(self.server_id, name, q.hash, q.definition, local, self.actor)
        self._invalidate()
        self.store.release(self.server_id, name)
        self.store.record_decision(self.server_id, name, "approve", q.hash, self.actor, note)
        self._event("tool_approved", "info", {"hash": q.hash}, name)
        return q.hash

    def reject(self, name: str, *, note: str = "") -> str:
        q = self.store.get_quarantined(self.server_id, name).get(name)
        if q is None:
            raise KeyError(f"no quarantined definition for '{name}'")
        self.store.set_quarantine_status(self.server_id, name, "rejected")
        self._invalidate()
        self.store.record_decision(self.server_id, name, "reject", q.hash, self.actor, note)
        self._event("tool_rejected", "info", {"hash": q.hash}, name)
        return q.hash

    def revoke(self, name: str, *, note: str = "") -> bool:
        approved = self.approved().get(name)
        if approved is None:
            return False
        self.store.delete_approved(self.server_id, name)
        self._invalidate()
        self.store.record_decision(self.server_id, name, "revoke", approved.hash, self.actor, note)
        self._event("tool_revoked", "info", {"hash": approved.hash}, name)
        return True

    # ------------------------------------------------------------------ invocation
    def check_call(
        self,
        name: str,
        arguments: Mapping[str, Any] | None,
        current_tools: list[Mapping[str, Any]] | None = None,
    ) -> Verdict:
        verdict = self._check_call(name, arguments or {}, current_tools)
        if not verdict.allowed:
            detail: dict[str, Any] = {"reasons": verdict.reasons}
            if verdict.findings:  # credential findings carry only redacted excerpts
                detail["findings"] = [str(f) for f in verdict.findings]
            self._event("call_blocked", "high" if verdict.findings else "medium", detail, name)
        return verdict

    def _check_call(self, name, arguments, current_tools) -> Verdict:
        approved = self.approved().get(name)
        if approved is None:
            return Verdict.block(f"tool '{name}' is not approved")
        if current_tools is not None:
            current, dups = index_tools(current_tools)
            if name in dups:
                return Verdict.block(f"server advertises '{name}' more than once")
            if name not in current:
                return Verdict.block(f"tool '{name}' is no longer advertised by the server")
            if tool_hash(current[name]) != approved.hash:
                return Verdict.block(f"definition of '{name}' changed since approval; tool is quarantined")
        if not isinstance(arguments, Mapping):
            return Verdict.block("arguments must be a JSON object")
        errors = validate(self._validator(approved, "input"), dict(arguments))
        if errors:
            return Verdict.block(*(f"invalid argument {e}" for e in errors))
        if self.policy.block_secrets_in_arguments:
            secrets = scan_secrets(dict(arguments), "arguments")
            if secrets:
                rules = ", ".join(sorted({f.rule for f in secrets}))
                return Verdict.block(f"arguments contain what looks like a credential ({rules})", findings=secrets)
        return Verdict.ok()

    def check_result(self, name: str, result: Mapping[str, Any]) -> Verdict:
        verdict = self._check_result(name, result)
        if not verdict.allowed:
            detail: dict[str, Any] = {"reasons": verdict.reasons, "findings": [str(f) for f in verdict.findings]}
            if verdict.details:
                detail["details"] = verdict.details
            self._event("result_blocked", "high" if verdict.findings else "medium", detail, name)
        elif verdict.findings:
            self._event("result_flagged", "medium", {"findings": [str(f) for f in verdict.findings]}, name)
        return verdict

    def _check_result(self, name: str, result: Mapping[str, Any]) -> Verdict:
        approved = self.approved().get(name)
        if approved is None:
            return Verdict.block(f"tool '{name}' is not approved")
        # Reasons are fixed strings (no server text): the proxy may show them to the model.
        # Anything that quotes the server's result goes into ``details`` for the audit log.
        p = self.policy
        reasons: list[str] = []
        details: list[str] = []
        structured = result.get("structuredContent")
        schema = approved.local_output_schema
        is_error = bool(result.get("isError"))

        if structured is not None:
            try:
                size = len(json.dumps(structured, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            except (TypeError, ValueError):
                return Verdict.block("structuredContent is not valid JSON")
            if size > p.max_structured_bytes:
                # Refuse before validating or scanning, so the work done on a result stays bounded.
                return Verdict.block(
                    f"structuredContent exceeds {p.max_structured_bytes} bytes",
                    details=[f"structuredContent is {size} bytes"],
                )

        if schema is not None and not is_error:
            if structured is None:
                reasons.append("result has no structuredContent but the approved tool declares an output schema")
            else:
                errors = validate(self._validator(approved, "output"), structured)
                if errors:
                    reasons.append("output does not match the approved output schema")
                    details += [f"output {e}" for e in errors]
        elif structured is not None and schema is None and p.require_output_schema:
            reasons.append("structuredContent returned by a tool without an approved output schema")

        findings: list[Finding] = []
        if structured is not None:
            findings += scan_value(structured, "structuredContent")

        for i, block in enumerate(result.get("content") or []):
            btype = block.get("type")
            if btype not in p.allowed_content_types:
                reasons.append(f"content[{i}] has a disallowed content type")
                details.append(f"content[{i}] type {str(btype)[:40]!r}")
                continue
            if btype != "text":
                continue
            text = block.get("text", "")
            if len(text) > p.max_text_length:
                reasons.append(f"content[{i}] text exceeds {p.max_text_length} characters")
                continue
            if p.strict_text_mirror and schema is not None and structured is not None and not is_error:
                try:
                    mirrored = json.loads(text)
                except ValueError:
                    mirrored = None
                if mirrored is None or not canonical_equal(mirrored, structured):
                    reasons.append(f"content[{i}] text does not mirror the validated structuredContent")
                    continue
            findings += scan_text(text, f"content[{i}].text")

        if reasons:
            return Verdict.block(*reasons, findings=findings, details=details)
        if findings and p.block_suspicious_output:
            return Verdict.block("result contains instruction-like content", findings=findings)
        return Verdict(True, [], findings)
