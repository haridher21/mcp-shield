"""Command-line approval interface.

    mcpshield [--db FILE] [--server-id ID] <command> ...

Commands that talk to the upstream server take its launch command after `--`:

    mcpshield scan  -- python demo/weather_server.py
    mcpshield serve -- python demo/weather_server.py
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

import anyio

from .diff import escape_text
from .shield import Shield
from .store import Store

STATE_LABEL = {
    "approved": "APPROVED   ",
    "quarantined-new": "BLOCKED new",
    "quarantined-modified": "QUARANTINED",
    "rejected": "REJECTED   ",
    "removed": "removed    ",
    "duplicate": "DUPLICATE  ",
}


def _upstream(cmd: list[str]):
    from mcp import StdioServerParameters

    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        sys.exit("error: give the upstream server command after `--`, e.g. -- python demo/weather_server.py")
    return StdioServerParameters(command=cmd[0], args=cmd[1:], env=dict(os.environ))


async def _fetch(cmd: list[str]) -> list[dict[str, Any]]:
    from mcp import Client

    from .proxy import fetch_tools

    async with Client(_upstream(cmd)) as client:
        return await fetch_tools(client)


def cmd_scan(shield: Shield, args) -> int:
    tools = anyio.run(_fetch, args.upstream)
    report = shield.sync(tools)
    print(f"server '{shield.server_id}': {len(tools)} tool(s), manifest {report.manifest_hash[:16]}")
    for s in report.statuses:
        sev = f"  [{s.severity}]" if s.state != "approved" else ""
        print(f"  {STATE_LABEL.get(s.state, s.state)}  {escape_text(s.name):<24} {(s.hash or '')[:12]}{sev}")
    current = {t["name"]: t for t in tools}
    if report.diff.has_changes:
        print()
        from .diff import render_tool_diff

        for td in report.diff.all():
            print(render_tool_diff(td, definition=current.get(td.name)))
            print()
        pending = [s.name for s in report.statuses if s.state.startswith("quarantined")]
        if pending:
            print("Review with `mcpshield diff TOOL`, then `mcpshield approve TOOL` or `mcpshield reject TOOL`.")
    return 1 if report.blocked else 0


def cmd_pending(shield: Shield, args) -> int:
    q = shield.store.get_quarantined(shield.server_id)
    if not q:
        print("Nothing in quarantine.")
        return 0
    for item in q.values():
        print(f"  {item.status:<8} {item.reason:<9} {escape_text(item.name):<24} {item.hash[:12]}  since {item.first_seen}")
    return 0


def cmd_diff(shield: Shield, args) -> int:
    try:
        print(shield.pending_diff(args.tool))
    except KeyError as exc:
        print(exc.args[0])
        return 1
    return 0


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def cmd_approve(shield: Shield, args) -> int:
    names = list(shield.store.get_quarantined(shield.server_id)) if args.all else args.tools
    if not names:
        print("Nothing to approve.")
        return 0
    rc = 0
    for name in names:
        try:
            print(shield.pending_diff(name))
        except KeyError as exc:
            print(exc.args[0])
            rc = 1
            continue
        if not args.yes and not _confirm(f"Approve this definition of '{escape_text(name)}'?"):
            print("  skipped")
            continue
        try:
            h = shield.approve(name, expected_hash=args.hash, note=args.note or "")
            print(f"  approved '{escape_text(name)}' ({h[:12]})")
        except (KeyError, ValueError) as exc:
            print(f"  {exc}")
            rc = 1
    return rc


def cmd_reject(shield: Shield, args) -> int:
    try:
        h = shield.reject(args.tool, note=args.note or "")
    except KeyError as exc:
        print(exc.args[0])
        return 1
    print(f"rejected '{args.tool}' ({h[:12]}); it stays blocked until a different definition is approved")
    return 0


def cmd_revoke(shield: Shield, args) -> int:
    if shield.revoke(args.tool, note=args.note or ""):
        print(f"revoked approval for '{args.tool}'")
        return 0
    print(f"'{args.tool}' is not approved")
    return 1


def cmd_status(shield: Shield, args) -> int:
    approved = shield.store.get_approved(shield.server_id)
    if not approved:
        print("No approved tools.")
    for a in approved.values():
        out = "strict output schema" if a.local_output_schema else "no output schema"
        print(f"  {escape_text(a.name):<24} {a.hash[:12]}  approved {a.approved_at} by {a.approved_by}  ({out})")
    q = shield.store.get_quarantined(shield.server_id)
    if q:
        print(f"{len(q)} tool(s) in quarantine; see `mcpshield pending`.")
    return 0


def cmd_events(shield: Shield, args) -> int:
    for e in reversed(shield.store.events(shield.server_id, args.limit, args.kind)):
        detail = e["detail"]
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict) and "diff" in parsed and not args.verbose:
                parsed = {k: v for k, v in parsed.items() if k != "diff"}
            # Event details can quote the server; ensure_ascii escapes control, bidi and non-ASCII characters.
            detail = json.dumps(parsed, ensure_ascii=True)
        except ValueError:
            detail = escape_text(detail)
        tool = escape_text(e["tool"]) if e["tool"] else "-"
        print(f"{e['ts']}  {e['severity']:<6} {e['kind']:<20} {tool:<16} {detail[:200]}")
    return 0


def cmd_output_schema(shield: Shield, args) -> int:
    with open(args.file, encoding="utf-8") as f:
        schema = json.load(f)
    if not shield.store.set_local_output_schema(shield.server_id, args.tool, shield._harden(schema)):
        print(f"'{args.tool}' is not approved")
        return 1
    print(f"local output schema for '{args.tool}' replaced (hardened)")
    return 0


def _parse_call_args(items: list[str]) -> dict[str, Any]:
    """Accept either one JSON object or shell-friendly key=value pairs.

    key=value avoids PowerShell 5.1 stripping the quotes out of JSON arguments.
    Values are parsed as JSON when possible (so n=3 is a number), else kept as strings.
    """
    if len(items) == 1 and items[0].lstrip().startswith("{"):
        return json.loads(items[0])
    out: dict[str, Any] = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            sys.exit(f"error: expected key=value, got {item!r}")
        try:
            out[key] = json.loads(value)
        except ValueError:
            out[key] = value
    return out


def cmd_call(shield: Shield, args) -> int:
    """One-shot guarded invocation, useful for demos without an AI application."""
    from mcp import Client

    from .proxy import build_proxy_server

    if "--" not in args.rest:
        sys.exit("error: usage: mcpshield call TOOL key=value ... -- SERVER_COMMAND")
    split = args.rest.index("--")
    arguments = _parse_call_args(args.rest[:split])
    args.upstream = args.rest[split + 1 :]

    async def run():
        async with Client(_upstream(args.upstream)) as up:
            async with Client(build_proxy_server(up, shield)) as client:
                return await client.call_tool(args.tool, arguments)

    result = anyio.run(run)
    if result.structured_content is not None:
        print(json.dumps(result.structured_content, indent=2))
    else:
        for block in result.content:
            print(getattr(block, "text", block))
    return 1 if result.is_error else 0


def cmd_serve(shield: Shield, args) -> int:
    from .proxy import serve_stdio

    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="mcpshield: %(message)s")
    anyio.run(serve_stdio, _upstream(args.upstream), shield)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcpshield", description="Pin, diff and enforce MCP tool definitions.")
    p.add_argument("--db", default=os.environ.get("MCPSHIELD_DB", "mcpshield.db"), help="SQLite file")
    p.add_argument("--server-id", default=os.environ.get("MCPSHIELD_SERVER", "default"))
    p.add_argument("--actor", default=os.environ.get("USERNAME") or os.environ.get("USER") or "cli")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="fetch tools, detect changes, quarantine them")
    s.add_argument("upstream", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_scan)

    sub.add_parser("pending", help="list quarantined definitions").set_defaults(fn=cmd_pending)

    s = sub.add_parser("diff", help="show a readable diff for a quarantined tool")
    s.add_argument("tool")
    s.set_defaults(fn=cmd_diff)

    s = sub.add_parser("approve", help="approve quarantined definition(s)")
    s.add_argument("tools", nargs="*")
    s.add_argument("--all", action="store_true", help="every quarantined tool")
    s.add_argument("--yes", "-y", action="store_true", help="do not prompt")
    s.add_argument("--hash", help="only approve if the quarantined hash starts with this")
    s.add_argument("--note")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("reject", help="reject a quarantined definition")
    s.add_argument("tool")
    s.add_argument("--note")
    s.set_defaults(fn=cmd_reject)

    s = sub.add_parser("revoke", help="withdraw an existing approval")
    s.add_argument("tool")
    s.add_argument("--note")
    s.set_defaults(fn=cmd_revoke)

    sub.add_parser("status", help="list approved tools").set_defaults(fn=cmd_status)

    s = sub.add_parser("events", help="show the security event log")
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--kind")
    s.add_argument("--verbose", "-v", action="store_true")
    s.set_defaults(fn=cmd_events)

    s = sub.add_parser("output-schema", help="replace the locally approved output schema of a tool")
    s.add_argument("tool")
    s.add_argument("file")
    s.set_defaults(fn=cmd_output_schema)

    s = sub.add_parser("call", help="invoke one tool through the shield")
    s.add_argument("tool")
    s.add_argument(
        "rest",
        nargs=argparse.REMAINDER,
        help="key=value pairs (city=Paris) or one JSON object, then -- and the server command",
    )
    s.set_defaults(fn=cmd_call)

    s = sub.add_parser("serve", help="run as a stdio MCP proxy in front of the upstream server")
    s.add_argument("upstream", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = Store(args.db)
    try:
        return args.fn(Shield(store, args.server_id, actor=args.actor), args)
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
