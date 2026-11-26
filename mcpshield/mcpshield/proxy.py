"""MCP adapter: the gateway between an AI application and one upstream MCP server.

    AI application  <-stdio->  MCPShield proxy  <-stdio->  upstream MCP server

Only the tools channel is mediated. The proxy does not forward resources,
prompts or upstream notifications.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import mcp.types as types
from mcp import Client, StdioServerParameters
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from . import __version__
from .shield import Shield, Verdict

log = logging.getLogger("mcpshield")


def tool_to_dict(tool: types.Tool) -> dict[str, Any]:
    return tool.model_dump(by_alias=True, exclude_none=True, mode="json")


def result_to_dict(result: types.CallToolResult) -> dict[str, Any]:
    return result.model_dump(by_alias=True, exclude_none=True, mode="json")


async def fetch_tools(client: Client) -> list[dict[str, Any]]:
    """Fetch the complete tool catalog, bypassing the SDK's client-side cache."""
    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    while True:
        page = await client.list_tools(cursor=cursor, cache_mode="bypass")
        tools.extend(tool_to_dict(t) for t in page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools


def blocked_result(verdict: Verdict, stage: str) -> types.CallToolResult:
    # Deliberately do NOT echo the offending upstream content back to the model:
    # result-side reasons are fixed strings and rule names; verdict.details stays in the audit log.
    reasons = "; ".join(verdict.reasons[:5]) or "policy violation"
    if verdict.findings and not verdict.reasons[1:]:
        reasons += " [" + ", ".join(sorted({f.rule for f in verdict.findings})) + "]"
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"MCPShield blocked this {stage}: {reasons}")],
        is_error=True,
    )


def build_proxy_server(upstream: Client, shield: Shield, name: str = "mcpshield") -> Server:
    def deadline():
        # A hung or deliberately slow upstream must not stall the AI application.
        return anyio.fail_after(shield.policy.upstream_timeout)

    async def on_list_tools(ctx, params) -> types.ListToolsResult:
        with deadline():
            tools = await fetch_tools(upstream)
        report = shield.sync(tools)
        if report.blocked:
            log.warning("MCPShield is withholding tools: %s", ", ".join(report.blocked))
        visible = shield.visible_tools(tools)
        return types.ListToolsResult(tools=[types.Tool.model_validate(t) for t in visible])

    async def on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name_ = params.name
        args = params.arguments or {}
        current = None
        if shield.policy.recheck_definitions_on_call:
            try:
                with deadline():
                    current = await fetch_tools(upstream)
            except TimeoutError:
                detail = f"tools/list re-check got no response within {shield.policy.upstream_timeout}s"
                log.warning("%s (call to '%s')", detail, name_)
                shield.store.log_event(shield.server_id, "upstream_timeout", "medium", detail, name_)
                return blocked_result(Verdict.block("could not re-check tool definitions: upstream timed out"), "call")
            shield.sync(current)
        verdict = shield.check_call(name_, args, current)
        if not verdict.allowed:
            return blocked_result(verdict, "call")
        try:
            with deadline():
                result = await upstream.call_tool(name_, args)
        except TimeoutError:
            detail = f"tools/call got no response within {shield.policy.upstream_timeout}s"
            log.warning("upstream call to '%s' timed out", name_)
            shield.store.log_event(shield.server_id, "upstream_timeout", "medium", detail, name_)
            return blocked_result(Verdict.block("upstream call timed out"), "result")
        except Exception as exc:  # upstream/transport failure (incl. SDK-side output checks): fail closed
            detail = f"{type(exc).__name__}: {str(exc)[:300]}"
            log.warning("upstream call to '%s' failed: %s", name_, detail)
            shield.store.log_event(shield.server_id, "upstream_error", "medium", detail, name_)
            return blocked_result(Verdict.block("upstream call failed"), "result")
        rd = result_to_dict(result)
        verdict = shield.check_result(name_, rd)
        if not verdict.allowed:
            return blocked_result(verdict, "result")
        # Forward only the validated wire representation.
        return types.CallToolResult.model_validate(rd)

    return Server(name, version=__version__, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def serve_stdio(upstream: StdioServerParameters, shield: Shield) -> None:
    async with Client(upstream) as client:
        server = build_proxy_server(client, shield)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
