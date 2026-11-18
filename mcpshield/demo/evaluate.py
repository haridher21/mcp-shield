"""Run every demo scenario through MCPShield and measure gateway overhead.

    python demo/evaluate.py [--calls 300]

Everything runs in-process (no subprocess / pipe latency), so the timings
isolate the cost of MCPShield's own work.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import tempfile
import time
from pathlib import Path

import anyio
from mcp import Client

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcpshield.proxy import build_proxy_server, fetch_tools  # noqa: E402
from mcpshield.shield import Policy, Shield  # noqa: E402
from mcpshield.store import Store  # noqa: E402
from weather_server import build_server  # noqa: E402

# (label, mode, tool, arguments, expected outcome)
SCENARIOS = [
    ("Benign baseline", "benign", "get_weather", {"city": "Paris"}, "allowed"),
    ("JSON object keys reordered", "reordered", "get_weather", {"city": "Paris"}, "allowed"),
    ("Description poisoned", "desc_changed", "get_weather", {"city": "Paris"}, "quarantined"),
    ("Sensitive input parameter added", "sensitive_param", "get_weather", {"city": "Paris", "api_key": "x"}, "quarantined"),
    ("Annotations flipped to destructive", "annotation_flip", "get_weather", {"city": "Paris"}, "quarantined"),
    ("Unexpected tool introduced", "new_tool", "send_report", {"conversation_history": "..."}, "blocked"),
    ("Unknown invocation argument", "benign", "get_weather", {"city": "Paris", "debug_dump": "1"}, "blocked"),
    ("Response has extra `instructions` field", "extra_field", "get_weather", {"city": "Paris"}, "rejected"),
    ("Instruction-like text in allowed field", "injection_text", "get_weather", {"city": "Paris"}, "rejected"),
    ("Oversized string in response", "oversized", "get_weather", {"city": "Paris"}, "rejected"),
    ("Text block diverges from structured result", "text_mismatch", "get_weather", {"city": "Paris"}, "rejected"),
    ("Backend secretly returns false data", "backend_swap", "get_weather", {"city": "Paris"}, "allowed"),
]


async def run_scenario(mode: str, tool: str, args: dict) -> tuple[str, int]:
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "eval.db")
        shield = Shield(store, "weather", actor="eval")
        state = {"mode": "benign"}
        upstream_server = build_server(lambda: state["mode"])
        async with Client(upstream_server) as up:
            shield.sync(await fetch_tools(up))
            shield.approve("get_weather")
            async with Client(build_proxy_server(up, shield)) as app:
                state["mode"] = mode
                await app.list_tools()
                result = await app.call_tool(tool, args)
                reached = len(upstream_server.calls)
                quarantined = store.get_quarantined("weather")
        store.close()
    if not result.is_error:
        return "allowed", reached
    text = result.content[0].text
    if "quarantined" in text:
        return "quarantined", reached
    if "this call" in text:
        return "blocked", reached
    return "rejected", reached


async def time_calls(app: Client, n: int) -> list[float]:
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        await app.call_tool("get_weather", {"city": "Paris"})
        samples.append((time.perf_counter() - t0) * 1000)
    return samples


async def overhead(n: int) -> list[tuple[str, list[float]]]:
    results = []
    async with Client(build_server(lambda: "benign")) as direct:
        await direct.list_tools()
        results.append(("direct (no gateway)", await time_calls(direct, n)))
    for label, recheck in (("MCPShield, validation only", False), ("MCPShield, + definition re-check per call", True)):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "bench.db")
            shield = Shield(store, "weather", Policy(recheck_definitions_on_call=recheck))
            async with Client(build_server(lambda: "benign")) as up:
                shield.sync(await fetch_tools(up))
                shield.approve("get_weather")
                async with Client(build_proxy_server(up, shield)) as app:
                    await app.list_tools()
                    results.append((label, await time_calls(app, n)))
            store.close()
    return results


async def main(n: int) -> int:
    print("Scenario results\n")
    print(f"  {'Scenario':<44} {'Expected':<12} {'Observed':<12} {'Reached server':<15} OK")
    failures = 0
    for label, mode, tool, args, expected in SCENARIOS:
        observed, reached = await run_scenario(mode, tool, args)
        ok = observed == expected
        failures += not ok
        print(f"  {label:<44} {expected:<12} {observed:<12} {'yes' if reached else 'no':<15} {'PASS' if ok else 'FAIL'}")
    print("\n  Note: the backend_swap row is *expected* to pass through - schema-valid false data is out of scope.\n")

    print(f"Latency per get_weather call, {n} calls, in-process (ms)\n")
    rows = await overhead(n)
    base = statistics.median(rows[0][1])
    print(f"  {'Path':<44} {'median':>8} {'p95':>8} {'overhead':>10}")
    for label, s in rows:
        med = statistics.median(s)
        p95 = sorted(s)[int(len(s) * 0.95) - 1]
        print(f"  {label:<44} {med:8.3f} {p95:8.3f} {med - base:+9.3f}")
    return 1 if failures else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=300)
    sys.exit(anyio.run(main, ap.parse_args().calls))
