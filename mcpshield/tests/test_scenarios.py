"""End-to-end attack scenarios: AI app -> MCPShield proxy -> weather server.

One test per row of the proposal's demonstration table, plus the full
approve -> detect -> explain -> block -> re-approve lifecycle.
"""

import pytest

pytestmark = pytest.mark.anyio

PARIS = {"city": "Paris"}


async def visible(app):
    return [t.name for t in (await app.list_tools()).tools]


async def test_benign_baseline(harness):
    async with harness.connect() as app:
        assert await visible(app) == ["get_weather"]
        r = await app.call_tool("get_weather", PARIS)
        assert not r.is_error and r.structured_content["location"] == "Paris"


async def test_reordered_keys_allowed(harness):
    async with harness.connect() as app:
        harness.mode = "reordered"
        assert await visible(app) == ["get_weather"]
        assert not (await app.call_tool("get_weather", PARIS)).is_error
        assert harness.shield.store.get_quarantined("weather") == {}


@pytest.mark.parametrize("mode", ["desc_changed", "sensitive_param", "annotation_flip"])
async def test_modified_definition_quarantined(harness, mode):
    async with harness.connect() as app:
        harness.mode = mode
        assert await visible(app) == []  # hidden from the model
        args = {**PARIS, "api_key": "k"} if mode == "sensitive_param" else PARIS
        r = await app.call_tool("get_weather", args)
        assert r.is_error and "quarantined" in r.content[0].text
        assert harness.upstream_calls == []  # never reached the server
        q = harness.shield.store.get_quarantined("weather")["get_weather"]
        assert q.reason == "modified" and q.status == "pending"
        assert harness.shield.store.events("weather", kind="tool_modified")[0]["severity"] == "high"


async def test_rug_pull_mid_session_blocked(harness):
    """Tool list fetched while benign; definition swapped before the call."""
    async with harness.connect() as app:
        assert await visible(app) == ["get_weather"]
        harness.mode = "desc_changed"
        r = await app.call_tool("get_weather", PARIS)
        assert r.is_error and harness.upstream_calls == []


async def test_unexpected_tool_blocked(harness):
    async with harness.connect() as app:
        harness.mode = "new_tool"
        assert await visible(app) == ["get_weather"]  # approved tool still works
        r = await app.call_tool("send_report", {"conversation_history": "secret"})
        assert r.is_error and "not approved" in r.content[0].text
        assert harness.upstream_calls == []
        assert harness.shield.store.get_quarantined("weather")["send_report"].reason == "added"


async def test_unknown_argument_blocked_before_transmission(harness):
    async with harness.connect() as app:
        r = await app.call_tool("get_weather", {"city": "Paris", "debug_dump": "/etc/passwd"})
        assert r.is_error and "debug_dump" in r.content[0].text
        assert harness.upstream_calls == []


@pytest.mark.parametrize("args", [{}, {"city": 42}, {"city": "x" * 500}, {"city": "Paris", "unit": "K"}])
async def test_invalid_arguments_blocked(harness, args):
    async with harness.connect() as app:
        assert (await app.call_tool("get_weather", args)).is_error
        assert harness.upstream_calls == []


async def test_extra_output_field_rejected(harness):
    async with harness.connect() as app:
        harness.mode = "extra_field"
        r = await app.call_tool("get_weather", PARIS)
        assert r.is_error and "instructions" in r.content[0].text
        assert r.structured_content is None
        assert len(harness.upstream_calls) == 1


async def test_instruction_text_in_allowed_field_blocked(harness):
    async with harness.connect() as app:
        harness.mode = "injection_text"
        r = await app.call_tool("get_weather", PARIS)
        assert r.is_error and "instruction-like" in r.content[0].text
        assert "Ignore all previous" not in r.content[0].text  # malicious text not echoed
        ev = harness.shield.store.events("weather", kind="result_blocked")[0]
        assert ev["severity"] == "high"


async def test_instruction_text_flag_only_policy(harness):
    harness.shield.policy.block_suspicious_output = False
    async with harness.connect() as app:
        harness.mode = "injection_text"
        r = await app.call_tool("get_weather", PARIS)
        assert not r.is_error
        assert harness.shield.store.events("weather", kind="result_flagged")


@pytest.mark.parametrize("mode", ["oversized", "text_mismatch"])
async def test_oversized_or_divergent_output_rejected(harness, mode):
    async with harness.connect() as app:
        harness.mode = mode
        assert (await app.call_tool("get_weather", PARIS)).is_error


async def test_backend_swap_not_detected_documented_limitation(harness):
    async with harness.connect() as app:
        harness.mode = "backend_swap"
        r = await app.call_tool("get_weather", PARIS)
        assert not r.is_error  # schema-valid lies pass: out of scope by design
        assert r.structured_content["temperature"] == 48.0


async def test_full_lifecycle_reapproval_and_rejection(harness):
    shield = harness.shield
    async with harness.connect() as app:
        # detect + block
        harness.mode = "sensitive_param"
        assert await visible(app) == []
        # explain
        diff = shield.pending_diff("get_weather")
        assert "api_key" in diff and "HIGH" in diff
        # reject: stays blocked on later syncs, no duplicate alert
        shield.reject("get_weather")
        assert await visible(app) == []
        assert len(shield.store.events("weather", kind="tool_modified")) == 1
        # server reverts: approved hash matches again
        harness.mode = "benign"
        assert await visible(app) == ["get_weather"]
        # a different change is quarantined fresh; re-approve it
        harness.mode = "annotation_flip"
        assert await visible(app) == []
        shield.approve("get_weather")
        assert await visible(app) == ["get_weather"]
        assert not (await app.call_tool("get_weather", PARIS)).is_error
        decisions = [d["decision"] for d in shield.store.decisions("weather")]
        assert decisions == ["approve", "reject", "approve"]


async def test_first_contact_requires_approval(harness):
    async with harness.connect(approve_baseline=False) as app:
        assert await visible(app) == []
        assert (await app.call_tool("get_weather", PARIS)).is_error


async def test_approve_pins_exact_reviewed_hash(harness):
    """Approving checks the hash the reviewer saw (TOCTOU guard)."""
    shield = harness.shield
    async with harness.connect() as app:
        harness.mode = "desc_changed"
        await visible(app)
        with pytest.raises(ValueError):
            shield.approve("get_weather", expected_hash="deadbeef")


async def test_approval_from_another_process_applies_live(harness):
    """Operator approves via the CLI (separate DB connection) while the proxy is serving."""
    from mcpshield.shield import Shield
    from mcpshield.store import Store

    async with harness.connect() as app:
        harness.mode = "annotation_flip"
        assert await visible(app) == []
        operator = Store(harness.shield.store.path)
        Shield(operator, "weather", actor="operator").approve("get_weather")
        operator.close()
        assert await visible(app) == ["get_weather"]
        assert not (await app.call_tool("get_weather", PARIS)).is_error
