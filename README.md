# MCPShield

A small, inspectable security gateway for the Model Context Protocol (MCP).

```
AI application  <--stdio-->  MCPShield  <--stdio-->  MCP server
```

MCPShield guards two channels the model relies on:

1. **Tool definitions.** It pins each approved tool by a SHA-256 over its canonical JSON, then detects, explains and quarantines any later change until a human approves or rejects it.
2. **Tool inputs and outputs.** It validates every call against the last approved input schema, and every structured result against a strict, locally approved output schema. Results with instruction-like content are blocked.

Lifecycle: **approve → detect → explain → block → re-approve**.

## Layout

| Module | Role |
|---|---|
| `mcpshield/canonical.py` | Deterministic JSON canonicalization (close to RFC 8785), tool and manifest hashing |
| `mcpshield/diff.py` | Field-level diff of definitions, severity rules, readable rendering |
| `mcpshield/validator.py` | Schema hardening, JSON Schema validation, bounded instruction-like content detection |
| `mcpshield/store.py` | SQLite: approved tools, quarantine, decisions, manifest snapshots, security events |
| `mcpshield/shield.py` | Approval and enforcement gate (no SDK dependency, so it is easy to unit-test) |
| `mcpshield/proxy.py` | MCP adapter: an official-SDK client to the upstream server, plus a server facing the AI app |
| `mcpshield/cli.py` | CLI approval interface |
| `demo/weather_server.py` | Controlled weather server with 11 switchable attack modes |
| `demo/evaluate.py` | Scenario table and latency-overhead benchmark |
| `tests/` | 45 pytest tests: unit tests and end-to-end attack scenarios |

## Setup

Requires Python 3.10+ and the official MCP Python SDK 2.3 or later.

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows; on macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## CLI walkthrough

```bash
# 1. First contact: every tool starts out blocked
python -m mcpshield scan -- python demo/weather_server.py

# 2. Review and approve (shows the definition, prompts y/N; --yes skips the prompt)
python -m mcpshield approve get_weather

# 3. Guarded call
python -m mcpshield call get_weather city=Paris -- python demo/weather_server.py

# 4. Simulate a rug pull: the server adds a sensitive parameter
WEATHER_MODE=sensitive_param python -m mcpshield scan -- python demo/weather_server.py
#   [HIGH] MODIFIED tool 'get_weather'  fccbcfb0466c -> 8f323ad28056
#     + inputSchema.properties.api_key   [high: new input parameter with a sensitive name]
#     + inputSchema.required.api_key     [high: parameter became required]

# 5. Decide
python -m mcpshield diff get_weather
python -m mcpshield reject get_weather            # or: approve get_weather --hash 8f323ad2

# Inspect
python -m mcpshield status | pending | events [-v]
```

Global options: `--db FILE` (default `mcpshield.db`, or the `MCPSHIELD_DB` environment variable) and `--server-id ID`.

### Using it in front of a real MCP client

Point the client at MCPShield instead of the server. For example, in an MCP client config:

```json
{
  "mcpServers": {
    "weather (shielded)": {
      "command": "python",
      "args": ["-m", "mcpshield", "--db", "/abs/path/mcpshield.db", "serve", "--",
               "python", "/abs/path/demo/weather_server.py"]
    }
  }
}
```

To demo a change mid-session, set `WEATHER_MODE_FILE=/path/mode.txt` on the server and edit the file while the client is connected. Approvals made from another terminal with the CLI take effect immediately; the proxy watches SQLite's `data_version`.

## Demonstration results (`python demo/evaluate.py`)

| Scenario | Expected | Observed | Reached server |
|---|---|---|---|
| Benign baseline | allowed | allowed | yes |
| JSON object keys reordered | allowed (same hash) | allowed | yes |
| Description poisoned | quarantined | quarantined | no |
| Sensitive input parameter added | quarantined | quarantined | no |
| Annotations flipped to destructive | quarantined | quarantined | no |
| Unexpected tool introduced | blocked | blocked | no |
| Unknown invocation argument | blocked before transmission | blocked | no |
| Response has extra `instructions` field | rejected | rejected | yes |
| Instruction-like text in an allowed field | rejected | rejected | yes |
| Oversized string in response | rejected | rejected | yes |
| Text block diverges from structured result | rejected | rejected | yes |
| Backend secretly returns false data | **not detected** (limitation) | allowed | yes |

Latency overhead, measured in-process with 300 calls on the dev laptop. Your numbers will differ.

| Path | Median (ms) | Overhead (ms) |
|---|---|---|
| Direct | 0.16 | n/a |
| MCPShield, validation only | 0.64 | +0.48 |
| MCPShield, plus a definition re-check on every call | 1.25 | +1.09 |

The per-call re-check (`Policy.recheck_definitions_on_call`) re-fetches `tools/list` before each call. It closes the window where a server changes a definition after the client has listed tools.

## Design decisions

- **Hash everything except irrelevant ordering.** Object key order and the order of the JSON Schema `required` array are normalized away. Whitespace, Unicode form (so homoglyphs count) and other list orders are treated as meaningful.
- **Quarantine means hidden.** Changed or new tools are removed from `tools/list` and calls to them are refused. The model never sees the unapproved text.
- **Approve the exact bytes reviewed.** An approval pins the quarantined definition by hash. `--hash` guards against the definition changing between review and approval (a TOCTOU race).
- **Strict local output schema.** At approval, the server's `outputSchema` is hardened: `additionalProperties: false`, and strings and arrays get capped `maxLength` and `maxItems`. It can be replaced with `mcpshield output-schema TOOL file.json`.
- **Text must mirror structured content.** When a tool has an output schema, each text block must be the JSON form of the validated `structuredContent`. Otherwise a server could put unvalidated text in a side channel the model reads.
- **Fail closed, don't echo.** Blocked results return a generic error to the model. The malicious content goes only to the event log.

## Limitations (deliberately out of scope)

- **Backend behavior.** A server that keeps its metadata and output schema-valid but returns false data, or does something harmful internally, is not detected (see the `backend_swap` scenario).
- **Heuristic text checks.** The instruction-like content patterns are bounded regexes. They catch obvious injections and can be evaded by paraphrasing, other languages or encodings. They do not guarantee that free text is safe.
- **Scope.** One transport (stdio) and the tools channel only. Resources, prompts, sampling and upstream notifications are not mediated.
- **Trust on first use.** The first approval is only as good as the human review behind it.
- **Canonicalization.** Keys are sorted by Unicode code point rather than JCS's UTF-16 code units, which differs only for characters outside the Basic Multilingual Plane. Forcing `additionalProperties: false` does not compose with `allOf`-style schemas.
- **Related work.** Hash-based pinning of tool definitions exists in other MCP scanners. The contribution here is a small, testable implementation of the full lifecycle, combined with strict input and output validation.

## Suggested team split (6 people)

| Area | Files |
|---|---|
| Protocol integration / proxy | `proxy.py`, client config, transport testing |
| Canonicalization and hashing | `canonical.py`, RFC 8785 conformance tests |
| Diff engine and severity rules | `diff.py`, rendering |
| Store, approval CLI | `store.py`, `cli.py` |
| Validation and content checks | `validator.py`, false-positive and false-negative study |
| Adversarial evaluation | `demo/`, `tests/test_scenarios.py`, overhead benchmark, limitations write-up |
