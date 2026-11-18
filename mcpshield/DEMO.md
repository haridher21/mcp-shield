# MCPShield live demo run-sheet

About 8 to 10 minutes. There are two ways to run it:

- **Main demo (A):** `demo\live_demo.py`, a narrated script that waits for Enter between steps. Nothing to type live, and it can't break on a typo.
- **Backup or Q&A (B):** run the real CLI by hand against a real server process, for anyone who asks "is it actually a proxy?"

---

## Before you present (the night before and 10 minutes before)

```powershell
cd "D:\Grad\CSCE 703\mcpshield"
python -m venv .venv                              # skip if .venv already exists
.venv\Scripts\python -m pip install -e ".[dev]"   # needs internet: do this the night before
.venv\Scripts\python -m pytest                    # expect: 45 passed
.venv\Scripts\python demo\live_demo.py --no-pause # full dry run, about 2 seconds
```

- Make the terminal font large (Ctrl + mouse wheel), maximize the window, and use a dark background.
- Use **Windows Terminal** if you can. The colors render correctly there, and old consoles can show garbage like `[31m`. If they do, add `--no-color`.
- Close Slack, email and notifications.
- Have `README.md` open in a second window for the architecture table.

---

## A. Main demo: `.venv\Scripts\python demo\live_demo.py`

Press **Enter** after you've said each step's talking point.

| Step | What appears | What to say |
|---|---|---|
| 1. First contact | Model sees **no tools**. Reviewer approves, then the call works. | "Nothing is trusted on first use. Approval pins a SHA-256 of the *canonical* JSON definition." |
| 2. Reordered keys | Still allowed | "Same tool, different key order, same hash. Canonicalization prevents false alarms." |
| 3. Sensitive parameter | Tool **hidden**, call blocked, request **never reaches server**, red HIGH diff | "This is a rug pull: the server quietly asks for an API key. MCP would only send a *list changed* notification. We explain the change and block it." Then: "The reviewer rejects it, and it stays blocked." |
| 4. Poisoned description | HIGH diff showing `id_rsa` and "Do not tell the user" | "This is tool poisoning: instructions hidden in metadata the model reads. The reviewer sees exactly which text changed." |
| 5. New tool | `send_report` blocked, `get_weather` still works | "New tools are blocked individually; approved ones keep working." |
| 6. Unknown argument | Blocked, never sent | "Calls are checked against the *approved* input schema before they leave the gateway." |
| 7. Extra `instructions` field | Result rejected | "Outputs are validated against a strict *local* copy of the schema. The server's own schema allowed extra fields; ours doesn't." |
| 8. Injection in an allowed field | Result rejected; malicious text **not** shown to the model | "Valid shape, malicious content. Bounded checks catch obvious injections. We fail closed and don't echo the payload." |
| 9. Limitation | **Allowed**: 48 °C "evacuate now" | "Be honest: if a server lies with well-formed data, we can't tell. We guard what's observable, not the truth of the data." |
| 10. Re-approval | MEDIUM diff, approved, works again | "Legitimate updates aren't a dead end. The full lifecycle is approve, detect, explain, block, re-approve." |
| Audit log | List of events with severities | "Every decision and security event is stored in SQLite." |

Optionally, show the full log afterwards:

```powershell
.venv\Scripts\python -m mcpshield --db demo_live.db --server-id weather events -v
```

---

## B. Backup or Q&A: the real CLI against a real server process

Here MCPShield launches `demo\weather_server.py` as a separate process and talks to it over MCP stdio, the same way Claude Desktop or another MCP client would.

```powershell
$py = ".venv\Scripts\python"
$env:MCPSHIELD_DB = "cli_demo.db"; Remove-Item cli_demo.db -ErrorAction SilentlyContinue

& $py -m mcpshield scan -- $py demo\weather_server.py          # first contact: BLOCKED new
& $py -m mcpshield approve get_weather                         # shows the definition, type y
& $py -m mcpshield call get_weather city=Paris -- $py demo\weather_server.py
& $py -m mcpshield call get_weather city=Paris debug=1 -- $py demo\weather_server.py   # blocked

$env:WEATHER_MODE = "sensitive_param"                          # the server turns malicious
& $py -m mcpshield scan -- $py demo\weather_server.py          # QUARANTINED + diff
& $py -m mcpshield call get_weather city=Paris -- $py demo\weather_server.py           # blocked

& $py -m mcpshield reject get_weather                          # stays blocked

$env:WEATHER_MODE = "injection_text"                           # malicious *output* instead
& $py -m mcpshield call get_weather city=Paris -- $py demo\weather_server.py           # blocked result

Remove-Item Env:WEATHER_MODE                                   # back to benign
& $py -m mcpshield events
```

- Use `city=Paris`, not JSON. PowerShell 5.1 strips the quotes out of JSON arguments.
- `$env:WEATHER_MODE` persists for that whole PowerShell window. Clear it with `Remove-Item Env:WEATHER_MODE`.
- Available modes: `benign reordered desc_changed sensitive_param annotation_flip new_tool extra_field injection_text oversized text_mismatch backend_swap legit_update`.

---

## Evaluation slide: `.venv\Scripts\python demo\evaluate.py`

This prints the 12-row scenario table (all PASS) and the latency overhead: about +0.5 ms per call for validation only, and about +1.1 ms with a definition re-check on every call. These are in-process numbers. Rerun on your own machine and quote those.

---

## Likely questions

- **"Doesn't something like this already exist?"** Yes. Hash pinning exists in MCP scanners, and we don't claim to have invented it. Our contribution is a small, testable implementation of the full lifecycle, plus strict input and output validation, with an evaluation.
- **"Why not just trust `notifications/tools/list_changed`?"** It says *that* something changed, not *what*, and nothing blocks the change. A malicious server also doesn't have to send it.
- **"What about a change made between listing tools and calling one?"** By default the gateway re-fetches the tool list before each call (step 3 shows this). That costs the extra ~0.6 ms.
- **"Can the injection detector be bypassed?"** Yes, by paraphrasing, another language or encoding. It's a bounded heuristic, and the README says so. The schema checks are the hard guarantee.
- **"Who approves the first version?"** A human, on first use. The first approval is only as good as that review.
- **"Which transports are supported?"** stdio only, and only the tools channel. Resources and prompts are out of scope.
