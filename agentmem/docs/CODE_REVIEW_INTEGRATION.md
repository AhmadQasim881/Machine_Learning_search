# Code-review integration — agentmem as an MCP server for Claude Desktop / Claude Code

This wires `agentmem` into Claude (Desktop **or** the Claude Code CLI) as a
persistent, chain-finding memory for long-horizon **source-code security review**.
Claude records taint facts as it reads code; the deterministic engine connects them
into `source → … → sink` chains; everything lives in one SQLite file so the model's
context stays small while memory grows across sessions.

> **Why this shape.** The model's context window is tiny next to a real codebase
> (a messenger, a server). Holding the whole program in the transcript is
> impossible and wasteful. Instead the heavy state lives in `agentmem`; Claude
> pulls back only what it needs (`get_context`, `recall`) and the chain engine does
> the cross-file, cross-session correlation the model cannot.

## 0. Prerequisites

- **Python 3.11+** (the `mcp` SDK requires ≥3.10; 3.11 is the safe floor).
- Install agentmem with the MCP extra, into a venv you control:

```bash
cd agentmem
python -m venv .venv && . .venv/bin/activate
pip install -e ".[mcp]"        # installs the `mcp` SDK (v2); the server also supports v1
```

The server supports both SDK lines via an import shim (`mcp>=2` exposes `MCPServer`,
`mcp<2` exposes `FastMCP`). Note the **absolute path to the venv's Python** — both
clients need it:

```bash
echo "$PWD/.venv/bin/python"   # e.g. /Users/you/agentmem/.venv/bin/python
```

## 1. Configuration (environment variables)

| Variable | Meaning | Default |
|---|---|---|
| `AGENTMEM_DB` | **Absolute** path to the SQLite memory file. Use **one DB per repo.** | `./agentmem.db` |
| `AGENTMEM_PROFILE` | `codereview` for taint analysis (use this), or `web`. | `web` |
| `AGENTMEM_EMBEDDINGS` | `1` to enable dependency-free semantic `recall`. | off |

Always use an **absolute** `AGENTMEM_DB`: clients start the server in an undefined
working directory (often `/`), so a relative path lands somewhere surprising.

## 2a. Claude Code CLI

```bash
# from inside the repo you want to review (scope: local = this project only)
claude mcp add \
  --env AGENTMEM_DB=/abs/path/telegram.db \
  --env AGENTMEM_PROFILE=codereview \
  --transport stdio agentmem \
  -- /abs/path/agentmem/.venv/bin/python -m agentmem.mcp_server
```

- The `--` is required so the server's own flags (`-m`) aren't parsed by Claude Code.
- Keep `--transport stdio` **between** the last `--env` and the server name
  (`agentmem`), or the name is misread as another env pair.
- Scope with `-s/--scope`: `local` (default, this project), `project` (writes a
  committable `.mcp.json`), or `user` (all your projects).
- Manage: `claude mcp list`, `claude mcp get agentmem`, `claude mcp remove agentmem`,
  and `/mcp` inside a session (use `/mcp` to reconnect if a stdio server drops).

Manual equivalent — `.mcp.json` at the project root (commit this for a shared setup;
`${VAR:-default}` expands in `command`/`args`/`env`):

```json
{
  "mcpServers": {
    "agentmem": {
      "type": "stdio",
      "command": "/abs/path/agentmem/.venv/bin/python",
      "args": ["-m", "agentmem.mcp_server"],
      "env": {
        "AGENTMEM_DB": "${AGENTMEM_DB:-/abs/path/telegram.db}",
        "AGENTMEM_PROFILE": "codereview"
      }
    }
  }
}
```

## 2b. Claude Desktop

Config file (open it from **Settings → Developer → Edit Config**):
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "agentmem": {
      "command": "/abs/path/agentmem/.venv/bin/python",
      "args": ["-m", "agentmem.mcp_server"],
      "env": {
        "AGENTMEM_DB": "/abs/path/telegram.db",
        "AGENTMEM_PROFILE": "codereview"
      }
    }
  }
}
```

- Windows: use `"C:\\Users\\you\\agentmem\\.venv\\Scripts\\python.exe"` (escaped
  backslashes) or forward slashes.
- If agentmem is not `pip install`ed into that venv, add
  `"PYTHONPATH": "/abs/path/to/agentmem"` to `env`.
- **Fully quit and reopen** the app to apply changes (closing the window is not
  enough: tray-quit on Windows, ⌘Q on macOS).
- Logs: `~/Library/Logs/Claude/mcp*.log` (macOS), `%APPDATA%\Claude\Logs\mcp*.log`
  (Windows).

## 3. Give Claude the review method

Point Claude at the review skill so it knows *how* to drive the memory:
- **Claude Code**: the skill ships at `agentmem/skills/code-review/SKILL.md`. Put it
  where your Claude Code picks skills up (e.g. `.claude/skills/`), or invoke it.
- **Claude Desktop**: paste the body of that `SKILL.md` into the project's custom
  instructions.

Then, to review (e.g. Telegram), open the cloned repo and prompt, roughly:

> Review this repository for security vulnerabilities using memory-driven code
> review. Start by calling `get_context`, then work subsystem by subsystem
> (entry-point handlers, parsers, auth, serializers), recording taint
> sources/flows/sinks/sanitizers as you read, and call `get_chains` / `next_probes`
> to find and close data-flow gaps. Run Opus at max effort.

The first session maps a subsystem and records facts; later sessions call
`get_context` and continue where memory left off — the DB is the running state of
the whole review.

## 4. The tools Claude will see

| Tool | Use |
|---|---|
| `get_context` | Reload what memory knows (call first each session). |
| `recall` | Ranked lookup by file/symbol/type (check before re-reading a file). |
| `record_source` / `record_flow` / `record_sink` / `record_sanitizer` | Record taint facts as code is read. |
| `get_chains` | The discovered `source→…→sink` chains (the finding list). |
| `next_probes` | The data-flow gap to trace next (dangling sink/source, orphan flow). |
| `observe` | Log the raw snippet/diff behind a fact (audit trail). |
| `reflect` | Consolidate: pin assets, persist hypotheses, rebuild summaries. |
| `invalidate` | Retract a false-positive fact (and any chain built on it). |
| `stats` | Health snapshot (confirm the DB path and that memory is growing). |
| `record_finding` | (web profile only) record a web bug-bounty finding. |

## 5. Gotchas (from the SDK + both clients)

- **stdout is the protocol channel.** The server logs only to stderr and never
  prints to stdout; don't add code that writes to stdout.
- **Absolute interpreter + absolute DB path.** Bare `python` may miss the venv;
  a relative DB lands in `/`.
- **Pass env explicitly** in the client config — Desktop inherits almost nothing.
- **Shutdown is fast** (SIGINT → SIGTERM → SIGKILL within ~0.5s). agentmem commits
  every write immediately, so no state is lost on exit.
- **Debug** with the MCP inspector: `AGENTMEM_DB=/tmp/x.db uv run mcp dev
  agentmem/agentmem/mcp_server.py` (needs `npx` on PATH).
- **Slow start**: `MCP_TIMEOUT=10000 claude` raises the startup timeout to 10s.

## 6. Smoke test (no client needed)

```bash
AGENTMEM_DB=/tmp/cr.db AGENTMEM_PROFILE=codereview \
  /abs/path/agentmem/.venv/bin/python - <<'PY'
from agentmem import mcp_server as S
print(S.record_source("h/msg.py", var="text", symbol="on_message", line=20))
print(S.record_flow("h/msg.py", var_in="text", var_out="cmd", line=24))
print(S.record_sink("exec/sh.py", var="cmd", sink_type="command", line=8))
print(S.get_chains())        # -> [sev 10] rce chain across the two files
print(S.next_probes())       # -> [] once the chain is complete
PY
```
