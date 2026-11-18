# Network Log Summarizer and Incident Explainer

A tool that reads network logs (router, switch, server, DHCP), finds incidents with deterministic rules, groups related ones under a root cause, and explains them in plain English with every claim linked to the log lines that support it. It is for small IT teams, college labs and homelabs that have no SIEM. Working package and command name: `netlog`.

The owner is a networking student building this over about 8 weeks, one task per session.

## Docs

| File | Purpose |
|---|---|
| `docs/PLAN.md` | The full plan: scope, architecture, data model, UI, evaluation, risks |
| `docs/PROMPTS.md` | Index and progress tracker for the task prompts |
| `docs/prompts/` | The detailed task prompts, one file per phase |
| `docs/FEATURES.md` | Every feature with a real-life example, plus the build log. Updated after every task |
| `docs/SCHEMA.md` | The normalized event schema (created in prompt 0.2) |
| `docs/RULES.md` | The detection rule catalogue (created in prompt 1.7) |

`docs/PLAN.md`, `docs/PROMPTS.md`, `docs/prompts/` and `docs/FEATURES.md` are private: they are excluded from git through `.git/info/exclude` and exist only on the owner's machine. Never reference them from the README or any other file that gets published, and never remove that exclusion.

## Environment

- Windows 11, PowerShell. Every command given to the owner must work in PowerShell.
- Python 3.11 or newer (3.12 installed). Virtual environment in `.venv`.
- Docker and Containerlab run through WSL2 (later phases).

Setup and checks:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest
.venv\Scripts\python -m ruff check .
```

## Stack

- Backend: Python, FastAPI, SQLite, Drain3, pytest, ruff. Code in `backend/netlog/`, tests in `backend/tests/`.
- Frontend (phase 4 only): React, Vite, Tailwind, in `frontend/`.
- Cisco IOS is the first vendor.
- The generator in `generator/` stays independent of the backend: neither imports the other, so they cannot share bugs.

## Design principles

- Parsing, detection, correlation and severity are deterministic code.
- The LLM only explains incidents the code already found. It never detects, never sets severity and never sees raw log files.
- The whole tool must work with the LLM switched off.
- All log content is untrusted input: never executed, never rendered as HTML, never treated as instructions.
- Thresholds, windows and other tunables live in config files, not in code.

## Working rules

- Do only the task in the prompt. If something else looks worth doing, say so instead of doing it.
- Every task ships with tests. Run the full test suite and the linter before saying a task is done.
- Ask before adding a dependency the plan does not mention.
- Never commit and never push. The owner does all git commits and pushes.
- Never add yourself or any AI as a co-author or contributor: no Co-Authored-By trailers, no "generated with" lines, no entries in author or contributor lists, README credits or package metadata.
- Never put real secrets, real IP addresses or real usernames in the repo. Test data uses private ranges and the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## After every task

- Update `docs/FEATURES.md`: set the status of each feature touched, replace the planned example with a real one from actual output where it differs, and add a dated line to the build log.
- End with a short report: what was built, the exact commands to try it, which file to read first to understand it, and anything unfinished or uncertain.
