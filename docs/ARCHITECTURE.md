# Architecture

How a log line becomes an explained incident. The README gives the short version; this page goes through the pipeline one stage at a time, for a reader who wants to know why it is built the way it is.

```
log file or live syslog
   |
   v
 1. Read          lines out of a file, safely              ingestion/reader.py
 2. Parse         time, device, program, message type,     parsers/
                  interfaces, addresses, users
 3. Store         SQLite, one row per line                 storage/database.py
 4. Mine          similar lines become one pattern         mining/
 5. Detect        rules from a data file produce           detection/, config/rules.toml
                  findings, each with a severity
 6. Correlate     findings become incidents, ordered       correlation/, config/causal_priors.toml
                  into cause and effect
 7. Explain       an evidence pack, an LLM or a built-in   llm/, redaction/
                  template, a validator in between
   |
   v
report, web API and interface, live incidents, alerts      report/, api/, frontend/, live/, alerts/
```

Two rules hold across every stage:

- **Code decides, the LLM explains.** Stages 1 to 6 are deterministic: the same file always gives the same incidents, severities and root causes, and every one of them can be tested. The LLM in stage 7 is shown only what stage 6 decided, and it can be switched off without losing anything but the wording.
- **Log content is untrusted.** A username, a DHCP hostname or a DNS name is chosen by whoever sends it, possibly an attacker. It is never executed, never rendered as HTML, never treated as an instruction, and parsers are written so that it cannot imitate the fields around it.

Every threshold, window and limit mentioned below is a setting in `backend/netlog/config/defaults.toml` or `rules.toml`, not a constant in the code.

## 1. Read

`ingestion/reader.py` turns a file into numbered lines. It refuses files that look binary, decodes UTF-8 and UTF-16 (Windows PowerShell writes the second when output is redirected), replaces bytes it cannot decode instead of failing, and cuts lines longer than a limit, marking them as truncated. Blank lines are counted but produce no event.

Line numbers are kept from here to the end: every citation in an explanation is a line number of the original file, so a reader can always find the line.

## 2. Parse

Every line goes through the same chain (`parsers/pipeline.py`):

1. **The header** (`parsers/syslog.py`): RFC 3164 (`Mar  3 02:14:07 R1 ...`, with or without `<PRI>`, with or without a year), RFC 5424, and the ISO 8601 form recent rsyslog versions write. It gives the time, the host, the program and the message.
2. **The vendor message**: Cisco IOS codes (`%LINK-3-UPDOWN`, `parsers/cisco.py`), Cisco ASA and iptables (`parsers/firewall.py`), sshd, sudo and PAM (`parsers/linux_auth.py`), ISC dhcpd (`parsers/dhcp.py`), BIND and dnsmasq (`parsers/dns.py`). Each recognized message gets an **event key** (`LINK-3-UPDOWN`, `sshd.failed_password`, `ASA-106023`) and its fields: interface, neighbor, addresses, ports, user, MAC, and so on.

The result is one `Event` per line, in the shape described in [SCHEMA.md](SCHEMA.md). Three decisions matter here:

- **Nothing is dropped.** A line no parser understands becomes an event with status `unparsed`, and the share of lines understood is reported. A tool that silently skips what it does not know looks more accurate than it is.
- **Which time to trust.** A Cisco line stored by a collector has two times, the collector's and the device's. The device's is used, unless it is marked unsynchronized, is an uptime counter, or is more than 24 hours from the collector's. Classic syslog has no year and no timezone, so both are assumed and every event records that they were.
- **Anchoring against hostile text.** Usernames can contain anything, including `admin from 10.0.0.1 port 22`. Every pattern reads the fields a device appends (address, port) from the end of the line and lets the user-chosen part take what is left, and the parsers report where that part sits so later stages can mask it.

## 3. Store

`storage/database.py` keeps events, templates, findings and incidents in SQLite, with full-text search over the message, event key, host and program. It is the one place every later stage reads from, and it is what the API serves. The command line uses a temporary database deleted after each run; the web app keeps one in `data/`.

## 4. Mine

`mining/templates.py` runs Drain3 over the messages to group lines that differ only in their variable parts: `Interface <IF>, changed state to down`. Addresses, interfaces, numbers and times are masked first; usernames and other client-chosen text are masked by the position the parser reported, not by a regex. Up and down are kept apart, so a down and an up are two patterns. `mining/dedup.py` then collapses runs of the same pattern on the same device into one row with a count.

Mining is for people, not for detection: it is what turns 50,000 lines into a list of 28 patterns on the dashboard, and what the evidence pack uses to show "this line, and 40 like it". Rules work on event keys and fields, which are exact.

## 5. Detect

`detection/engine.py` runs the rules in `config/rules.toml`. A rule is data: which event keys it matches, conditions on fields, how to group (per interface, per source address, per host), a window and a threshold. The engine has no rule-specific code. The kinds of rule:

| Kind | Fires when | Used by |
|---|---|---|
| `threshold` | At least N matching events in a window, or N different values of a field (`count_distinct`). A threshold of 1 fires on any single event | Link flap, brute force, port scan, BGP session down |
| `share` | Matching events are a share of another set, and at least N of them | DNS failures |
| `sequence` | One event followed by another within a time limit | A login then a config change |
| `absence` | An event not followed by its opposite within a time limit | An interface that stays down |

Each match is a **finding**, with the lines that triggered it. Its severity comes from the rule: a base level, raised by strength (how far past the threshold), by flags (`succeeded` when a login from the attacking address followed the failures) and by the critical devices and interfaces the user lists. Every severity carries the sentence that explains it. [RULES.md](RULES.md) lists every rule; [WRITING_RULES.md](WRITING_RULES.md) shows how to tune them or add new ones without code.

## 6. Correlate

A failed link produces a dozen findings on four routers. This stage turns them into one incident with a root cause.

**Grouping** (`correlation/grouping.py`). Two findings join when they are close in time (60 seconds, or 15 minutes for the same kind of problem on the same device) **and** connected: the same device, the two ends of one link, a routing neighbor of one device being the other. Time alone is never enough, so a brute-force attack and a link fault in the same minute stay two incidents. Routine findings (Info: a config change, an interface down) never start or bridge an incident; they are attached afterwards as context.

**Topology** (`correlation/topology.py`). Logs never say which address belongs to which router. The tool infers it from adjacency messages (R2 reports neighbor 10.255.0.1 going down at the moment R1's interface does) and states what it could not establish. A small topology file can say which device is which and which interfaces are cabled together; without one, a switch reload does not pull in the router on its other end.

**Cause and effect** (`correlation/causality.py`, `config/causal_priors.toml`). Inside an incident, findings are ordered by a table of known mechanisms, each with its expected delay: an interface going down takes OSPF over that interface down at once; the other routers lose OSPF when their 40-second dead timer runs out; BGP drops when its hold timer expires. A link whose timing matches is marked direct, one that only fits loosely plausible. The finding that explains the most others, earliest, is the root cause. The incident gets a confidence (high, medium or low) with its reason, alternatives when another cause would explain almost as much, and a list of what the logs cannot tell, such as why the interface went down. A configuration change shortly before a failure is shown as a suspect, never as proven.

## 7. Explain

**The evidence pack** (`llm/evidence.py`). The only thing an LLM is ever shown: the incident's facts (severity and why, root cause, confidence, chain), its findings and a few representative lines per pattern, each with an id (`F1` for a finding, `C1` for a step of the chain, `E12` for a line) that an explanation must cite. It has a hard size limit, 3,000 tokens; a large incident gets one example line per pattern instead of three.

**Redaction** (`redaction/redactor.py`). Before the pack leaves the machine, addresses, hostnames and usernames are replaced by stand-ins (`HOST_1`, `IP_1`, `USER_1`) and secrets (keys, community strings, password hashes) are removed outright. The real values are put back only in the report the user reads.

**The provider** (`llm/provider.py`, `llm/openai_provider.py`). One interface, one real provider today, and a fake for tests. The answer is a fixed structure (summary, timeline, hypotheses, impact, fix steps, verification commands, unknowns), every statement with its citations. The prompt is a versioned file (`llm/prompts/`) that tells the model that the pack's content is data, not instructions. Answers are cached by the pack's hash and the prompt version, so an incident is paid for once.

**The validator** (`llm/validate.py`). An answer is rejected if a citation does not exist or a statement has none; if it names an interface, address, device or time that is not in the pack; if it contradicts the severity or the root cause the rules decided; if it contains links or HTML; if it is too long; or if a step that changes a device is not marked as one. A rejected answer is asked for once more, with the reasons; if that fails too, the built-in explanation is used.

**The built-in explanation** (`llm/fallback.py`, `config/fallback.toml`). A template per incident type, filled in from the pack, in junior or senior wording. It is what runs with the LLM switched off, and it passes the same validator. Every report says which of the two wrote each explanation.

Scenario 9 checks the whole stage: usernames written to talk an LLM into calling the attack harmless. The rules find the attack exactly as before, since they never read the usernames as text. With redaction on, the usernames reach the LLM only as stand-ins; with it off, the prompt tells the model that everything in the pack is data, and the validator rejects an answer that lowers the severity or says nothing happened.

## Around the pipeline

- **Reports** (`report/`): text, Markdown and JSON from the command line, and a post-mortem document per incident. Text from logs is escaped so it cannot format anything.
- **Web API** (`api/`): FastAPI over the same database, with the pipeline running in the background and its stage reported as it goes. The interface in `frontend/` (React, Vite, Tailwind) reads only this API.
- **Live** (`live/`): a UDP and TCP syslog listener with an allow-list, a per-sender rate limit and a bounded queue. Every 5 seconds the same rules and correlation run over the last two hours; `live/tracker.py` matches each new incident to an open one so it keeps its id, and closes it after five quiet minutes.
- **Alerts** (`alerts/`): one webhook message when a live incident at High or above has been open for 30 seconds, one more only if it gets worse, with a rate limit, digests and silences.

## Testing

Each stage has its own tests, and three kinds run across all of them:

- **Golden tests**: real-format lines with the exact event expected (`backend/tests/golden/`), including sanitized lines from real devices.
- **Scenarios**: generated logs with an answer key (`data/scenarios/`), checked end to end.
- **The evaluation harness** (`eval/`): precision, recall, root cause, severity and devices on 160 held-out files the rules were never tuned on, plus noise-only files for false alarms. Results are in `eval/results/latest.md`, and what happened on real logs is in [REAL_LOG_TESTING.md](REAL_LOG_TESTING.md).
