# Command Line

One command analyzes a log file and prints a report. It runs fully offline unless you set up an LLM provider, which is optional and only ever writes the explanations.

```powershell
netlog analyze <file>
```

After installing the project (`pip install -e .`), the command is `netlog` inside the virtual environment: `.venv\Scripts\netlog` on Windows, `.venv/bin/netlog` on Linux and macOS. `python -m netlog` does the same.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--format text` / `markdown` / `json` | `text` | How the report is written |
| `--output FILE`, `-o FILE` | the terminal | Write the report to a file |
| `--min-severity LEVEL` | `low` | Lowest severity to list: `info`, `low`, `medium`, `high` or `critical` |
| `--year YEAR` | the current year | Year of the first log line. Classic syslog lines carry no year |
| `--timezone ZONE` | `UTC` | Timezone of the devices' clocks: `UTC` or an offset such as `+05:30` |
| `--topology FILE` | none | A file saying which address is which device and which interfaces are connected |
| `--findings` | off | Also list the individual findings inside each incident |
| `--audience junior` / `senior` | `senior` | Who the explanation is written for. Junior explains terms and reasoning; senior is terse |
| `--no-llm` | off | Never ask an LLM, even when one is configured; use the built-in explanations |
| `--usage` | off | Show how many LLM requests and tokens the report cost |
| `--rules FILE` | none | A rule file whose rules replace or add to the built-in ones |
| `--config FILE` | none | A settings file that overrides the defaults |
| `--no-color` | | Never use color |
| `--quiet`, `-q` | | Do not show progress |

## Examples

```powershell
# Analyze a file from last year whose devices use Indian Standard Time
netlog analyze router.log --year 2025 --timezone +05:30

# Only what needs attention now
netlog analyze router.log --min-severity high

# Everything, including routine events
netlog analyze router.log --min-severity info

# Tell it about your network, so it can connect what the logs alone cannot
netlog analyze router.log --topology my-network.toml

# For someone new to networking: terms explained, every check with its reason
netlog analyze router.log --audience junior

# A report to attach to a ticket
netlog analyze router.log --format markdown -o report.md

# For another program to read
netlog analyze router.log --format json -o report.json
```

## What the report contains

In this order:

1. **File:** number of lines, how many were understood, the devices seen, the time span, and how many message patterns the lines collapsed into.
2. **Verdict:** how many incidents at each severity, or a clear statement that nothing was found.
3. **Incidents**, most severe first.
4. **Most frequent messages:** the ten most common message patterns.
5. **Notes:** any year or timezone that was assumed, and a warning if less than 95% of lines were understood.

### An incident

Related findings are grouped into one incident. A failed link that takes down routing on three routers is one incident, not twelve alerts. Each incident shows:

| Line | Meaning |
|---|---|
| Headline | What happened, with the severity |
| When, Devices, Findings | The time span, every device involved, and how many findings of each kind are inside |
| Likely cause | The root cause the tool worked out. Shown as **Suspect** when it is a configuration change, which the logs can point at but never prove |
| Confidence | High, medium or low, with the reason |
| Severity | Why it has that level |
| What happened | The story: the cause first, then each group of effects indented under what caused it |
| Not known from these logs | What the logs cannot tell, such as why an interface went down |
| Explanation | The incident in plain English, with what to do about it; see below |

Here is the story of a failed link, shortened:

```
What happened
  Interface GigabitEthernet0/1 on R1 was down for 8m 36s
      2260  Mar  3 02:46:12 R1 89085: ... %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
     -> OSPF adjacency lost on R1 (3 findings) (at once)
        Why: OSPF runs over that interface, so the router dropped its neighbors there the
             moment the interface went down.
        -> BGP session down on R1 (3 findings) (+20s to +24s) [plausible]
     -> OSPF adjacency lost on R2, R3, R4 (+35s to +41s)
        Why: The other routers stopped hearing OSPF hellos from the device whose interface
             failed, and gave up on it when the 40-second dead timer ran out.
```

- Like effects share a line: three routers losing the same neighbor are shown once.
- The time in brackets is how long after the cause each effect began.
- `[plausible]` marks a step that is usual but depends on how the network is built. `[suspect]` marks a configuration change. A step with no mark is certain when it applies.
- Under each step are the log lines that prove it, with their line numbers in the original file.

### The explanation

Everything above the explanation is decided by rules. The explanation puts it into words and adds what to do. It never changes the severity, the root cause or the confidence.

```
Explanation
  For a senior reader. Written by the built-in templates, not an LLM (no LLM provider is
  configured).
  Likely root cause: Interface GigabitEthernet0/1 on R1 was down for 8m 36s (confidence high).
  Severity critical. BGP session from R1 to 10.255.0.2 went down, with 11 related findings ...
  Timeline
    - 02:46:11 UTC: Interface GigabitEthernet0/1 on R1 was down for 8m 36s. [lines 2260, 2400]
  Root-cause hypotheses
    1. Likely root cause: Interface GigabitEthernet0/1 on R1 was down for 8m 36s. ... [lines ...]
  Impact
    - Direct effect: 3 findings, at once. [lines 2261, 2262, 2263]
  What to do
    1. Look at the status and the error counters of GigabitEthernet0/1 on R1.
    4. [REVIEW BEFORE RUNNING] Shut and no shut the interface only after the physical checks ...
  Commands to confirm (read-only)
    show interfaces GigabitEthernet0/1
        Healthy: The interface and the line protocol are both up ...
```

- **Who wrote it** is stated on the first line: an LLM, or the built-in templates with the reason (none configured, switched off, the provider failed, or its answers were rejected).
- **`[lines 2260, 2400]`** are line numbers in the file you analyzed. Open the file at those lines to check the statement. Long lists are cut after eight numbers.
- **`[REVIEW BEFORE RUNNING]`** marks a step that would change a device. Read it and decide; the tool never runs anything.
- **Also not known** appears when the explanation names something unknown that the incident does not already list.
- `--audience junior` gives the same facts, steps and citations in more words: terms are explained, the mechanism behind each effect is spelled out, and every check comes with its reason.

To have an LLM write the explanations, put `NETLOG_LLM_PROVIDER=openai` and `NETLOG_LLM_API_KEY=...` in a file named `.env` in the folder you run the command from (or name another file with the `NETLOG_ENV_FILE` environment variable). Each listed incident then costs one request, two if the first answer is rejected. Answers are kept in `data/netlog.db`, so the same incident is not paid for twice. The LLM is sent a short evidence pack in which addresses, device names and usernames are replaced by stand-ins; the real values are put back on your machine.

### Routine findings

Routine events are recorded as Info findings: every configuration change, and every interface that stayed down for more than 30 seconds, which includes someone switching off a desk PC. On their own they are not problems, and a normal day produces many of them. They never form an incident, but one that explains an incident is attached to it: the interface that failed, or the change made just before. The report says how many were recorded, and `--min-severity info` lists them all.

### Telling the tool about your network

The logs never say which address belongs to which device, or which cable goes where. The tool works out what it can: when two routers form or lose an adjacency they both log it at the same moment, which reveals who is who. What it cannot work out it leaves unknown, and says so.

A topology file fills the gaps. Both sections are optional, and a partial file is fine:

```toml
[[device]]
name = "R1"
addresses = ["10.255.0.1", "10.0.0.1"]

[[link]]
a = { host = "R3", interface = "GigabitEthernet0/3" }
b = { host = "SW1", interface = "GigabitEthernet0/1" }
```

`data/scenarios/topology.toml` is a complete example for the sample logs.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No incident at or above the minimum severity |
| `1` | At least one incident at or above the minimum severity. With `--min-severity info`, also when there are routine findings |
| `2` | The file could not be analyzed: missing, empty, not a log, or a bad option |

This makes the tool usable in a script:

```powershell
netlog analyze today.log --min-severity high --quiet -o report.md
if ($LASTEXITCODE -eq 1) { Write-Host "Problems found, see report.md" }
```

## Color and encoding

- Color is used only when the report goes to a terminal. It is off when the output is piped or written to a file, with `--no-color`, or when the `NO_COLOR` environment variable is set.
- The text report uses plain ASCII for its own layout, so it displays correctly in Windows PowerShell with its default console settings.
- If a log line contains a character the console cannot show, a `?` is printed in its place.
- Control characters in log lines are replaced with `?`, so a log line cannot change the terminal's colors or move the cursor.

## JSON output

The field names below are stable: new fields may be added, existing ones are not renamed.

```json
{
  "version": 1,
  "file": { },
  "summary": { },
  "incidents": [ ],
  "findings": [ ],
  "templates": [ ],
  "assumptions": [ ],
  "warnings": [ ]
}
```

### `file`

| Field | Meaning |
|---|---|
| `name`, `size_bytes` | The file analyzed |
| `lines` | Lines with content |
| `blank_lines` | Blank lines, not counted in `lines` |
| `parsed`, `partial`, `unparsed` | Lines fully understood, damaged or truncated, and not understood |
| `classified` | Parsed lines whose message type was also recognized |
| `percent_parsed` | `parsed` as a share of `lines` |
| `start`, `end` | Time of the first and last event, in UTC |
| `devices` | A list of `{ "host", "lines" }` |
| `templates` | Number of message patterns |

### `summary`

| Field | Meaning |
|---|---|
| `min_severity` | The level asked for |
| `incidents` | Incidents listed in `incidents` |
| `incidents_by_severity` | Count of all incidents per level |
| `by_severity` | Count of all findings per level, including those not listed |
| `shown` | Findings listed in `findings` |
| `hidden` | Findings not listed |

### `incidents[]`

| Field | Meaning |
|---|---|
| `id` | Derived from the findings inside, so the same log always gives the same id |
| `headline` | What happened |
| `severity`, `severity_reason` | The level and why |
| `start`, `end`, `duration_seconds` | When, in UTC |
| `devices` | Every device involved |
| `root_cause` | `{ "kind", "summary", "devices", "entity", "findings", "explains" }`. `findings` is empty when the cause is not itself in the logs, such as a device that went silent |
| `alternatives` | Other possible root causes, in the same shape |
| `confidence`, `confidence_reason` | `high`, `medium` or `low`, and why |
| `unknowns` | What the logs cannot tell |
| `findings` | Ids of the findings that are the problem |
| `context` | Ids of routine findings attached for context |
| `chain` | Each step of cause and effect: `{ "cause", "effect", "prior", "certainty", "explanation", "delay_seconds" }`, where `cause` and `effect` are finding ids |
| `story` | The chain as the report shows it: rows of `{ "depth", "label", "when", "certainty", "explanation", "explained", "findings", "evidence" }` |
| `title` | A longer description naming the most serious finding |
| `explanation` | The plain-English explanation; see below |

### `incidents[].explanation`

| Field | Meaning |
|---|---|
| `source` | `llm`, `cache` (an LLM's answer read from the local cache) or `fallback` (the built-in templates) |
| `written_by` | The same as a phrase |
| `audience` | `junior` or `senior` |
| `provider`, `model` | The LLM asked, if any |
| `fallback_reason` | Why the built-in explanation was used; `null` otherwise |
| `summary` | Two to four sentences |
| `timeline`, `impact` | Lists of `{ "text", "lines", "evidence" }`: `lines` are line numbers in the file, `evidence` the ids as they were cited |
| `hypotheses` | The same, plus `against_lines` and `against` for evidence that speaks against the hypothesis |
| `fix_steps` | `{ "text", "review_before_running" }`, in order |
| `verification_commands` | `{ "command", "purpose" }`; read-only |
| `unknowns` | What the logs cannot tell |
| `usage` | `{ "requests", "input_tokens", "output_tokens", "latency_ms" }` for this explanation |

### `findings[]`

Every finding at or above the minimum severity, plus any that belong to a listed incident.

| Field | Meaning |
|---|---|
| `id` | The id that incidents refer to |
| `incident`, `role` | The incident it belongs to, and whether it is a `problem` or `context` there |
| `severity` | `info`, `low`, `medium`, `high` or `critical` |
| `severity_reason` | One line explaining the level |
| `rule` | The rule that produced it; see [RULES.md](RULES.md) |
| `incident_type` | The kind of problem, such as `link_flap` |
| `title` | What happened, in plain words |
| `host` | The device, when the finding concerns exactly one |
| `group` | The values the events were grouped by, such as host and interface |
| `start`, `end`, `duration_seconds` | When, in UTC |
| `strength` | 0 to 1: how far past the rule's threshold |
| `flags` | Extra facts, such as `succeeded` or `recovered` |
| `metrics` | The numbers behind the finding: counts, reasons, usernames |
| `evidence_count` | How many log lines are evidence |
| `evidence` | Up to five of them, as `{ "line", "text" }` |

### `templates[]`

| Field | Meaning |
|---|---|
| `pattern` | The message pattern, such as `Interface <IF>, changed state to down` |
| `count` | How many lines match it |
| `event_key`, `source_type` | The message type and kind of log |
| `hosts` | The devices it appeared on |

## Post-mortem

`netlog postmortem` analyzes a file the same way and writes the post-mortem of one incident in Markdown: title and severity, summary, impact, a timeline with times, the likely root cause and confidence, contributing factors, what the logs show was done and what should be done, what cannot be determined, follow-up actions as a checklist for the team, and an appendix of the evidence lines with their line numbers. It says at the top that it was drafted automatically and needs review before it is filed.

```powershell
# The most severe incident of the file
.venv\Scripts\netlog postmortem data\scenarios\02_cascade.log --year 2026 -o postmortem.md
# A chosen incident, written for a junior reader
.venv\Scripts\netlog postmortem router.log --incident inc-6f861a94c9 --audience junior
```

It takes the reading options of `analyze` (`--year`, `--timezone`, `--topology`, `--audience`, `--no-llm`, `--rules`, `--config`, `--quiet`). Exit code 0 when it was written, 2 when the file has no incidents or no incident with that id. The web page of an incident has a Download post-mortem button that gives the same document.

## Stored explanations for the demo

The built-in scenarios can be explained once by a real LLM, and the answers stored with them in `data/scenarios/explanations.json` (the `[demo] explanations` setting). With no API key, the web app then shows those explanations for the demo scenarios, checked against the evidence again each time, and makes no request.

```powershell
# Says what it would do and what it would cost; makes no request
.venv\Scripts\netlog demo-explanations
# Does it: one or two requests per incident and audience
.venv\Scripts\netlog demo-explanations --yes
```

It needs a configured LLM provider and key, and refuses to run without one.

## Trying a rule file

`netlog rules test <rule file> <log file>` runs the built-in rules, changed and added to by the rule file, over one log file, and prints how many times each rule triggered and what each finding says. Nothing is stored. A rule file with a mistake is refused with a message naming the rule, the setting and the problem. Exit code 0 when no rule triggered, 1 when one did, 2 when the rule file or the log could not be used. [WRITING_RULES.md](WRITING_RULES.md) explains the rule format.

```powershell
.venv\Scripts\netlog rules test my-rules.toml router.log --year 2026
```

## Live syslog

Instead of uploading yesterday's file, devices can send their messages straight to netlog. The listener runs inside the web API when it is switched on:

```powershell
$env:NETLOG_LIVE = "1"
.venv\Scripts\python -m uvicorn netlog.api.app:app
```

or with `enabled = true` under `[live]` in your settings. It listens on UDP and TCP port 5514 of 127.0.0.1, and the Live page of the web app (http://localhost:5173/live) shows the message rate, the senders and the open incidents, updating by itself. Each incident opens on the ordinary incident page.

Every message goes through the same parsers as a file. Every few seconds the rules and correlation run over the last two hours of messages: an incident opens when it is first found, grows as more evidence arrives, keeps the same id the whole time, and closes when nothing new has arrived for five minutes and nothing in it is still down. It is explained once it has been stable for 30 seconds, and once more at most when it closes. Incidents survive a restart of the API. Messages are kept for 7 days and incidents with their evidence for 90; every one of these numbers is a setting under `[live]`.

To try it without a router, send a sample to it, sped up 20 times, from 02:44 in the log:

```powershell
.venv\Scripts\netlog replay data\scenarios\02_cascade.log --speed 20 --start 02:44
```

`netlog replay` moves every timestamp so the first line happens now, and sends the lines at their moments over UDP (`--tcp` for TCP; `--host` and `--port` for another listener; `--end HH:MM` to stop early).

### Pointing a device at it

On a Cisco device: `logging host 192.168.1.20 transport udp port 5514`, where 192.168.1.20 is the computer running netlog. Then set `bind = "192.168.1.20"` under `[live]`, so the listener accepts messages from the network and not only from this computer.

Port 514 is the standard syslog port. On Linux and macOS a port below 1024 needs administrator rights (run as root, or forward 514 to 5514 in the firewall); on Windows any free port can be used, but the Windows firewall must let the messages in. Devices that cannot change their port can be pointed at 514 with `port = 514`.

### Security

Plain syslog has no authentication and no encryption: anyone who can reach the port can send messages that look like they come from your routers, and anyone on the path can read them. So:

- The listener binds to 127.0.0.1 by default, and to one address of your choosing otherwise. Do not bind it to `0.0.0.0` on a network you do not trust.
- List your devices in `allowed_senders`; messages from any other address are counted and dropped. A sender address can still be forged over UDP, so this keeps out mistakes and casual noise, not a determined attacker.
- Each sender has a rate limit, messages longer than 8 KB or that are not text are dropped, and a burst that overflows the queue drops the oldest messages. All of these are counted and shown on the Live page; none of them can stop the listener.
- Message text is only ever shown as text, never run or interpreted.

### Alerts

When the listener finds something serious, netlog can post a message to a chat channel. Set one or both webhook addresses in `.env` (never in a settings file: whoever has the address can post to your channel), then restart the API:

```text
NETLOG_ALERT_SLACK_URL=https://hooks.slack.com/services/...
NETLOG_ALERT_WEBHOOK_URL=https://example.org/my-receiver
```

The first takes Slack's format, which Mattermost, Rocket.Chat and Discord (its `/slack` address) also accept. The second gets plain JSON: every fact as a field, and the same text under `text`. Check the setup with a clearly labelled test message:

```powershell
.venv\Scripts\netlog alerts test
```

which prints `slack: delivered`, or why not (`slack: FAILED after 4 tries (HTTP 500)`). The web API has the same as `POST /api/alerts/test`.

An alert is short enough to read on a phone's lock screen. Replaying scenario 2 gives exactly one:

```text
CRITICAL: BGP session from R1 to 10.255.0.2 went down, with 11 related findings on R1, R2, R3, R4
Likely cause: Interface GigabitEthernet0/1 on R1 was down for 1m 5s (high confidence)
Devices: R1, R2, R3, R4 | started 2026-03-03 02:46:11 UTC
Open the incident (a link to the incident page)
```

with a `Summary:` line from the explanation when one is ready; an alert never waits for it.

**When.** An incident raises an alert when it opens at High or above, and one more each time its severity rises to a level it has not been alerted at ("CRITICAL (was HIGH): ..."). More evidence at the same severity, the incident closing, or a restart of the API send nothing more. The first alert waits until the incident has been open for 30 seconds, because an incident grows in its first seconds (the interface goes down, then OSPF, then BGP): waiting sends one alert with the severity and cause it settles on, instead of a High alert naming the wrong cause followed by a Critical one. With `on_close = true`, an incident that raised an alert also says when it is over and how long it lasted.

**Floods.** At most 5 alerts go out in any 10 minutes. The ones beyond are held back and sent together, as soon as the limit allows, in one digest message that lists the incidents worst first.

**Silences, for planned maintenance.** Incidents are still detected and recorded; only the messages stop.

```powershell
.venv\Scripts\netlog alerts silence --device R1 --for 2h --reason "IOS upgrade"
.venv\Scripts\netlog alerts silence --type link_flap --for 30m
.venv\Scripts\netlog alerts silence --all --for 1h
.venv\Scripts\netlog alerts list
.venv\Scripts\netlog alerts unsilence 3
```

A device silence covers every incident that involves the device. A type silence covers incidents whose likely cause is of that type: a rule name from `GET /api/rules`, such as `link_flap`, or `link_failure` when both ends of a link report it. An incident with no likely cause is covered when any of its findings comes from that rule. An incident that was silenced is not alerted later at the same severity, only if it gets worse. A silence lasts at most a week. The API has the same: `POST /api/alerts/silences` with `{"device": "R1", "minutes": 120, "reason": "IOS upgrade"}`, and `DELETE /api/alerts/silences/{id}` to end one early. `GET /api/alerts` lists the silences and every alert recorded: sent, failed, held for a digest, or silenced.

**Failures.** A webhook that does not answer, times out, or answers with a server error is tried 3 more times, after 2, 4 and 8 seconds; then the failure is recorded and shown under warnings on the Live page. An answer saying the address is wrong is not retried. Sending happens on a thread of its own, so a webhook that is down never slows detection. Alerts not yet sent when the API stops go out when it starts again.

**Privacy.** An alert goes to an outside service. If that service is not your own (Slack, Discord), set `redact = true` under `[alerts]`: IP addresses become `[IP]` and usernames `[user]` in every alert, and the link is kept. It is off by default, for chat you host yourself, where the names help. The webhook address never appears in logs, in API answers or in the database.

**Safety.** Titles and causes come from log content, which anyone who can reach the listener can write. Every value is put on one line, cut to length, and escaped, so a log line cannot add lines to an alert, turn into a link, or mention `@channel` or `@everyone`.

Every number here is a setting under `[alerts]`: `min_severity`, `first_alert_wait_seconds`, `on_close`, `max_alerts`, `period_seconds`, `redact`, `link_base` (the address of the web pages, for the link; change it to one your phone can reach), `timeout_seconds`, `max_retries`, `backoff_seconds` and `max_silence_hours`.

## What it cannot do yet

- Run anything. Fix steps and commands are suggestions for a person to read.
- Know your network without being told. Without a topology file it connects only what the logs themselves reveal.
