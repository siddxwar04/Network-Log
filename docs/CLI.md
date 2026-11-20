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

## What it cannot do yet

- Run anything. Fix steps and commands are suggestions for a person to read.
- Know your network without being told. Without a topology file it connects only what the logs themselves reveal.
- Read anything other than a file: no live syslog.
