# Command Line

One command analyzes a log file and prints a report. It runs fully offline.

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

# A report to attach to a ticket
netlog analyze router.log --format markdown -o report.md

# For another program to read
netlog analyze router.log --format json -o report.json
```

## What the report contains

In this order:

1. **File:** number of lines, how many were understood, the devices seen, the time span, and how many message patterns the lines collapsed into.
2. **Verdict:** how many findings at each severity, or a clear statement that nothing was found.
3. **Findings**, most severe first. For each: the severity, what happened, when, why it has that severity, and up to five key log lines with their line numbers in the original file.
4. **Most frequent messages:** the ten most common message patterns.
5. **Notes:** any year or timezone that was assumed, and a warning if less than 95% of lines were understood.

When a finding has more than five evidence lines, the first three and the last two are shown. The last lines matter: that is where a recovery, or the login that finally succeeded, appears.

### Why Info findings are hidden by default

Routine events are recorded as Info findings: every configuration change, and every interface that stayed down for more than 30 seconds, which includes someone switching off a desk PC. They are useful context when something else goes wrong, but a normal day produces many of them. The report says how many were left out. `--min-severity info` lists them.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing found at or above the minimum severity |
| `1` | At least one finding at or above the minimum severity |
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
| `by_severity` | Count of all findings per level, including those not listed |
| `shown` | Findings listed in `findings` |
| `hidden` | Findings below `min_severity` |

### `findings[]`

| Field | Meaning |
|---|---|
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

- Group related findings into one incident with a root cause. A failed link that takes down routing on three routers is listed as its separate findings.
- Explain a finding beyond its severity reason.
- Read anything other than a file: no live syslog.
