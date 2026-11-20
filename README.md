# Network Log Summarizer and Incident Explainer

Reads network logs, finds the incidents in them, and explains what happened in plain English, with every statement linked to the log lines that prove it.

> **Status: in development.** The offline analyzer is complete: one command reads a log file, detects problems with 12 rules, groups them into incidents and names a likely root cause for each. Plain-English explanations and the web interface are still to come. See [Progress](#progress) for exactly what works today.

## The problem

At 2:14 am a cable between two routers goes bad. Within a minute, five devices write about 3,000 log lines: interfaces going down, routing sessions dropping, tunnels failing. An engineer reading those lines by hand needs twenty minutes to work out that it was one cable.

Large teams solve this with a SIEM such as Splunk or the Elastic stack. Small IT teams, college labs and homelabs usually have neither the budget nor the time to run one, and are left with `grep`.

## The goal

Given the same 3,000 lines, the finished tool should answer:

> **One incident, Critical.** The link between R1 and R2 failed at 02:14:07, and everything else is a consequence. Check the cable or SFP on R1 `GigabitEthernet0/1`.

Each part of that answer links to the log lines behind it.

| Step | What it means | Today |
|---|---|---|
| Understand network logs | Cisco IOS, Linux authentication and DHCP to start with | Works |
| Detect problems with rules, not guesswork | Link flaps, routing drops, brute-force logins, DHCP exhaustion and more | Works |
| Say how serious each one is, and why | A fixed, testable severity with a one-line reason | Works |
| Group related alerts | One failed link that takes down OSPF and BGP on three routers becomes one incident with one root cause | Works |
| Explain in plain English | An AI model writes the explanation, but only from evidence the rules already found | Planned |
| Work without the AI | Detection, grouping and reports run fully offline | Works for everything built so far |

## How it works

```
 log file
    |
    v
 +---------------------+
 | Read and parse      |   time, device, message type, interface, addresses      built
 +---------------------+
    |
    v
 +---------------------+
 | Mine templates      |   thousands of similar lines become a few patterns      built
 +---------------------+
    |
    v
 +---------------------+
 | Detect and score    |   rules find each kind of problem and rate it           built
 +---------------------+
    |
    v
 +---------------------+
 | Correlate           |   related findings become one incident with a cause     built
 +---------------------+
    |
    v
 +---------------------+
 | Explain             |   plain-English summary, checked against the evidence   planned
 +---------------------+
    |
    v
 report (built), dashboard and alerts (planned)
```

Two design rules shape the project:

1. **Rules decide, the AI explains.** Parsing, detection, correlation and severity are ordinary deterministic code that can be tested and measured. The AI model never decides whether something is an incident or how serious it is, and it never sees raw log files.
2. **Log content is untrusted.** Usernames, hostnames and messages can be written by an attacker, so nothing from a log is ever executed, rendered as HTML or treated as an instruction.

## Progress

| Stage | What it covers | Status |
|---|---|---|
| Event schema | One standard shape for every log line | Done |
| Test log generator | Realistic logs with known incidents and an answer key | Done |
| File reading and syslog parsing | Time and device from every line, RFC 3164 and RFC 5424 | Done |
| Vendor parsing | Cisco IOS, Linux auth, DHCP message content | Done |
| Storage and template mining | Searchable database, pattern extraction | Done |
| Detection rules and severity | 12 rules, each finding with a severity and a reason | Done |
| Command-line tool | One command, a report in text, Markdown or JSON | Done |
| Correlation | Grouping, causal chain, root cause, confidence | Done |
| AI explanation | Cited explanations with a validator | Next |
| Web interface | Dashboard, incident page, timeline | Planned |
| Live syslog and alerts | Real-time intake, chat notifications | Planned |
| Evaluation | Measured accuracy on labelled logs | Planned |

### What works today

- **One command analyzes a file.** `netlog analyze router.log` prints what was found, most severe first, with the log lines that prove it. It runs fully offline.
- **Understands Cisco IOS, Linux sshd and sudo, and ISC dhcpd** on top of both syslog formats. Classic syslog lines carry no year and no timezone, so both are assumed and the report says so.
- **Detects 12 kinds of problem:** flapping and failed interfaces, BGP and OSPF drops, DHCP exhaustion, brute-force logins, config changes, CPU and memory trouble, reloads and MAC flapping. Rules are plain settings in a file, not code.
- **Gives every finding a severity and a reason.** 300 failed logins that all fail are Medium; the same attack ending in one successful login is Critical.
- **Groups findings into incidents.** Twelve alerts from four routers become one incident. Findings are joined only when they are close in time and connected; an attack and a link fault in the same minute stay separate.
- **Names a likely root cause, with a confidence level.** It orders each incident into cause and effect using what is known about how protocols fail, and it lists what the logs cannot tell. A configuration change shortly before a failure is shown as a suspect, never as proven.
- **Works out who is who from the logs.** Logs never say which address belongs to which router. The tool infers it from adjacency messages, and leaves unknown what it cannot establish.
- **Collapses noise.** A 50,000-line file reduces to 28 message patterns.
- **Never drops a line.** A line no parser understands is kept and counted, and the tool reports what share of the file it understood.
- **Treats log content as untrusted.** A username such as `admin from 10.0.0.1 port 22` does not fool the parsers, and a log line cannot inject formatting into a report.

On the sample logs, all nine files give the expected incidents with the right root cause, severity and devices when the tool is given the network's topology. From the logs alone, eight of nine match: in the ninth the root cause is right, but a neighboring router is not connected to the incident, because nothing in the logs says the two devices are cabled together and the tool does not guess. These are generated logs; see [Limitations](#limitations).

Here is the report for a log where one failed interface, hidden in 5,000 lines, took down routing on four routers (most evidence lines left out, the rest shortened):

```
Verdict
  1 incident: 1 critical (12 findings on 4 devices)

Incidents
  [CRITICAL] Interface GigabitEthernet0/1 on R1 was down for 8m 36s
      When          2026-03-03 02:46:11 to 02:46:52 UTC (41s)
      Devices       R1, R2, R3, R4
      Findings      12 findings: 6 OSPF adjacency lost, 6 BGP session down
      Likely cause  Interface GigabitEthernet0/1 on R1 was down for 8m 36s
      Confidence    High: every finding is accounted for, the timing matches how the protocols
                    behave, and 4 devices report it.
      Severity      Critical: the most serious finding is "BGP session from R1 to 10.255.0.2 went
                    down".
      What happened
        Interface GigabitEthernet0/1 on R1 was down for 8m 36s
            2260  Mar  3 02:46:12 R1 ... %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
           -> OSPF adjacency lost on R1 (3 findings) (at once)
              Why: OSPF runs over that interface, so the router dropped its neighbors there the
                   moment the interface went down.
              -> BGP session down on R1 (3 findings) (+20s to +24s) [plausible]
           -> BGP session down on R2, R3, R4 (+23s to +27s)
           -> OSPF adjacency lost on R2, R3, R4 (+35s to +41s)
              Why: The other routers stopped hearing OSPF hellos from the device whose interface
                   failed, and gave up on it when the 40-second dead timer ran out.
      Not known from these logs
        - Why the interface went down. The logs show that it did, not whether a cable, an optic or
          the device at the other end was at fault.
        - Neighbor addresses not matched to a device in these logs: 10.255.0.2, 10.255.0.3,
          10.255.0.4. List them in a topology file to say which device each one is.
```

## What it detects

| Rule | Detects | Default trigger | Severity |
|---|---|---|---|
| Link flap | An interface bouncing down and up | 5 downs on one interface in 5 minutes | Medium; High at 10 or more |
| Interface down | An interface that stayed down | Down for more than 30 seconds | Info |
| BGP session down | A BGP session dropping | Any drop | Critical |
| OSPF adjacency loss | An OSPF neighbor leaving the FULL state | Any loss | High |
| DHCP exhaustion | A DHCP pool with no addresses left | 10 refusals in 5 minutes | High |
| Config change | Someone changing a device's configuration | Any change | Info |
| Brute-force login | Password guessing from one address | 20 failed logins in 10 minutes | Medium; Critical if a login then succeeds |
| CPU hog | A process holding the CPU too long | 3 warnings in 5 minutes | High |
| Memory failure | A device running out of memory | Any failure | High |
| Device reload | A reload being requested | Any request | High |
| Device restart | A device starting up, requested or not | Any restart | Critical |
| MAC flapping | A MAC address moving between ports, the usual sign of a loop | 3 warnings in one VLAN in 5 minutes | High |

Every threshold is a setting in `backend/netlog/config/rules.toml`, and you can replace or add rules with your own file through `--rules`. A deliberate shutdown, a single unplugged cable and one mistyped password are not reported as problems.

[docs/RULES.md](docs/RULES.md) describes each rule in full: its log signature, usual causes, and when it can be wrong.

## Getting started

Requires Python 3.11 or newer. Commands are for Windows PowerShell.

```powershell
git clone https://github.com/siddxwar04/Network-Log.git
cd Network-Log
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

Analyze one of the sample logs:

```powershell
.venv\Scripts\netlog analyze data\scenarios\04_brute_force.log --year 2026
```

Then try your own file, or other options:

```powershell
.venv\Scripts\netlog analyze router.log --min-severity high
.venv\Scripts\netlog analyze router.log --format markdown -o report.md
.venv\Scripts\netlog analyze router.log --findings
.venv\Scripts\netlog analyze data\scenarios\07_device_reload.log --year 2026 --topology data\scenarios\topology.toml
```

Check the tool against the answer keys of every sample log:

```powershell
.venv\Scripts\python -m eval.scorecard --topology data\scenarios\topology.toml
```

See the evidence pack of an incident: the short, numbered case file that is the only thing an LLM will be shown, with addresses and names replaced by stand-ins. Without `--show` it lists the size of every pack:

```powershell
.venv\Scripts\python -m eval.packs --show 02_cascade
.venv\Scripts\python -m eval.packs
```

Ask an LLM to explain an incident from its evidence pack. This is optional and makes a paid request: copy `.env.example` to `.env`, set `NETLOG_LLM_PROVIDER=openai` and your key in `NETLOG_LLM_API_KEY`, then run the command below. Answers are cached, so the same incident is only paid for once. Without a key the command says so and everything else keeps working. The explanation is not part of the `netlog analyze` report yet.

```powershell
.venv\Scripts\python -m eval.explain 02_cascade
.venv\Scripts\python -m eval.explain 02_cascade --mode junior
```

See [docs/CLI.md](docs/CLI.md) for every option, the exit codes and the JSON format.

Run the tests:

```powershell
.venv\Scripts\python -m pytest
```

Generate a fresh test log:

```powershell
.venv\Scripts\python -m generator --scenario cascade --seed 5 --out data/tmp
```

On Linux or macOS, use `.venv/bin/` in place of `.venv\Scripts\`.

## Sample logs

The `data/scenarios/` folder holds generated logs, each with a `.labels.json` file that states which incident is inside, its root cause and the exact lines that belong to it.

| File | What happens |
|---|---|
| `01_link_flap` | An interface on R1 goes down and up 12 times in about 5 minutes |
| `02_cascade` | R1 loses its core link; OSPF and BGP to R1 drop on three other routers |
| `03_config_bgp` | A user changes R2's config and a BGP session drops 20 seconds later |
| `04_brute_force` | 400 failed SSH logins from one address, then a successful one |
| `05_dhcp_exhaustion` | The DHCP pool runs out and new devices are refused |
| `07_device_reload` | A switch is reloaded: minutes of silence, then boot messages |
| `08_noise` | A normal day with no incident |
| `08_noise_50k` | The same normal day at 50,000 lines, for checking speed and false alarms |
| `10_overlap` | Two unrelated incidents at the same time |

The noise in these files is built to resemble incidents without being one: a single port going down and up, an administrator shutting a port on purpose, one mistyped password. Detection rules have to tell the difference.

See [generator/README.md](generator/README.md) for the simulated network, the line formats and the label format.

## Repository layout

```
backend/
  netlog/
    cli.py           the netlog command
    schema.py        the normalized event
    ingestion/       reading files
    parsers/         syslog, Cisco IOS, Linux auth and DHCP parsers
    storage/         SQLite database
    mining/          template mining and dedup
    detection/       rule engine and severity
    config/          default settings and the built-in rules
    report/          text, Markdown and JSON reports
    correlation/     incidents, topology, cause and effect
    llm/             the evidence pack, the prompt, the provider adapter and the cache
    redaction/       hiding addresses and names before they leave the machine
    api/             web API                  (planned)
  tests/
generator/           test log generator
eval/                scorecard, pack sizes, and a command to try an explanation
data/scenarios/      generated logs with label files
docs/                reference documentation
frontend/            web interface            (planned)
```

## Documentation

- [docs/CLI.md](docs/CLI.md): the command, its options, exit codes and JSON output.
- [docs/RULES.md](docs/RULES.md): every detection rule, with its log signature, thresholds, severity and usual causes.
- [docs/SCHEMA.md](docs/SCHEMA.md): every field of the normalized event, with worked examples.
- [generator/README.md](generator/README.md): the test log generator.

## Limitations

- **A root cause is the tool's best reading of the logs, not a verdict.** It is found by applying fixed rules about what can cause what. Each incident states a confidence level and what the logs cannot tell.
- **Explanations are not checked or shown in the report yet.** An LLM can be asked to explain an incident, and its answer must have a fixed structure with citations, but nothing yet verifies that the citations are real, and the report still states only what the rules established.
- **Tested on generated logs only.** The sample logs follow real Cisco IOS, OpenSSH and ISC dhcpd formats, but they come from this project's own generator, so the results show the tool is consistent with its design, not that it works on every network. Testing on logs from real devices is planned.
- **Little knowledge of your network.** The tool cannot tell a core uplink from a desk port unless you list what is critical in the settings, so an interface going down is Info on its own. It also cannot know which cable goes where; a small topology file fills that in.
- **Cisco IOS first.** Other vendors will follow once the pipeline is complete.
- **A file at a time.** There is no live syslog intake yet.

## Tech stack

Python with pydantic, SQLite, Drain3, pytest and ruff. Planned: FastAPI for the web API, and React with Vite and Tailwind for the web interface.
