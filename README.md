# Network Log Summarizer and Incident Explainer

Reads network logs, finds the incidents in them, and explains what happened in plain English, with every statement linked to the log lines that prove it.

> **Status: early development.** The foundations are built and tested. Detection, correlation, explanations and the web interface are still to come. See [Progress](#progress) for exactly what works today.

## The problem

At 2:14 am a cable between two routers goes bad. Within a minute, five devices write about 3,000 log lines: interfaces going down, routing sessions dropping, tunnels failing. An engineer reading those lines by hand needs twenty minutes to work out that it was one cable.

Large teams solve this with a SIEM such as Splunk or the Elastic stack. Small IT teams, college labs and homelabs usually have neither the budget nor the time to run one, and are left with `grep`.

## What this tool will do

Given the same 3,000 lines, it should answer:

> **One incident, Critical.** The link between R1 and R2 failed at 02:14:07, and everything else is a consequence. Check the cable or SFP on R1 `GigabitEthernet0/1`.

Each part of that answer links to the log lines behind it.

- **Understands network logs:** Cisco IOS, Linux authentication and DHCP to start with.
- **Detects incidents with rules, not guesswork:** link flaps, routing session drops, brute-force logins, DHCP exhaustion, config changes, device reloads.
- **Groups related alerts:** one failed link that takes down OSPF and BGP on three routers is reported as one incident with one root cause.
- **Explains in plain English:** an AI model writes the explanation, but only from evidence the rules already found.
- **Works without the AI:** detection, correlation and reports run fully offline.

## How it works

```
 log file
    |
    v
 +---------------------+
 | Read and parse      |   time, device, message type, interface, addresses
 +---------------------+
    |
    v
 +---------------------+
 | Mine templates      |   thousands of similar lines become a few patterns
 +---------------------+
    |
    v
 +---------------------+
 | Detect              |   rules look for the signature of each kind of problem
 +---------------------+
    |
    v
 +---------------------+
 | Correlate           |   related findings become one incident with a root cause
 +---------------------+
    |
    v
 +---------------------+
 | Explain             |   plain-English summary, checked against the evidence
 +---------------------+
    |
    v
 report, dashboard, alerts
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
| Vendor parsing | Cisco IOS, Linux auth, DHCP message content | Next |
| Storage and template mining | Searchable database, pattern extraction | Planned |
| Detection rules and severity | The incident detectors | Planned |
| Correlation | Grouping, causal chain, root cause | Planned |
| AI explanation | Cited explanations with a validator | Planned |
| Web interface | Dashboard, incident page, timeline | Planned |
| Live syslog and alerts | Real-time intake, chat notifications | Planned |
| Evaluation | Measured accuracy on labelled logs | Planned |

### What works today

- **Reads log files of any size** line by line, in UTF-8 or UTF-16, with Windows or Unix line endings. Binary files are rejected, and oversized lines are cut safely.
- **Parses both syslog formats.** Classic syslog lines carry no year and no timezone, so both are assumed and each event records that. A log that runs from December into January is read as crossing into the next year.
- **Never drops a line.** A line no parser understands is kept and counted, and the tool reports what share of the file it understood.
- **Generates test logs with an answer key.** Eight scenarios on a simulated network of four routers, two switches and two servers.

All nine sample log files parse at 100% for time and device. The 50,000-line file takes about 1.4 seconds.

## Getting started

Requires Python 3.11 or newer. Commands are for Windows PowerShell.

```powershell
git clone https://github.com/siddxwar04/Network-Log.git
cd Network-Log
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

Run the tests:

```powershell
.venv\Scripts\python -m pytest
```

Generate a fresh test log:

```powershell
.venv\Scripts\python -m generator --scenario cascade --seed 5 --out data/tmp
```

On Linux or macOS, use `.venv/bin/python` in place of `.venv\Scripts\python`.

There is no command-line tool or web interface yet. Today the project is the parsing library, the generator and their tests.

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
| `10_overlap` | Two unrelated incidents at the same time |

The noise in these files is built to resemble incidents without being one: a single port going down and up, an administrator shutting a port on purpose, one mistyped password. Detection rules have to tell the difference.

See [generator/README.md](generator/README.md) for the simulated network, the line formats and the label format.

## Repository layout

```
backend/
  netlog/
    schema.py        the normalized event
    ingestion/       reading files
    parsers/         syslog parsing and parse coverage
    mining/          template mining          (planned)
    detection/       rules and severity       (planned)
    correlation/     incidents and root cause (planned)
    llm/             explanations             (planned)
    redaction/       hiding addresses and names before they leave the machine (planned)
    storage/         database                 (planned)
    api/             web API                  (planned)
  tests/
generator/           test log generator
data/scenarios/      generated logs with label files
docs/                reference documentation
frontend/            web interface            (planned)
```

## Documentation

- [docs/SCHEMA.md](docs/SCHEMA.md): every field of the normalized event, with worked examples.
- [generator/README.md](generator/README.md): the test log generator.

## Limitations

- **Early stage.** No incidents are detected yet.
- **Tested on generated logs only.** The sample logs follow real Cisco IOS, OpenSSH and ISC dhcpd formats, but they come from this project's own generator. Testing on logs from real devices is planned.
- **Cisco IOS first.** Other vendors will follow once the pipeline is complete.

## Tech stack

Python, pydantic, pytest and ruff today. Planned: FastAPI, SQLite and Drain3 for the backend, and React with Vite and Tailwind for the web interface.
