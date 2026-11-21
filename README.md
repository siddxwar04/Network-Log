# Network Log Summarizer and Incident Explainer

Reads network logs, finds the incidents in them, and explains what happened in plain English, with every statement linked to the log lines that prove it.

> **Status: in development.** The offline analyzer is complete: one command reads a log file, detects problems with 16 rules, groups them into incidents, names a likely root cause for each and explains it in plain English, with or without an AI model. The web interface works: upload a file or pick a demo, watch it being analyzed, read the dashboard, and open each incident with its explanation beside the log lines it cites, a timeline, a causal chain and a post-mortem to download. Rules can be tuned in a file of your own, devices can send their logs live, and serious live incidents raise a chat alert. Its accuracy is measured on 170 generated files the rules were never tuned on, and the whole tool starts with one Docker command. Still to come: testing on logs from real devices. See [Progress](#progress) for exactly what works today and what is left.

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
| Explain in plain English | An AI model writes the explanation, but only from evidence the rules already found, and its answer is checked before it is shown | Works; not yet tried against a real model |
| Work without the AI | Detection, grouping and reports run fully offline, with a built-in explanation in place of the AI's | Works |

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
 | Explain             |   plain-English summary, checked against the evidence   built
 +---------------------+
    |
    v
 report, dashboard and alerts (built)
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
| Detection rules and severity | 16 rules, each finding with a severity and a reason | Done |
| Command-line tool | One command, a report in text, Markdown or JSON | Done |
| Correlation | Grouping, causal chain, root cause, confidence | Done |
| AI explanation | Cited explanations with a validator, a built-in fallback, junior and senior wording | Done |
| Web API | Upload, pipeline status, events, incidents, explanations, timeline | Done |
| Web interface | Upload, processing, dashboard, incident page with clickable citations, timeline, causal chain, post-mortem download, demo mode | Done |
| User-editable rules | Overrides, rules of your own, critical devices, a command to try a rule file | Done |
| Live syslog | Devices send logs over UDP or TCP; incidents open, grow and close as things happen | Done |
| Alerts | Slack or JSON webhook messages for serious live incidents, with a rate limit, digests and silences | Done |
| One-command install | Docker Compose and an install guide | Done |
| DNS and firewall logs | Cisco ASA, iptables, BIND and dnsmasq, with rules for port scans and DNS failures | Done |
| Evaluation | Measured accuracy on 160 held-out files and 10 noise files, with every miss listed | Done |
| Real-log testing | Results on logs from real devices the tool was not built around | Planned |
| Final documentation and review | This page finished, and a last sweep before publishing | Planned |

### What works today

- **One command analyzes a file.** `netlog analyze router.log` prints what was found, most severe first, with the log lines that prove it. It runs fully offline.
- **Understands Cisco IOS, Linux sshd and sudo, ISC dhcpd, Cisco ASA and iptables (UFW) firewalls, and BIND and dnsmasq DNS servers** on top of both syslog formats. Classic syslog lines carry no year and no timezone, so both are assumed and the report says so.
- **Detects 16 kinds of problem:** flapping and failed interfaces, BGP and OSPF drops, DHCP exhaustion, brute-force logins, config changes, CPU and memory trouble, reloads, MAC flapping, port scans and sweeps, DNS servers failing, and machines looking up many names that do not exist. Rules are plain settings in a file, not code.
- **Gives every finding a severity and a reason.** 300 failed logins that all fail are Medium; the same attack ending in one successful login is Critical.
- **Groups findings into incidents.** Twelve alerts from four routers become one incident. Findings are joined only when they are close in time and connected; an attack and a link fault in the same minute stay separate.
- **Names a likely root cause, with a confidence level.** It orders each incident into cause and effect using what is known about how protocols fail, and it lists what the logs cannot tell. A configuration change shortly before a failure is shown as a suspect, never as proven.
- **Works out who is who from the logs.** Logs never say which address belongs to which router. The tool infers it from adjacency messages, and leaves unknown what it cannot establish.
- **Explains each incident.** Under every incident the report gives a summary, a timeline, the likely cause, what to check and the read-only commands that confirm it, for a junior or a senior reader (`--audience`). Each statement names the lines of the log file it rests on. Steps that would change a device are marked `REVIEW BEFORE RUNNING`.
- **Uses an AI model only if you set one up, and checks what it writes.** The model sees a short evidence pack with addresses and names replaced by stand-ins, never the log file. Its answer is rejected if it cites a line that does not exist, mentions an interface or address that is not in the evidence, or contradicts the severity or root cause the rules decided. A rejected answer is asked for once more, then replaced by the built-in explanation. The report says which of the two wrote each explanation.
- **Collapses noise.** A 50,000-line file reduces to 28 message patterns.
- **Never drops a line.** A line no parser understands is kept and counted, and the tool reports what share of the file it understood.
- **Treats log content as untrusted.** A username such as `admin from 10.0.0.1 port 22` does not fool the parsers, and a log line cannot inject formatting into a report.
- **Has a web interface.** Upload a file or pick a demo scenario, watch the pipeline run, read the dashboard, and open an incident to see its explanation beside the log lines it cites, a timeline of every device's events, and the causal chain drawn as a diagram. Each incident can be downloaded as a post-mortem in Markdown. With no API key the app runs in demo mode and says so.
- **Lets you tune the rules without code.** A rule file of your own changes thresholds, windows and severities, switches rules off, adds new rules and lists your critical devices. `netlog rules test` shows what a rule file would find before you rely on it, and a mistake is refused with a message naming the rule and the setting.
- **Watches the network live.** Devices send their syslog straight to netlog over UDP or TCP. Every few seconds the same rules run over the recent messages: an incident opens when it is first found, grows as evidence arrives, keeps one id the whole time, and closes after five quiet minutes. The listener binds to this computer only unless told otherwise, can be limited to a list of senders, and rate-limits each sender. `netlog replay` sends a sample log to it as if it were happening now.
- **Starts with one command.** `docker compose up -d --build` in `deploy/` starts the API, the live listener and the web interface together, in demo mode until you add a key. Every setting is in one commented `.env` file, data lives in a Docker volume that survives upgrades, and both containers run without root. See [docs/INSTALL.md](docs/INSTALL.md).
- **Sends a chat alert when something serious starts.** A short message to Slack (or anything that takes Slack's format) or to any JSON webhook: the severity, what broke, the likely cause with its confidence, the devices, the start time and a link to the incident. One incident gives one alert, plus one more only if it gets worse. Floods are capped and summed up in a digest, and a device, an incident type or everything can be silenced for planned maintenance. Webhook addresses stay in `.env` and never appear in logs or API answers.

On scenario 2, the live listener sends exactly one alert:

```
CRITICAL: BGP session from R1 to 10.255.0.2 went down, with 11 related findings on R1, R2, R3, R4
Likely cause: Interface GigabitEthernet0/1 on R1 was down for 1m 5s (high confidence)
Devices: R1, R2, R3, R4 | started 2026-03-03 02:46:11 UTC
Open the incident
```

### What is still to come

- **Explanation quality, measured.** Citation validity and fallback rate of real LLM answers, and scores from people using the [manual rubric](docs/EXPLANATION_RUBRIC.md).
- **Logs from real devices.** So far every log is generated. Results on logs the tool was not built around, including from a virtual lab of real router images.
- **Finishing touches.** This page completed, and a final review before publishing.

## Measured accuracy

_These are synthetic logs from this project's own generator, so the numbers show the tool is consistent with its design, not that it works on every real network._

The evaluation harness runs the tool on logs whose answers are known. The **held-out** set is 160 files made fresh for the test, 20 per kind of incident, which the rules were never tuned on: some incidents just above a rule's threshold, some far above, 13 built to fall just short and give nothing, with 2,000 to 10,000 lines of normal traffic around them and cascades reaching 2 to 4 routers. The tuned set is the ten sample logs below; the noise set is 10 files of normal traffic only, up to 50,000 lines. Measured from the logs alone, without a topology file:

| Set | Files | Lines | Incidents | Found | False alarms | Precision | Recall | Root cause | Severity | Devices |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Held-out** | 160 | 894,486 | 167 | 167 | 0 | 100% | 100% | 100% | 100% | 88.0% |
| Tuned | 10 | 94,918 | 9 | 9 | 0 | 100% | 100% | 100% | 100% | 88.9% |
| Noise only | 10 | 143,014 | 0 | 0 | 0 | | | | | |

A found incident matches an expected one when it is of the same type, its likely cause is on the same device, and their times overlap. An unexpected incident at Medium or above is a false alarm. The tool reads, detects and correlates about 5,000 lines a second, and 94,918 lines of the sample logs reduce to 299 message patterns.

**Why these numbers are weaker than they look.** The held-out files come from the same generator as the tuned ones, with the same message wording: they vary strength, volume and device count, not how devices word their messages, so a perfect score here says nothing about wording the tool has not seen. The rules and the generator were also written from the same understanding of how protocols fail. The one gap the harness does show is real: when a switch reloads, the router whose link to it drops is left out of the incident in all 21 such files, because nothing in the logs says the two are cabled together and the tool does not guess; a topology file fills it in. Explanations are not measured yet. Logs from real devices are the next test.

The full results, with every item listed, are in [eval/results/latest.md](eval/results/latest.md), and on the Accuracy page of the web app.

Here is the report for a log where one failed interface, hidden in 5,000 lines, took down routing on four routers (most evidence lines and the explanation left out, the rest shortened):

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
| Port scan | One address trying many ports and being refused by a firewall | 25 different ports in 1 minute | Medium; High if a connection from it is then let through |
| Port sweep | One address trying one port on many machines | 20 different addresses in 1 minute | Medium |
| DNS failures | A DNS server failing to answer | 20% of queries, at least 20, in 5 minutes | Medium; High at half or more |
| Names that do not exist | One machine looking up many names that do not exist, a sign of some malware | 50 different names in 5 minutes | Medium |

Every threshold is a setting in `backend/netlog/config/rules.toml`. You can change any rule's threshold, window or severity, switch it off, list your critical devices, and add rules of your own in `data/rules.toml`, without editing that file; `netlog rules test my-rules.toml router.log` shows what a rule file would find before you rely on it. See [docs/WRITING_RULES.md](docs/WRITING_RULES.md). A deliberate shutdown, a single unplugged cable, one mistyped password and everyday refused connections are not reported as problems.

[docs/RULES.md](docs/RULES.md) describes each rule in full: its log signature, usual causes, and when it can be wrong.

## Getting started

### With Docker

The quickest way to try it. Needs Docker Desktop (Windows, macOS) or Docker Engine with Compose 2.24 or newer (Linux):

```powershell
git clone https://github.com/siddxwar04/Network-Log.git
cd Network-Log/deploy
docker compose up -d --build
```

Then open http://localhost:8080 and pick a demo scenario. [docs/INSTALL.md](docs/INSTALL.md) covers settings, adding an LLM key, pointing devices at the live listener, backups, upgrades and removal.

### From source

For development, and for the `netlog` command. Requires Python 3.11 or newer. Commands are for Windows PowerShell.

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
.venv\Scripts\netlog analyze router.log --audience junior
.venv\Scripts\netlog analyze router.log --no-llm
.venv\Scripts\netlog analyze data\scenarios\07_device_reload.log --year 2026 --topology data\scenarios\topology.toml
```

Measure its accuracy: generate the held-out and noise sets once (about 30 seconds), then run the harness (about 5 minutes). It writes `eval/results/latest.md` and `latest.json`:

```powershell
.venv\Scripts\python -m eval.heldout
.venv\Scripts\python -m eval.harness
```

Or check the tool quickly against the answer keys of the twelve sample logs only:

```powershell
.venv\Scripts\python -m eval.scorecard --topology data\scenarios\topology.toml
```

See the evidence pack of an incident: the short, numbered case file that is the only thing an LLM will be shown, with addresses and names replaced by stand-ins. Without `--show` it lists the size of every pack:

```powershell
.venv\Scripts\python -m eval.packs --show 02_cascade
.venv\Scripts\python -m eval.packs
```

Every report explains its incidents with built-in templates. To have an LLM write the explanations instead, copy `.env.example` to `.env` and set `NETLOG_LLM_PROVIDER=openai` and your key in `NETLOG_LLM_API_KEY`; `netlog analyze` then makes a paid request for each incident it lists, and `--no-llm` switches that off for one run. The command below shows one scenario's explanations on their own. Every answer is checked against the evidence pack before it is shown: its citations must exist, it may not mention anything that is not in the pack, and it may not contradict what the tool decided. An answer that fails is asked for once more; if that fails too, a built-in explanation written from fixed templates is used instead. Answers that pass are cached, so the same incident is only paid for once. Without a key the command prints the built-in explanation and says so.

```powershell
.venv\Scripts\python -m eval.explain 02_cascade
.venv\Scripts\python -m eval.explain 02_cascade --mode junior
```

Count how the explanations of every sample incident fared against those checks. With a provider configured it makes paid requests, so it does nothing until you add `--yes`:

```powershell
.venv\Scripts\python -m eval.validity
```

See [docs/CLI.md](docs/CLI.md) for every option, the exit codes and the JSON format.

Start the web API, which puts the same pipeline behind HTTP for a browser or another program:

```powershell
.venv\Scripts\python -m uvicorn netlog.api.app:app
```

Then open http://127.0.0.1:8000/docs. The page lists every endpoint and lets you try each one: upload a file with `POST /api/uploads`, poll `GET /api/uploads/{id}/status` until the stage is `done`, then read `GET /api/uploads/{id}/incidents`. The API has no login and is meant for one person's machine; do not expose it to a network you do not trust. Uploaded files are kept in `data/uploads/` under generated names and results in `data/netlog.db`; the size limit and the browser origins allowed to call it are settings under `[api]`.

To use it in the browser, keep the API running and start the web interface in a second PowerShell window. It needs Node.js 20 or newer; the first `npm install` takes a few minutes.

```powershell
cd frontend
npm install
npm run dev
```

Then open http://localhost:5173. Drop a log file on the page, or click a demo scenario, and watch the pipeline work through its stages; the dashboard of the file opens when it is done. Open an incident to read its explanation beside the log lines it rests on: every statement ends in line numbers you can click to find the line, the timeline shows each device's events in time, and the causal chain draws what caused what. Download post-mortem saves the incident as a Markdown document for a team to review and file; `netlog postmortem router.log` writes the same from the command line. Run the frontend's own tests with `npm test` in the same folder.

Devices can also send their logs straight to netlog as things happen: start the API with `$env:NETLOG_LIVE = "1"` first, and the Live page shows incidents opening, growing and closing. `netlog replay data\scenarios\02_cascade.log --speed 20 --start 02:44` sends a sample to it, as if now. See [Live syslog](docs/CLI.md#live-syslog) for pointing a router at it and what plain syslog's lack of authentication means.

To get a chat message when the listener finds something serious, put a webhook address in `.env`: `NETLOG_ALERT_SLACK_URL` for Slack or anything that takes its format, `NETLOG_ALERT_WEBHOOK_URL` for plain JSON. Then restart the API and check the setup:

```powershell
.venv\Scripts\netlog alerts test
.venv\Scripts\netlog alerts silence --device R1 --for 2h --reason "IOS upgrade"
.venv\Scripts\netlog alerts list
```

See [Alerts](docs/CLI.md#alerts) for when an alert is sent, the rate limit, silences and hiding addresses and usernames in alert text.

With no API key set up, the app runs in demo mode and says so: nothing is sent anywhere, the demo scenarios use explanations an LLM wrote earlier and that are stored in `data/scenarios/explanations.json` (once that file has been generated with `netlog demo-explanations --yes`), and other files get the built-in explanations.

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
| `06_port_scan` | One address on the internet tries 500 ports on the firewall and is refused |
| `07_device_reload` | A switch is reloaded: minutes of silence, then boot messages |
| `08_noise` | A normal day with no incident, firewall and DNS servers included |
| `08_noise_50k` | The same normal day at 50,000 lines, for checking speed and false alarms |
| `09_prompt_injection` | The brute force again, with usernames written to talk an LLM into hiding it |
| `10_overlap` | Two unrelated incidents at the same time |
| `11_dns_failure` | The DNS resolver cannot reach the internet for 10 minutes; most queries fail |

The noise in these files is built to resemble incidents without being one: a single port going down and up, an administrator shutting a port on purpose, one mistyped password, addresses on the internet trying a couple of ports, clients looking up names that do not exist. Detection rules have to tell the difference.

See [generator/README.md](generator/README.md) for the simulated network, the line formats and the label format.

## Repository layout

```
backend/
  netlog/
    cli.py           the netlog command
    rules_cli.py     netlog rules test
    alerts_cli.py    netlog alerts test, list, silence, unsilence
    schema.py        the normalized event
    ingestion/       reading files
    parsers/         syslog, Cisco IOS, Linux auth and DHCP parsers
    storage/         SQLite database
    mining/          template mining and dedup
    detection/       rule engine and severity
    config/          default settings and the built-in rules
    report/          text, Markdown and JSON reports
    correlation/     incidents, topology, cause and effect
    llm/             the evidence pack, the prompt, the provider adapter, the cache,
                     the validator and the built-in explanations
    redaction/       hiding addresses and names before they leave the machine
    api/             the web API and the background pipeline
    live/            the live syslog listener, incident tracking and replay
    alerts/          when to alert, message formats and webhook delivery
  tests/
generator/           test log generator
eval/                the evaluation harness and held-out sets, scorecard, pack sizes,
                     a command to try an explanation, validity counts
  results/           the latest accuracy results
data/scenarios/      generated logs with label files
deploy/              Docker images, Compose file, settings example, smoke test
docs/                reference documentation
frontend/            web interface (React, Vite, Tailwind)
```

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md): installing and running it with Docker.
- [docs/CLI.md](docs/CLI.md): the command, its options, exit codes and JSON output.
- [docs/RULES.md](docs/RULES.md): every detection rule, with its log signature, thresholds, severity and usual causes.
- [docs/WRITING_RULES.md](docs/WRITING_RULES.md): tuning the rules and writing your own, with three worked examples.
- [docs/SCHEMA.md](docs/SCHEMA.md): every field of the normalized event, with worked examples.
- [docs/EXPLANATION_RUBRIC.md](docs/EXPLANATION_RUBRIC.md): a one-page sheet for scoring explanations by hand.
- [eval/results/latest.md](eval/results/latest.md): the latest accuracy results.
- [generator/README.md](generator/README.md): the test log generator.

## Limitations

- **A root cause is the tool's best reading of the logs, not a verdict.** It is found by applying fixed rules about what can cause what. Each incident states a confidence level and what the logs cannot tell.
- **Not yet tried against a real AI model at scale.** The validator, the retry and the fallback are tested with stand-in answers, including hostile ones; the stored demo explanations have not been generated yet.
- **Tested on generated logs only.** The sample logs follow real Cisco IOS and ASA, OpenSSH, ISC dhcpd, BIND, dnsmasq and UFW formats, but they come from this project's own generator, so the results show the tool is consistent with its design, not that it works on every network. Testing on logs from real devices is planned.
- **Little knowledge of your network.** The tool cannot tell a core uplink from a desk port unless you list what is critical in the settings, so an interface going down is Info on its own. It also cannot know which cable goes where; a small topology file fills that in.
- **Cisco IOS first.** Other vendors will follow once the pipeline is complete.
- **Plain syslog has no authentication.** Anyone who can reach the listener's port can send messages that look like they come from your routers. Keep it on a network you trust; see [Live syslog](docs/CLI.md#live-syslog).
- **Live incidents look back two hours.** An incident longer than that keeps the counts of its first findings, and a topology file is not used for live incidents yet.
- **Alerts go to chat only.** Slack-compatible and JSON webhooks; no email or paging services, and alert settings are changed in the settings file, not on a screen. Not yet tried against a real Slack workspace.
- **Single user, no login.** The web app and API are meant for one person's machine. The Docker install publishes them on this computer only by default, without HTTPS.
- **Live devices on Docker Desktop.** A Cisco device does not name itself in syslog, so it is named by its address; Docker Desktop on Windows and macOS may show every device as one internal address. For live monitoring of several devices, run the Docker install on Linux. See [docs/INSTALL.md](docs/INSTALL.md#send-logs-from-your-devices).

## Tech stack

Backend: Python with FastAPI, pydantic, SQLite, Drain3, pytest and ruff. Frontend: React with Vite, Tailwind and Apache ECharts.
