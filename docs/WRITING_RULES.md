# Writing Rules

netlog, the command behind CauseLine, finds problems with detection rules: "five link failures on one interface within five minutes is a link flap". The built-in rules are described in [RULES.md](RULES.md). Every network is different, so you can tune them and add your own in a rule file, without programming and without editing the built-in file.

A rule file is plain data in [TOML](https://toml.io). It can never run code or commands, and it cannot read other files. A file with a mistake is refused with a message that names the rule, the setting and the problem; netlog never runs with a rule silently ignored.

## Where your rule file lives

| How | Used by |
|---|---|
| `data/rules.toml`, or the file named by `user_file` under `[rules]` in your settings | the web app and every command, when the file exists |
| `--rules my-rules.toml` | one run of `netlog analyze` or `netlog postmortem` |
| the `NETLOG_RULES` environment variable | every run, in place of the above |

`data/rules.toml` is not part of the repository: it is yours. The web API writes changes made through it to the same file (see [The API](#the-api)).

Before relying on a rule file, try it on a log you already have:

```powershell
.venv\Scripts\netlog rules test my-rules.toml router.log --year 2026
```

It runs the built-in rules with your file applied, prints how many times each rule triggered and what each finding says, and stores nothing. Lower a threshold, run it against last month's logs, and you see how many more findings it would have given.

## A rule file has three parts

```toml
# 1. Change some settings of a rule and keep the rest.
[[override]]
name = "link_flap"
threshold = 3

# 2. Add a rule of your own, or replace a built-in one completely by using its name.
[[rule]]
name = "config_storm"
# ... every setting, as described below

# 3. Devices and interfaces whose findings are one level more serious.
[critical]
devices = ["CORE-SW1"]
interfaces = [{ host = "R1", interface = "GigabitEthernet0/1" }]
```

All three are optional. Anything else in the file is refused.

## Overrides

An `[[override]]` names an existing rule (built-in or yours) and the settings to change:

| Setting | What it changes | Rules it applies to |
|---|---|---|
| `name` | Which rule. Required | |
| `enabled` | `false` switches the rule off; it then finds nothing | all |
| `severity` | The base level: `info`, `low`, `medium`, `high` or `critical` | all |
| `severity_because` | Why, in a few words, shown with the severity | all |
| `strong_at` | How far past the threshold a finding is at full strength | all |
| `threshold` | How many matching events | threshold rules |
| `window_seconds` | Within how many seconds | threshold rules |
| `within_seconds` | The time limit between the two events | sequence and absence rules |

A rule may be overridden only once per file.

## Rules

Every `[[rule]]` has these settings:

| Setting | Meaning |
|---|---|
| `name` | A unique name, such as `config_storm`. A name already used by a built-in rule replaces that rule |
| `incident_type` | What kind of problem it is, such as `config_storm`. Findings of the same type and devices are grouped into incidents |
| `kind` | `threshold`, `share`, `sequence` or `absence` (below) |
| `title` | The finding's one-line title. It may use `{host}`, `{count}`, `{duration}` and any field the rule groups by, such as `{interface}`; a field written `extra.network` is used as `{network}`. Only the name goes in the braces: formatting such as `{count:>5}` is refused |
| `description` | One sentence on what the rule is for |
| `enabled` | `true` (the default) or `false` |
| `severity` | The base level: `info`, `low`, `medium` (the default), `high` or `critical` |
| `severity_because` | Why that level, in a few words |
| `severity_when` | Conditions that raise the level: a list of `{ flag = "...", level = "...", because = "..." }` or `{ strength_at_least = 0.5, level = "...", because = "..." }` |
| `strong_at` | When the finding counts as strong: this many times the threshold in the busiest window (default 4) |

### Which events a rule looks at

| Setting | Meaning |
|---|---|
| `event_keys` | The message types to match, such as `["LINK-3-UPDOWN"]` or `["sshd.failed_password"]`. Required. A message type that no parser produces gives a warning, since it may be a typo |
| `where` | Fields that must have a value, or one of a list: `where = { state_to = "down" }` |
| `where_not` | Fields that must not have a value |

The fields are `host`, `app`, `source_type`, `severity` (the syslog level, 0 to 7), `event_key`, the entities `interface`, `src_ip`, `dst_ip`, `neighbor_ip`, `username`, `mac`, `vlan`, `protocol`, `port`, `state_from`, `state_to`, `reason`, and any `extra.<name>` a parser records. [SCHEMA.md](SCHEMA.md) lists the message types and the fields each one fills in.

### `kind = "threshold"`

At least `threshold` matching events for the same group within `window_seconds`. With `threshold = 1` every matching event is a finding, and events close together are joined into one.

| Setting | Meaning |
|---|---|
| `group_by` | The fields that make events "the same thing", such as `["host", "interface"]`. Required |
| `window_seconds` | The time window. Required, greater than zero |
| `threshold` | How many events. Required, a whole number greater than zero |
| `count_distinct` | Count different values of this field instead of events: `count_distinct = "port"` makes `threshold = 25` mean 25 different ports, so retries to one port count once. It cannot be a `group_by` field. The title can use `{distinct_port}` |
| `distinct` | Count how many different values of a field were seen, such as the usernames tried |
| `capture` | Record the most common value of a field |
| `tags` | Add a flag when a metric reaches a level: `{ name = "flag", metric = "count", at_least = 20 }` |
| `followed_by` | Add a flag when a second kind of event came afterwards, such as a successful login after many failures |
| `related` | Add other events about the same thing to the evidence |

### `kind = "share"`

The matching events make up at least `share` of the events `of` matches, and number at least `threshold`, within `window_seconds`, for the same group. The built-in `dns_failure_spike` is one: failed answers as a share of the questions asked.

| Setting | Meaning |
|---|---|
| `event_keys`, `where`, `where_not` | The events being measured, such as failures |
| `of` | A table with `event_keys` (and optionally `where`, `where_not`): what they are a share of, such as all queries |
| `group_by`, `window_seconds`, `threshold` | As for a threshold rule. `threshold` is the least number of measured events |
| `share` | The share, from 0 to 1: `0.2` is 20% |
| `distinct`, `capture` | As for a threshold rule |

When there are fewer `of` events than measured ones (a server that logs its failures but not its queries), the measured events are taken as the whole. The title can use `{count}`, `{total}` (the `of` events in the same stretch), `{percent}` and `{peak_percent}`. Strength is the busiest window's share divided by `share` times `strong_at`.

### `kind = "sequence"`

An event matching `first`, then one matching `then`, for the same group within `within_seconds`.

| Setting | Meaning |
|---|---|
| `first`, `then` | Two tables, each with `event_keys` and optionally `where` and `where_not` |
| `same` | The fields both events must share, such as `["host", "src_ip"]` |
| `within_seconds` | The time limit. Required, greater than zero |

The title of a sequence rule may also use `{duration}` for the time between the two events.

### `kind = "absence"`

Like a sequence, but a finding is made when the `then` event does NOT come in time: something went down and did not come back.

## Critical devices and interfaces

```toml
[critical]
devices = ["CORE-SW1", "R1"]
interfaces = [{ host = "R1", interface = "GigabitEthernet0/1" }]
```

A finding on a critical device or interface is one level more serious, and its severity reason says so. These add to the lists under `[severity]` in the settings.

## When something is wrong

netlog refuses a rule file with a mistake, and says exactly what is wrong:

| Mistake | Message |
|---|---|
| A misspelled setting | `rule 'link_flap': override threshhold is not a setting an override can change (known: enabled, severity, ...)` |
| A negative window | `rule 'config_storm': window_seconds must be a number greater than zero, not -60` |
| A threshold of zero | `rule 'config_storm': threshold must be a number greater than zero, not 0` |
| A number in quotes | `rule 'config_storm': threshold must be a number greater than zero, not '11'` |
| The same name twice | `rule 'config_storm' is defined twice in my-rules.toml` |
| A rule that does not exist | `my-rules.toml: [[override]] names rule 'link_flapp', which does not exist` |
| Formatting in a title | `rule 'config_storm': title formats {count}; write the name alone, as {count}` |

A message type no parser produces is only a warning, since your devices may send messages netlog has no parser for:

```text
netlog: warning: rule 'config_storm': event key 'SYS-5-CONFIG_l' is not a message type netlog knows; check the spelling (it is fine if your devices send it)
```

The web API will not start with a rule file that has a mistake, and a change made through the API that would make one is refused with the same message.

## Three worked examples

Each example below shows the log lines, the rule file and what `netlog rules test` prints. They are tested exactly as written.

### 1. Tuning: link flaps at 3 instead of 5

On a small college network, an uplink that drops three times in five minutes is already serious. The built-in `link_flap` rule waits for five, so this log of three flaps finds nothing:

<!-- example 1 log -->
```text
Mar  3 09:00:05 R1 101: Mar  3 09:00:05.120: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
Mar  3 09:00:09 R1 102: Mar  3 09:00:09.480: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up
Mar  3 09:00:51 R1 103: Mar  3 09:00:51.022: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
Mar  3 09:00:54 R1 104: Mar  3 09:00:54.310: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up
Mar  3 09:01:58 R1 105: Mar  3 09:01:58.705: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
Mar  3 09:02:02 R1 106: Mar  3 09:02:02.941: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up
```

Lower the threshold and keep everything else about the rule:

<!-- example 1 rule -->
```toml
# Three flaps in five minutes is already serious on this network.
[[override]]
name = "link_flap"
threshold = 3
```

```powershell
.venv\Scripts\netlog rules test tuning.toml flaps.log --year 2026
```

<!-- example 1 result -->
```text
Rules: 16 built-in; from tuning.toml: 1 changed (link_flap), 0 added
Log: flaps.log, 6 lines

link_flap: triggered 1 time
  medium   Interface GigabitEthernet0/2 on R1 went down 3 times in 1m 54s
No other rule triggered.
```

### 2. A new threshold rule: more than 10 configuration changes in an hour

A deployment script stuck in a loop, or someone making many changes in a hurry, shows as a burst of `SYS-5-CONFIG_I` messages on one device. This log has 11 changes on SW1 in 35 minutes:

<!-- example 2 log -->
```text
Mar  3 14:02:10 SW1 500: Mar  3 14:02:10.100: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:05:10 SW1 501: Mar  3 14:05:10.137: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:09:10 SW1 502: Mar  3 14:09:10.174: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:12:10 SW1 503: Mar  3 14:12:10.211: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:15:10 SW1 504: Mar  3 14:15:10.248: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:19:10 SW1 505: Mar  3 14:19:10.285: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:22:10 SW1 506: Mar  3 14:22:10.322: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:26:10 SW1 507: Mar  3 14:26:10.359: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:30:10 SW1 508: Mar  3 14:30:10.396: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:33:10 SW1 509: Mar  3 14:33:10.433: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
Mar  3 14:37:10 SW1 510: Mar  3 14:37:10.470: %SYS-5-CONFIG_I: Configured from console by deploy on vty0 (192.0.2.40)
```

"More than 10" is a threshold of 11:

<!-- example 2 rule -->
```toml
[[rule]]
name = "config_storm"
incident_type = "config_storm"
description = "Many configuration changes on one device in a short time: a script gone wrong, or someone in a hurry."
kind = "threshold"
title = "{count} configuration changes on {host} in {duration}"
event_keys = ["SYS-5-CONFIG_I"]
group_by = ["host"]
window_seconds = 3600
threshold = 11
severity = "medium"
severity_because = "a burst of changes is easy to get wrong and hard to undo"
```

```powershell
.venv\Scripts\netlog rules test storm.toml changes.log --year 2026
```

<!-- example 2 result -->
```text
Rules: 16 built-in; from storm.toml: 0 changed, 1 added (config_storm)
Log: changes.log, 11 lines

config_change: triggered 1 time
  info     Configuration of SW1 changed by deploy
config_storm: triggered 1 time
  medium   11 configuration changes on SW1 in 35m
No other rule triggered.
```

The built-in `config_change` rule still records the changes themselves at `info`; the new rule adds the burst at `medium`.

### 3. A new sequence rule: a login, then a configuration change from the same address within 2 minutes

On a network where changes go through a change window, someone logging in and changing the configuration straight away is worth a look. This log has two logins on R2, each followed by a change from the same address: one 45 seconds later, one 11 minutes later.

<!-- example 3 log -->
```text
Mar  3 21:14:02 R2 801: Mar  3 21:14:02.517: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 198.51.100.23] [localport: 22] at 21:14:02 UTC Tue Mar 3 2026
Mar  3 21:14:47 R2 802: Mar  3 21:14:47.090: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (198.51.100.23)
Mar  3 21:30:11 R2 803: Mar  3 21:30:11.204: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netops] [Source: 10.10.10.55] [localport: 22] at 21:30:11 UTC Tue Mar 3 2026
Mar  3 21:41:36 R2 804: Mar  3 21:41:36.662: %SYS-5-CONFIG_I: Configured from console by netops on vty0 (10.10.10.55)
```

<!-- example 3 rule -->
```toml
[[rule]]
name = "login_then_config"
incident_type = "login_then_config"
description = "A login followed soon by a configuration change from the same address."
kind = "sequence"
title = "Login to {host} from {src_ip}, then a configuration change {duration} later"
same = ["host", "src_ip"]
within_seconds = 120
severity = "low"
severity_because = "on this network changes go through a change window, so a quick change is worth a look"

[rule.first]
event_keys = ["SEC_LOGIN-5-LOGIN_SUCCESS"]

[rule.then]
event_keys = ["SYS-5-CONFIG_I"]
```

```powershell
.venv\Scripts\netlog rules test sequence.toml login.log --year 2026
```

<!-- example 3 result -->
```text
Rules: 16 built-in; from sequence.toml: 0 changed, 1 added (login_then_config)
Log: login.log, 4 lines

config_change: triggered 2 times
  info     Configuration of R2 changed by admin
  info     Configuration of R2 changed by netops
login_then_config: triggered 1 time
  low      Login to R2 from 198.51.100.23, then a configuration change 45s later
No other rule triggered.
```

Only the first login counts: the second change came 11 minutes after its login, past the 2-minute limit.

## Using a rule file for real

Save your rules as `data/rules.toml`, and every analysis uses them: the web app from its next upload on, and every `netlog analyze`. Findings of your rules are grouped into incidents and reported like those of the built-in rules.

## The API

| Request | What it does |
|---|---|
| `GET /api/rules` | Every rule in force with its settings, where it comes from (`built-in`, `built-in, changed` or `your file`), what your file changes, your critical devices and interfaces, and any warnings |
| `PATCH /api/rules/{name}` | Changes a rule's `enabled`, `severity`, `threshold`, `window_seconds` or `within_seconds`, for example `{"threshold": 3}`. The change is written to your rule file as an `[[override]]`, keeping everything else in the file, and applies to analyses started from then on. A value that does not fit is refused with the same message as above, and the file is left as it was |

Try them at http://127.0.0.1:8000/docs while the API is running.
