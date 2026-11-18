# Event Schema

Every log line, whatever device wrote it, is converted into one **event** with the same fields. Parsers produce events. Everything after parsing (storage, detection rules, correlation, explanations, the UI) reads events and never the raw text format.

The schema is defined in `backend/netlog/schema.py`.

## Event fields

### Identity

| Field | Required | Meaning | Example |
|---|---|---|---|
| `id` | No | Database id, assigned when the event is stored | `1042` |
| `upload_id` | No | The upload this event belongs to, assigned when stored | `3` |
| `line_no` | Yes | Line number in the source file, starting at 1 | `1340` |
| `raw` | Yes | The line exactly as it was read, so it can be shown and cited | see the examples below |

### Time

| Field | Required | Meaning | Example |
|---|---|---|---|
| `timestamp` | Yes, unless unparsed | When the event happened, always stored in UTC. A timestamp with no timezone is rejected; one in another timezone is converted | `2026-03-03T02:14:07.123Z` |
| `year_assumed` | No (default false) | True when the log line had no year and one was assumed | `true` |
| `tz_assumed` | No (default false) | True when the log line had no timezone and one was assumed | `true` |

### Origin

| Field | Required | Meaning | Example |
|---|---|---|---|
| `host` | No | The device that wrote the line | `R1` |
| `source_type` | No (default `unknown`) | The kind of log: `cisco_ios`, `linux_auth`, `dhcp`, `syslog_generic` or `unknown` | `cisco_ios` |
| `app` | No | The program or syslog tag that wrote the line | `sshd` |

### Classification

| Field | Required | Meaning | Example |
|---|---|---|---|
| `facility` | No | Syslog facility number, 0 to 23, when the line carries one | `23` |
| `severity` | No | Syslog severity, 0 to 7, when the line carries one | `3` |
| `event_key` | No | A stable name for the type of event. Detection rules match on this | `LINK-3-UPDOWN`, `sshd.failed_password` |

Severity levels:

| Number | Name | Number | Name |
|---|---|---|---|
| 0 | Emergency | 4 | Warning |
| 1 | Alert | 5 | Notice |
| 2 | Critical | 6 | Informational |
| 3 | Error | 7 | Debug |

For Cisco IOS the event key is the message code, `FACILITY-SEVERITY-MNEMONIC`. For other sources it is a name this project defines, in the form `program.event`.

### Content

| Field | Required | Meaning | Example |
|---|---|---|---|
| `message` | No (default empty) | The message text with the header removed | `Interface GigabitEthernet0/1, changed state to down` |
| `entities` | No | The named things the line talks about; see below | |

### Processing

| Field | Required | Meaning | Example |
|---|---|---|---|
| `parse_status` | No (default `parsed`) | `parsed`, `partial` (header understood, line damaged or truncated) or `unparsed` (kept, but no parser understood it) | `parsed` |
| `template_id` | No | The message pattern this event belongs to, filled in by template mining | `t-9f2c1a` |

An unparsed line is still an event. It needs only `line_no` and `raw`, so no line is ever dropped.

## Entity fields

All optional. Detection rules group and match on these.

| Field | Meaning | Example |
|---|---|---|
| `interface` | Interface name in canonical long form | `GigabitEthernet0/1` |
| `src_ip` | Source address, such as the client of a login attempt | `203.0.113.9` |
| `dst_ip` | Destination address | `10.0.1.20` |
| `neighbor_ip` | Routing neighbor, as in a BGP or OSPF message | `10.0.0.2` |
| `username` | Username exactly as logged. This is attacker-controlled text and is never trusted | `admin` |
| `mac` | MAC address as lowercase colon-separated pairs | `00:11:22:33:44:55` |
| `vlan` | VLAN id, 1 to 4094 | `10` |
| `protocol` | Protocol the event concerns | `ospf`, `bgp`, `ssh` |
| `port` | TCP or UDP port, 0 to 65535 | `51522` |
| `state_from` | Previous state | `FULL` |
| `state_to` | New state | `down` |
| `reason` | The reason the device gave | `Dead timer expired` |
| `extra` | Other named values specific to one message type | `{"second_interface": "GigabitEthernet0/2"}` |

### Interface names

Cisco devices print the same port in several ways. They are all stored in the long form so that events about one port compare as equal:

| As logged | Stored as |
|---|---|
| `Gi0/1`, `gigabitethernet0/1`, `GigabitEthernet0/1` | `GigabitEthernet0/1` |
| `Fa0/24` | `FastEthernet0/24` |
| `Te1/0/1` | `TenGigabitEthernet1/0/1` |
| `Po1` | `Port-channel1` |
| `Vl10` | `Vlan10` |

Linux-style names that are all lowercase with no slash, such as `eth0` or `ens33`, are kept as they are. A name whose type is unknown or ambiguous is also kept as logged.

### Addresses

IP addresses are validated and stored in standard form (`2001:DB8:0:0:0:0:0:1` becomes `2001:db8::1`). MAC addresses are accepted in Cisco dotted (`0011.2233.4455`), colon or dash notation and stored in one form.

## Worked examples

The examples assume the year 2026 and the UTC timezone, since these lines carry neither.

### 1. Cisco link down

```
<187>Mar  3 02:14:07 R1 1042: *Mar  3 02:14:07.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
```

| Field | Value | Where it came from |
|---|---|---|
| `timestamp` | `2026-03-03T02:14:07.123Z` | The device's own timestamp inside the message |
| `year_assumed`, `tz_assumed` | `true`, `true` | The line has no year and no timezone |
| `host` | `R1` | Syslog header |
| `source_type` | `cisco_ios` | The `%FACILITY-SEVERITY-MNEMONIC:` pattern |
| `facility` | `23` | `<187>` divided by 8 |
| `severity` | `3` (Error) | The `3` in `%LINK-3-UPDOWN` |
| `event_key` | `LINK-3-UPDOWN` | The message code |
| `message` | `Interface GigabitEthernet0/1, changed state to down` | Text after the code |
| `entities.interface` | `GigabitEthernet0/1` | Message text |
| `entities.state_to` | `down` | Message text |

### 2. Failed SSH login

```
Mar  3 02:20:11 srv1 sshd[2417]: Failed password for invalid user admin from 203.0.113.9 port 51522 ssh2
```

| Field | Value | Where it came from |
|---|---|---|
| `timestamp` | `2026-03-03T02:20:11Z` | Syslog header |
| `year_assumed`, `tz_assumed` | `true`, `true` | The line has no year and no timezone |
| `host` | `srv1` | Syslog header |
| `source_type` | `linux_auth` | The program is `sshd` |
| `app` | `sshd` | Syslog tag |
| `facility`, `severity` | empty | The line has no `<PRI>` prefix |
| `event_key` | `sshd.failed_password` | Defined by this project |
| `message` | `Failed password for invalid user admin from 203.0.113.9 port 51522 ssh2` | Text after the tag |
| `entities.username` | `admin` | Message text |
| `entities.src_ip` | `203.0.113.9` | Message text |
| `entities.port` | `51522` | Message text |
| `entities.protocol` | `ssh` | The program |
| `entities.extra` | `{"invalid_user": "true"}` | The words "invalid user" |

### 3. DHCP pool exhausted

```
Mar  3 09:01:44 dhcp1 dhcpd[811]: DHCPDISCOVER from 00:11:22:33:44:55 via eth1: network 10.20.0.0/24: no free leases
```

| Field | Value | Where it came from |
|---|---|---|
| `timestamp` | `2026-03-03T09:01:44Z` | Syslog header |
| `host` | `dhcp1` | Syslog header |
| `source_type` | `dhcp` | The program is `dhcpd` |
| `app` | `dhcpd` | Syslog tag |
| `event_key` | `dhcp.no_free_leases` | Defined by this project |
| `entities.mac` | `00:11:22:33:44:55` | Message text |
| `entities.interface` | `eth1` | Message text; a Linux name, kept as logged |
| `entities.extra` | `{"network": "10.20.0.0/24"}` | Message text |
