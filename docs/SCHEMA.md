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
| `source_type` | No (default `unknown`) | The kind of log: `cisco_ios`, `linux_auth`, `dhcp`, `firewall`, `dns`, `syslog_generic` or `unknown` | `cisco_ios` |
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

## Cisco IOS events

### Which timestamp is used

A Cisco line stored by a syslog collector carries two times: the collector's, and the device's own inside the message.

```
Mar  3 02:46:12 R1 89085: Mar  3 02:46:11.699: %LINK-3-UPDOWN: ...
|-------------|           |------------------|
 collector time             device time
```

The device time is used, because it records when the event happened and has millisecond precision. The collector time is used instead in three cases, and `entities.extra["clock"]` says which:

| `clock` | Meaning | Example device time |
|---|---|---|
| `unsynced` | The device marked its clock as not set (a leading `*`). A switch that has just booted prints a date in 1993 until NTP answers | `*Mar  1 00:00:52.000` |
| `uptime` | The device prints time since boot, not a date | `00:01:23` |
| `suspect` | The device's clock is more than 24 hours away from the collector's | `Jan  5 10:00:00.000` on a line collected on 3 March |

When the collector time is used, the device's original text is kept in `entities.extra["device_time"]`.

A device time has no year unless the device is configured to print one. The year is chosen so that the device time lands closest to the collector time, which handles a line logged at `Dec 31 23:59:59` and collected at `Jan  1 00:00:00`.

A line that comes straight from a device with no collector header (`<189>42: Mar  3 02:14:07.123: %...`) has only the device time, so that is used whatever its state.

### Severity

The digit in the message code is the severity (`%LINK-3-UPDOWN` is severity 3). When a line also has a `<PRI>` prefix that disagrees, the message code wins.

### Extra values

| Key in `entities.extra` | Set for | Meaning |
|---|---|---|
| `seq` | Any Cisco message | The device's message counter. It restarts from 1 after a reboot |
| `clock`, `device_time` | See above | Why the device's clock was not used |
| `admin` | `LINK-5-CHANGED` | `true` when a person shut the interface on purpose |
| `second_interface` | `SW_MATM-4-MACFLAP_NOTIF` | The other port the MAC address is flapping between |
| `vrf` | `BGP-5-ADJCHANGE` | The VRF, when the session is in one |
| `direction`, `error_code`, `error_meaning` | `BGP-3-NOTIFICATION` | `sent` or `received`, the code such as `4/0`, and what the code means |
| `process` | `OSPF-5-ADJCHG`, `SYS-3-CPUHOG`, `SYS-2-MALLOCFAIL` | The OSPF process id, or the name of the process involved |
| `source`, `line` | `SYS-5-CONFIG_I`, `SYS-5-RELOAD` | Where the change came from, such as `console` and `vty0` |
| `duration_ms` | `SYS-3-CPUHOG` | How long the task held the CPU |
| `bytes` | `SYS-2-MALLOCFAIL` | The size of the allocation that failed |
| `software` | `SYS-5-RESTART` | The software version line |

### Messages that are not understood

A Cisco message with a code this project has no extractor for is still a parsed event: it has its event key, severity and message, and no entities. A message whose code is known but whose wording is not what the extractor expects is marked `partial`, so the gap shows up in parse coverage.

## Linux authentication events

Lines from `sshd`, `sudo` and `cron` get the source type `linux_auth`.

| Event key | Message | Entities |
|---|---|---|
| `sshd.failed_password` | `Failed password for ... from ... port ...` | `username`, `src_ip`, `port` |
| `sshd.accepted` | `Accepted password for ...` or `Accepted publickey for ...` | `username`, `src_ip`, `port` |
| `sshd.invalid_user` | `Invalid user ... from ...` | `username`, `src_ip`, `port` |
| `sshd.connection_closed` | `Connection closed by ...`, `Disconnected from ...`, `Disconnecting ...` | `username`, `src_ip`, `port`, `reason` |
| `sshd.max_auth_attempts` | `maximum authentication attempts exceeded for ...` | `username`, `src_ip`, `port` |
| `sshd.auth_failure` | `pam_unix(sshd:auth): authentication failure; ...` | `username`, `src_ip` |
| `sshd.session_opened`, `sshd.session_closed` | `pam_unix(sshd:session): session opened for user ...` | `username`, `state_to` |
| `cron.session_opened`, `cron.session_closed` | The same, from cron | `username`, `state_to` |
| `sudo.command` | `bob : TTY=... ; PWD=... ; USER=root ; COMMAND=...` | `username` |
| `sudo.auth_failure` | The same, with `3 incorrect password attempts` | `username` |
| `sudo.not_in_sudoers` | The same, with `user NOT in sudoers` | `username` |

| Key in `entities.extra` | Meaning |
|---|---|
| `pid` | The process id from the syslog tag, such as the `2417` in `sshd[2417]` |
| `invalid_user` | `true` when the account does not exist on the server |
| `method` | How the login was attempted: `password`, `publickey` |
| `src_host` | The source, when sshd logged a hostname and not an address. `src_ip` is then empty |
| `target_user`, `command`, `tty` | For sudo: who the command ran as, the command, and the terminal |
| `attempts` | For `sudo.auth_failure`: the number of wrong passwords |

A username is whatever the person logging in typed. It can contain spaces or text that imitates the rest of the message, such as `admin from 10.0.0.1 port 22`. The address and port that sshd appends are always at the end of the line, so they are read from the end and the username takes whatever is left.

## DHCP events

Lines from `dhcpd` get the source type `dhcp`. In these events `mac` is the client and `dst_ip` is the address being handed out.

| Event key | Message | Entities |
|---|---|---|
| `dhcp.discover` | `DHCPDISCOVER from <mac> via <interface>` | `mac`, `interface` |
| `dhcp.no_free_leases` | A discover that ends in `no free leases` | `mac`, `interface`, `reason` |
| `dhcp.offer` | `DHCPOFFER on <ip> to <mac> via <interface>` | `dst_ip`, `mac`, `interface` |
| `dhcp.request` | `DHCPREQUEST for <ip> from <mac> via <interface>` | `dst_ip`, `mac`, `interface`, `reason` |
| `dhcp.ack` | `DHCPACK on <ip> to <mac> via <interface>` | `dst_ip`, `mac`, `interface` |
| `dhcp.nak` | `DHCPNAK on <ip> to <mac> via <interface>` | `dst_ip`, `mac`, `interface` |
| `dhcp.release` | `DHCPRELEASE of <ip> from <mac> via <interface>` | `dst_ip`, `mac`, `interface` |
| `dhcp.decline` | `DHCPDECLINE of <ip> from <mac> via <interface>` | `dst_ip`, `mac`, `interface`, `reason` |

| Key in `entities.extra` | Meaning |
|---|---|
| `hostname` | The name the client reported. Chosen by the client, so never trusted |
| `network` | For `dhcp.no_free_leases`: the subnet whose pool is empty |
| `server_id` | For `dhcp.request`: the server the client is answering |
| `relay` | The relay agent's address, when the request did not arrive on a local interface. `interface` is then empty |
| `lease` | For `dhcp.release`: `found` or `not found` |

A line from one of these programs with a message that matches no pattern is still an event with the right source type. It has no event key.

## Firewall events

Cisco ASA messages and Linux iptables (and UFW) packet logs get the source type `firewall`. Every one says what the firewall did in `extra.action`:

| `action` | Meaning |
|---|---|
| `deny` | Refused or dropped |
| `allow` | Let through: an ASA `Built` connection, a permitting access list, an iptables rule whose prefix says ACCEPT or ALLOW |
| `teardown` | A connection that had been let through has ended |
| `log` | Logged by an iptables rule whose prefix does not say what it did |

`src_ip` and `extra.src_port` are who started the connection, `dst_ip` and `port` where it was going, `protocol` is `tcp`, `udp`, `icmp` and so on, and `interface` is where it arrived: an ASA interface name such as `outside`, or a Linux one such as `eth0`.

### Cisco ASA

The event key is `ASA-` and the message number, **without the severity**: `%ASA-4-106023` becomes `ASA-106023`. An ASA administrator can change the level of any message, and a rule should not stop matching when they do. The level is still in `severity`. Firepower Threat Defense (`%FTD-`) uses the same numbers and gets the same keys.

| Event key | Message | Entities |
|---|---|---|
| `ASA-106001` | `Inbound TCP connection denied from <src>/<port> to <dst>/<port> flags <flags> on interface <if>` | `src_ip`, `dst_ip`, `port`, `interface`; `extra.flags` |
| `ASA-106006` | `Deny inbound UDP from <src>/<port> to <dst>/<port> on interface <if>` | as above |
| `ASA-106007` | `Deny inbound UDP from ... due to DNS Response` (or `Query`) | as above, `reason` |
| `ASA-106010` | `Deny inbound <proto> src <if>:<src>/<port> dst <if>:<dst>/<port>` | as above, `extra.dst_interface` |
| `ASA-106014` | `Deny inbound icmp src <if>:<src> dst <if>:<dst> (type n, code n)` | as above, `extra.icmp_type`, `extra.icmp_code` |
| `ASA-106015` | `Deny TCP (no connection) from <src>/<port> to <dst>/<port> flags <flags> on interface <if>` | as above, `reason` |
| `ASA-106021` | `Deny <proto> reverse path check from <src> to <dst> on interface <if>` | as above, `reason` |
| `ASA-106023` | `Deny <proto> src <if>:<src>/<port> dst <if>:<dst>/<port> by access-group "<acl>"` | as above, `extra.acl` |
| `ASA-106100` | `access-list <acl> denied\|permitted <proto> <if>/<src>(<port>) -> <if>/<dst>(<port>) hit-cnt ...` | as above, `extra.acl`; action `deny` or `allow` |
| `ASA-710003` | `<proto> access denied by ACL from <src>/<port> to <if>:<dst>/<service>` (a connection to the firewall itself) | as above; `port` when the service is a number, else `extra.service` |
| `ASA-302013`, `ASA-302015` | `Built inbound\|outbound TCP\|UDP connection <id> for <if>:<addr>/<port> (...) to <if>:<addr>/<port> (...)` | `allow`. For `outbound` the second address started the connection, so the two are swapped. `extra.connection`, `extra.direction` |
| `ASA-302014`, `ASA-302016` | `Teardown TCP\|UDP connection <id> for ... to ... duration <h:mm:ss> bytes <n> <reason>` | `teardown`. The two ends in the order printed: the message does not say which side started it. `extra.duration`, `extra.bytes`, `extra.reason` |
| `ASA-113005`, `ASA-113015` | `AAA user authentication Rejected : reason = ... : server = ...\|local database : user = ... : user IP = ...` | `username`, `src_ip`, `reason`; action `deny` |
| `ASA-605004` | `Login denied from <src>/<port> to <if>:<dst>/<service> for user '<name>'` | `username`, `src_ip`, `dst_ip`, `protocol` (the service); action `deny` |

Any other ASA message keeps its key and severity and is not read further. A listed message that does not look as expected is `partial`.

The formats were checked against Cisco's *ASA Series Syslog Messages* guide and Cisco's published example lines, except 106010 and 106014, whose text in the guide could not be read in full: they follow the guide's partial template and are less certain.

### iptables and UFW

The kernel logs a packet as `<prefix> IN=<if> OUT=<if> MAC=... SRC=... DST=... ... PROTO=TCP SPT=... DPT=...`. The prefix is whatever the rule's author chose, so the action is read from words in it: BLOCK, DROP, DENY, REJECT give `iptables.deny`; ACCEPT, ALLOW, PERMIT give `iptables.allow`; anything else `iptables.log`. UFW writes `[UFW BLOCK]` and `[UFW ALLOW]`. The prefix is kept in `extra.prefix`, `OUT` in `extra.out_interface`. ICMP packets carry `extra.icmp_type` and `extra.icmp_code` instead of ports; an ICMP error quotes the packet it is about in brackets, and only the fields before the bracket are read.

## DNS events

Lines from BIND (`named`) and `dnsmasq` get the source type `dns`.

| Event key | Meaning | Lines |
|---|---|---|
| `dns.query` | A client asked a question | BIND: `client @0x... <ip>#<port> (<name>): query: <name> IN <type> <flags> (<server>)`; dnsmasq: `query[<type>] <name> from <ip>` |
| `dns.reply` | The server answered | dnsmasq: `reply\|cached\|config <name> is <answer>`; BIND 9.20.3 and later with `responselog yes;`: `... response: <name> IN <type> <rcode> ...` |
| `dns.query_failed` | The server could not answer | BIND's query-errors category: `... query failed (<reason>) for <name>/IN/<type> at ...` |
| `dns.forwarded` | The question was passed on | dnsmasq: `forwarded <name> to <server>` |

`src_ip` is the client that asked. `extra.qname` is the name asked for and `extra.qtype` the record type. An answer carries `extra.rcode`: `NOERROR`, `NXDOMAIN` (the name does not exist), `SERVFAIL`, `REFUSED` or `TIMEOUT`; a dnsmasq answer that is an address keeps it in `extra.answer`, and NODATA counts as `NOERROR`.

- dnsmasq names the client on an answer only with `log-queries=extra`, which puts a serial number and `<client>/<port>` at the start of every line. Without it, answers have no `src_ip`.
- dnsmasq logs an error from upstream as `reply error is SERVFAIL`, with the word `error` where the name would be, so such an answer has no `qname`.
- BIND does not log NXDOMAIN at its normal levels before 9.20.3's response log, so NXDOMAIN-based rules need dnsmasq, or BIND 9.20.3 or later.
- BIND's own query log file (`21-Nov-2026 10:00:00.123 queries: info: client ...`) is read too. It has a year but no timezone and no host name.
- Names are chosen by whoever asks, so a name can be any text. It is only stored and shown as text, and template mining masks it like a username.

The formats were checked against BIND's reference manual and source code and dnsmasq's source code. BIND's `response:` line was checked against the source only; no published example was found.

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
| `entities.extra` | `{"seq": "1042"}` | The counter before the device time |

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
| `entities.extra` | `{"pid": "2417", "invalid_user": "true"}` | The syslog tag, and the words "invalid user" |

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
| `entities.protocol` | `dhcp` | The program |
| `entities.reason` | `network 10.20.0.0/24: no free leases` | Message text |
| `entities.extra` | `{"pid": "811", "network": "10.20.0.0/24"}` | The syslog tag and the message text |
