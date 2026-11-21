# Detection Rules

Every rule the tool ships with: what it detects, the log lines it looks for, its thresholds, how serious the result is, what usually causes the problem, and when the rule can be wrong.

Rules are data, not code. They live in `backend/netlog/config/rules.toml`, and the thresholds below are the defaults in that file. To change a threshold, switch a rule off, list your critical devices or add rules of your own without touching that file, see [WRITING_RULES.md](WRITING_RULES.md).

## How a rule works

A rule looks at events of certain types, groups them (for example by device and interface), and produces a **finding** when its condition is met. There are four kinds of rule.

| Kind | Condition | Example |
|---|---|---|
| `threshold` | At least N matching events for one group within a time window, or with `count_distinct`, at least N different values of one field | 5 link-downs on one interface in 5 minutes; 25 different ports from one address in a minute |
| `share` | Matching events make up at least a given share of another kind of event, and number at least N, within a window | 20% of DNS queries failing, at least 20 failures, in 5 minutes |
| `sequence` | One event, then another for the same group within a time limit | A login, then a config change from the same address |
| `absence` | An event that is not followed by its counterpart in time | An interface going down and not coming back within 30 seconds |

One problem gives one finding. An interface that flaps for half an hour is a single finding spanning thirty minutes, and bursts that follow each other within one window are joined.

## Summary

| Rule | Detects | Default trigger | Severity |
|---|---|---|---|
| `link_flap` | An interface bouncing down and up | 5 downs on one interface in 5 minutes | Medium; High at 10 or more |
| `interface_down` | An interface that stayed down | Down for more than 30 seconds | Info |
| `bgp_session_down` | A BGP session dropping | Any drop | Critical |
| `ospf_adjacency_loss` | An OSPF neighbor leaving the FULL state | Any loss | High |
| `dhcp_exhaustion` | A DHCP pool with no addresses left | 10 refusals in 5 minutes | High |
| `config_change` | Someone changing a device's configuration | Any change | Info |
| `brute_force_login` | Password guessing from one address | 20 failed logins in 10 minutes | Medium; Critical if a login then succeeds |
| `cpu_hog` | A process holding the CPU too long | 3 warnings in 5 minutes | High |
| `memory_allocation_failure` | A device running out of memory | Any failure | High |
| `device_reload` | A reload being requested | Any request | High |
| `device_restart` | A device starting up | Any restart | Critical |
| `mac_flapping` | A MAC address moving between ports | 3 warnings in one VLAN in 5 minutes | High |
| `port_scan` | One address trying many ports, refused | 25 different ports in 1 minute | Medium; High if a connection from it is then let through |
| `port_sweep` | One address trying one port on many machines, refused | 20 different addresses in 1 minute | Medium |
| `dns_failure_spike` | A DNS server failing to answer | 20% of queries and at least 20 failures in 5 minutes | Medium; High at half the queries or more |
| `dns_nxdomain_burst` | One machine looking up many names that do not exist | 50 different names in 5 minutes | Medium |

## Severity

Severity is decided by fixed rules. The language model that writes explanations is told the result and never sets or changes it.

Three things decide a finding's level:

1. **The rule's base level**, from the table above.
2. **Conditions that raise it.** A rule can name a flag (a brute force that succeeded) or a strength (a flap far past its threshold). When several hold, the most serious wins.
3. **Critical devices and interfaces.** A finding on a device or interface you have listed as critical is raised one level, never beyond Critical.

**Strength** is a number from 0 to 1 saying how far past its threshold a finding went. A finding exactly at the threshold scores 0.25, and one at four times the threshold or more scores 1.

Every finding carries a one-line reason, for example:

> High: a flapping interface repeatedly interrupts whatever is connected through it; raised from medium because it went down at least twice as often as the threshold; no critical interfaces are configured, so its importance is not known.

### Telling the tool what matters

The tool has no map of your network, so it cannot tell a core uplink from a desk port. Out of the box nothing is treated as critical, and the reason line says so. To change that, list what matters in your settings file:

```toml
[severity]
critical_devices = ["R1"]
critical_interfaces = [{ host = "R1", interface = "GigabitEthernet0/1" }]
```

Interface names must be written in their long form.

---

## Interfaces

### link_flap

**Detects:** an interface that keeps going down and coming back.

| | |
|---|---|
| Log signature | `%LINK-3-UPDOWN: Interface <name>, changed state to down`, repeated |
| Trigger | 5 or more on the same device and interface within 5 minutes |
| Severity | Medium. High when the busiest 5 minutes hold 10 or more |
| Recorded | Number of downs, the busiest window, duration |

**Usual causes:** a damaged or loose cable, a failing optic (SFP), a speed or duplex mismatch, a faulty port, or a device on the other end that keeps restarting.

**What it does not count:**
- An interface shut down on purpose. That logs `%LINK-5-CHANGED ... administratively down`, a different message.
- A single down and up, such as someone unplugging a laptop.

**Can be wrong when:** a port faces a device that is meant to power-cycle often, such as a machine under test.

### interface_down

**Detects:** an interface that went down and stayed down.

| | |
|---|---|
| Log signature | `%LINK-3-UPDOWN ... changed state to down` with no `... changed state to up` for the same interface soon after |
| Trigger | Still down after 30 seconds |
| Severity | Info |
| Recorded | How long it was down; `not_recovered` if it never came back before the log ended |

**Usual causes:** a device switched off or unplugged, a cut cable, a failed optic, or the device on the other end reloading.

**Why it is only Info:** a desk port going down when someone leaves for the day looks exactly like a core link failing. The tool cannot tell them apart without being told, so on its own this stays at the lowest level. It matters in two ways: when you list the interface as critical, and as the **root cause** of other findings. A link failure that takes down OSPF and BGP sessions is connected to them by correlation.

**Can be wrong when:** the "up" message was lost or never logged, which makes an outage look longer than it was.

---

## Routing

### bgp_session_down

**Detects:** a BGP session to a neighbor dropping. Routes learned from that neighbor are withdrawn.

| | |
|---|---|
| Log signature | `%BGP-5-ADJCHANGE: neighbor <address> Down <reason>` |
| Trigger | Any drop. Drops for the same device and neighbor within 10 minutes are one finding |
| Severity | Critical |
| Recorded | The reason; the matching `%BGP-3-NOTIFICATION` with its error code and meaning; `flapping` at 3 or more drops; `recovered` if the session is up again after the last drop |

**Usual causes:**
- **Hold time expired** (notification `4/0`): no keepalive arrived in time. The path to the neighbor is broken or badly congested, the neighbor is overloaded, or something is now blocking TCP port 179.
- **Administrative shutdown or reset** (notification `6/2`, `6/4`): someone did it on purpose, on one side or the other.
- **Interface flap:** the link the session ran over went down.
- **A config change:** a new access list, a changed neighbor setting or a changed AS number.

**Can be wrong when:** the drop was planned maintenance. The tool cannot know that; check for a config change or an admin notification just before.

### ospf_adjacency_loss

**Detects:** an OSPF neighbor leaving the FULL state. Routing inside the network is recalculated.

| | |
|---|---|
| Log signature | `%OSPF-5-ADJCHG: Process <id>, Nbr <router id> on <interface> from FULL to <other state>, <reason>` |
| Trigger | Any loss. Losses for the same device and neighbor within 10 minutes are one finding |
| Severity | High |
| Recorded | The reason, the interface, the new state; `flapping` at 3 or more; `recovered` if FULL again after the last loss |

**Usual causes:**
- **Interface down or detached:** this device's own interface failed, so it drops the neighbor at once.
- **Dead timer expired:** no hello arrived for 40 seconds (by default). The neighbor or the path to it failed while this device's interface stayed up. This is what the far side of a failure reports.
- **Dropping back to EXSTART or INIT:** the two sides lost agreement, often an MTU mismatch or a duplicate router id.

**What it does not count:** a neighbor moving towards FULL, or failing before it ever reached FULL.

**Can be wrong when:** a neighbor is restarted on purpose.

---

## Addressing

### dhcp_exhaustion

**Detects:** a DHCP pool with no addresses left. New devices cannot join the network.

| | |
|---|---|
| Log signature | `DHCPDISCOVER from <mac> via <interface>: network <subnet>: no free leases` |
| Trigger | 10 or more for one server and subnet within 5 minutes |
| Severity | High |
| Recorded | Number of refusals and how many different devices were refused |

**Usual causes:** more devices than the pool has addresses, a lease time so long that addresses of departed devices are not reclaimed, or a device (faulty or malicious) requesting many addresses under different MAC addresses.

**Can be wrong when:** one misbehaving client retries very fast. Check how many different devices were refused; if it is one, the pool is probably fine and the client is the problem.

**Not covered:** servers that do not log "no free leases". A run of requests with no offers is not detected yet.

---

## Changes and people

### config_change

**Detects:** someone changing a device's configuration.

| | |
|---|---|
| Log signature | `%SYS-5-CONFIG_I: Configured from <source> by <user> on <line> (<address>)` |
| Trigger | Any change. Changes by the same user on the same device within 5 minutes are one finding |
| Severity | Info |
| Recorded | Who, from which address, and over which line |

**Why it is recorded:** a configuration change is normal work, not a problem. It matters when something breaks shortly afterwards: it is then the first thing to check, and correlation flags it as a suspect.

### brute_force_login

**Detects:** many failed logins from one address, meaning someone is guessing passwords.

| | |
|---|---|
| Log signature | `sshd: Failed password for <user> from <address> port <port>` on Linux; `%SEC_LOGIN-4-LOGIN_FAILED` on Cisco |
| Trigger | 20 or more from the same address within 10 minutes, across all devices |
| Severity | Medium. Critical when a login from the same address succeeds afterwards |
| Recorded | Number of failures, how many usernames and devices were tried, `password_spraying` at 5 or more usernames, `succeeded` with the account that was entered |

**Usual causes:** automated scanning from the internet against an exposed SSH service, a targeted attack, or a misconfigured script retrying with an old password.

**When a success counts:** only a login after the twentieth failure and within 10 minutes of the last one. A login that succeeded before the guessing was established proves nothing.

**Can be wrong when:**
- A monitoring system or script uses a stale password and retries constantly.
- Many people share one address, such as an office behind NAT, and several mistype on the same morning.

**Not covered:** failures where the source is logged as a hostname, and slow guessing that stays under the threshold.

---

## Device health

### cpu_hog

**Detects:** a process holding the CPU for too long.

| | |
|---|---|
| Log signature | `%SYS-3-CPUHOG: Task is running for (<ms>)msecs ... process = <name>` |
| Trigger | 3 or more on one device within 5 minutes |
| Severity | High |
| Recorded | The process named most often |

**Usual causes:** a routing process working through a very large update, a software defect, a broadcast storm reaching the control plane, or heavy management polling.

**Why it matters:** a device with a starved CPU stops sending hellos and keepalives on time, so its neighbors drop it. Look for OSPF and BGP findings on the same device.

### memory_allocation_failure

**Detects:** a device that could not allocate memory.

| | |
|---|---|
| Log signature | `%SYS-2-MALLOCFAIL: Memory allocation of <bytes> bytes failed from <address>` |
| Trigger | Any failure. Failures on one device within 10 minutes are one finding |
| Severity | High |
| Recorded | The size requested, and the process when the message names it |

**Usual causes:** a memory leak in the software, a routing table too large for the device, or memory fragmented after long uptime.

### device_reload

**Detects:** a reload being requested.

| | |
|---|---|
| Log signature | `%SYS-5-RELOAD: Reload requested by <user> on <line> (<address>). Reload Reason: <reason>` |
| Trigger | Any request |
| Severity | High |
| Recorded | Who asked, from where, and the reason given |

### device_restart

**Detects:** a device starting up.

| | |
|---|---|
| Log signature | `%SYS-5-RESTART: System restarted --` |
| Trigger | Any restart |
| Severity | Critical |
| Recorded | The software version line |

**Reading the two together:** a restart with a `device_reload` finding a few minutes before it was requested by a person. A restart with no request before it means the device crashed or lost power, which is the more serious case.

**Signs in the log around a restart:** the device is silent for some minutes, its message counter starts again from 1, and its first lines carry an unset clock (`*Mar  1 00:00:52`).

**Not covered:** a device that restarts without logging `SYS-5-RESTART`, for example when logging to the collector starts too late in the boot.

### mac_flapping

**Detects:** a MAC address that keeps moving between two ports.

| | |
|---|---|
| Log signature | `%SW_MATM-4-MACFLAP_NOTIF: Host <mac> in vlan <id> is flapping between port <a> and port <b>` |
| Trigger | 3 or more for one switch and VLAN within 5 minutes |
| Severity | High |
| Recorded | How many addresses are affected and the two ports |

**Usual causes:** a switching loop (two links between the same switches with spanning tree not blocking one), a wireless client roaming between access points on different ports, or a duplicate MAC address.

**Can be wrong when:** the address belongs to a wireless client or to a server with a failover pair. One address moving is usually harmless; many addresses moving between the same two ports is a loop.

---

## Firewall

### port_scan

**Detects:** one address trying many different ports and being refused: someone mapping which services are open.

| | |
|---|---|
| Log signature | Denied connections: Cisco ASA `106001`, `106006`, `106007`, `106010`, `106015`, `106021`, `106023`, `106100` (denied), iptables or UFW lines whose prefix says BLOCK, DROP, DENY or REJECT |
| Trigger | 25 or more **different destination ports** from one source address within 1 minute. Retries to the same port count once |
| Severity | Medium. High when a connection from the same address is let through within the next hour (ASA `302013`, `302015`, iptables ALLOW) |
| Recorded | Ports tried, how many machines and firewalls saw it, the protocol and the most-tried address |

**Usual causes:** scanning tools run by attackers, researchers or search engines for exposed devices; your own vulnerability scanner or monitoring.

**Can be wrong when:** a legitimate program opens many connections on different ports (some peer-to-peer and media software, passive FTP through a firewall that does not inspect it). Check who owns the address before acting.

**Not covered:** a slow scan spread over hours (fewer than 25 ports in any one minute), and scans spread across many source addresses. Connections the firewall allowed are only used for the High level, never counted as part of the scan.

### port_sweep

**Detects:** one address trying the same port on many different machines and being refused: someone looking for every host that runs one service.

| | |
|---|---|
| Log signature | The same denied-connection messages as `port_scan` |
| Trigger | 20 or more **different destination addresses** on one port from one source within 1 minute |
| Severity | Medium |
| Recorded | Addresses tried, the firewalls that saw it, the protocol |

**Usual causes:** worms and scanners looking for one exposed service (SMB on 445, RDP on 3389, Telnet on 23).

**Can be wrong when:** a monitoring or inventory system checks one port on every machine, or a misconfigured client tries every address in a range.

Both rules belong to the incident type `port_scan`, so a scan and a sweep from the same address are one incident.

---

## DNS

### dns_failure_spike

**Detects:** a DNS server failing to answer a large share of the questions it is asked, so names stop resolving for everyone who uses it.

| | |
|---|---|
| Log signature | Failures: BIND `query failed (SERVFAIL\|REFUSED\|timed out)` (query-errors category), dnsmasq `reply ... is SERVFAIL\|REFUSED`. Queries: BIND `query:` lines, dnsmasq `query[...]` lines |
| Trigger | On one server within 5 minutes: at least 20 failures, and failures at least 20% of the queries |
| Severity | Medium. High when at least half the queries failed |
| Recorded | Failures, queries in the same stretch, the share, the clients and names affected, the commonest failure code |

A name that does not exist (NXDOMAIN) is an answer, not a failure, and is not counted. When the server does not log its queries, the failures are taken as the whole, which makes the share 100%.

**Usual causes:** the resolver losing its connection to the internet or to the servers it forwards to, a firewall blocking port 53, a broken forwarder setting, or one popular domain whose own servers are down.

**Can be wrong when:** a single client floods the server with questions about one broken name. Check how many different names and clients failed.

**Not covered:** failures that only the clients see (a server that is down logs nothing), and slow answers that do not fail.

### dns_nxdomain_burst

**Detects:** one machine looking up many different names that do not exist, which is how some malware searches for its control server among names it invents. A misconfigured program can do the same.

| | |
|---|---|
| Log signature | dnsmasq `reply <name> is NXDOMAIN` with `log-queries=extra` (which names the client on each answer); BIND 9.20.3 and later with `responselog yes;` |
| Trigger | 50 or more **different names** answered NXDOMAIN to one client within 5 minutes. The same missing name asked again counts once |
| Severity | Medium |
| Recorded | How many different names, and which servers answered |

**Usual causes:** malware using a domain generation algorithm; a program with a wrong search domain trying many combinations; a broken script.

**Can be wrong when:** a security tool or a mail server checks many names on purpose (blocklist lookups).

**Not covered:** BIND before 9.20.3, and dnsmasq without `log-queries=extra`, do not name the client on an answer, so this rule cannot see them.

---

## Known gaps

- **No topology knowledge.** Importance comes only from the critical lists in your settings.
- **One line at a time.** Messages that span several lines are read line by line.
- **Formats checked against generated logs only.** `SYS-3-CPUHOG`, `SYS-2-MALLOCFAIL` and `SW_MATM-4-MACFLAP_NOTIF` have been tested against hand-written examples, not logs from a device.
- **Cisco IOS and ASA, Linux sshd, iptables and UFW, ISC dhcpd, BIND and dnsmasq only.**
- **Firewall and DNS formats checked against vendor documentation and source, not against logs from real devices.** ASA 106010 and 106014 could only be checked against a partial template.
