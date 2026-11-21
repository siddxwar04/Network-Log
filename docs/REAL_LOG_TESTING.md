# Real-Log Testing

Until this test, every log the tool had seen came from this project's own generator, written by the same people who wrote the rules. This page records what happened when it read logs it was not built around: what was tested, what it found, what was fixed, and what still fails.

## What was tested

No lab of real router images was available for this test (it needs WSL2 and Docker, which were not installed), so the logs come from two public collections, kept outside the repository:

| Source | Files | Lines | What it is |
|---|---:|---:|---|
| [Loghub](https://github.com/logpai/loghub) `OpenSSH_2k.log` | 1 | 2,000 | Four hours of sshd on an internet-facing server, December. Several real password-guessing attacks |
| Loghub `Linux_2k.log` | 1 | 2,000 | Six weeks of an older Red Hat server: sshd through PAM, ftpd, su, cron, logrotate. Real password-guessing attacks |
| [Elastic integrations](https://github.com/elastic/integrations) test logs, Cisco ASA | 8 | 616 | Lines collected from real ASAs to test another product's parser, many header styles |
| Elastic, Cisco IOS | 12 | 117 | The same for IOS and IOS XE, including lines sent straight from devices |
| Elastic, Linux auth | 7 | 147 | sshd, sudo, PAM and user management from Ubuntu, Debian and RHEL |
| Elastic, Infoblox NIOS | 2 | 119 | DHCP (ISC dhcpd) and DNS (BIND) as an Infoblox appliance writes them |
| Elastic, iptables | 2 | 38 | Linux and Ubiquiti packet logs |
| **Total** | **33** | **5,037** | |

Two things limit what this shows. The Elastic files are separate sample lines, not continuous logs, so they test reading, not detection; nothing in them is an incident. And there are no notes from whoever ran these machines, so what "really happened" was worked out by counting in the raw text by hand, independently of the tool. The year of every file is unknown and was assumed (`--year 2024`).

The real logs hold real public addresses and usernames. None of them is in this repository: below, attackers are named A to H, and every test line made from a real one has its addresses moved into documentation ranges and its names replaced.

## Step 1: what it found, before any change

**Reading.** Of 5,037 lines, the tool read the header (time, device, program) of 90.2% and recognized the message of 27.3%.

| Source | Header read | Message recognized |
|---|---:|---:|
| Cisco ASA | 32.3% | 28.2% |
| Cisco IOS | 41.0% | 36.8% |
| Infoblox DHCP and DNS | 99.2% | 6.7% |
| Older Red Hat (Loghub Linux) | 100% | 0.0% |
| OpenSSH (Loghub) | 100% | 51.1% |
| Linux auth (Elastic) | 97.3% | 70.1% |
| iptables | 92.1% | 68.4% |

**Detection, against what happened.** The brute-force rule's documented threshold is 20 failed logins from one address within 10 minutes. Counting the raw lines by hand:

| File | What happened | Found by the tool | Root cause right | Notes |
|---|---|---|---|---|
| OpenSSH | Attacker A: 286 failed logins in 10 minutes | Yes, Medium | Yes (A) | |
| OpenSSH | Attacker B: 80 in 7 minutes | Yes, Medium | Yes | |
| OpenSSH | Attacker C: 46 over two hours, 30 of them in 83 seconds | Yes, the burst of 30 | Yes | |
| OpenSSH | Attacker D: 26 in one minute | Yes, Medium | Yes | |
| OpenSSH | Attacker E: 20 failures in two minutes, 2 of them `Failed none` | Yes, at exactly 20 | Yes | Borderline, see the proposals |
| OpenSSH | Attacker F: 17 in five minutes | Not reported | | Correct: below the threshold |
| OpenSSH | One successful login, from an address that never failed | Not flagged | | Correct: no attack succeeded |
| Linux | Attacker G: 80 PAM failures in 95 seconds | **Missed** | | Lines not recognized |
| Linux | Attacker H: 23 in two minutes, and a second source with 23 in one minute (named by hostname) | **Missed** | | Lines not recognized |
| Elastic samples | No incidents (separate sample lines) | None | | No false alarms |

No source in the firewall samples tried more than four denied ports, so no port scan was expected and none was reported. There were **no false alarms** in any file, and no split or merged incidents.

## Step 2: the problems, sorted

**Parser gaps** (formats the tool did not read):

1. **ISO 8601 times.** `2026-03-03T02:20:11.123456+00:00 host sshd[...]:` is rsyslog's high-precision file format, the default in recent Debian and Ubuntu releases. Not read at all.
2. **ASA headers with a year.** `Oct 10 2018 12:34:56 host : %ASA-...`, the usual form when an ASA stamps its own time. 272 of 282 lines of one file were unread.
3. **ASA codes with a class.** `%ASA-session-5-106100`, `%ASA-auth-6-113004`.
4. **IOS lines straight from a device** with its hostname (`logging origin-id hostname`), with two counters (`service sequence-numbers`), or with an empty counter (`<189>: Jan  6 ...`).
5. **IOS through a relay that kept the device's name**, which looked like a program called `sw01`.
6. **Facilities with more than one part**: a stack member, `%PIM-SW1-6-...`.
7. **Older Red Hat PAM lines**: `sshd(pam_unix)[4101]: authentication failure; ...`, with the module inside the program name.
8. **PAM failures with no `user=`** (the name tried is not an account) and a trailing space: 105 lines of the OpenSSH file. Also `PAM 4 more authentication failures`.
9. **Infoblox DHCP**: the appliance's address after its name, and extra fields after the interface (`TransID`, `relay`, `lease-duration`, `offered-duration`, `(RENEW)`, `uid`). This includes the **no free leases** message, which the DHCP exhaustion rule depends on.
10. **Infoblox DNS**: the question and the answer in one line (`client ... UDP: query: name IN A response: NXDOMAIN +ED`).

**Detection misses** (lines read, no rule fired): the older Red Hat attacks. Those systems log only PAM's `authentication failure`, never sshd's `Failed password`, and the brute-force rule counts only the second. See the proposals.

**False alarms:** none.

**Correlation errors:** none seen. These logs have no multi-device failures to correlate, so this says little.

## Step 3: what was fixed

Every parser gap above was fixed, each with golden tests made from sanitized copies of the real lines (`backend/tests/golden/real_world.json`, `backend/tests/test_real_log_lines.py`). No rule, threshold or causal prior was changed.

| Fix | File |
|---|---|
| ISO 8601 headers, with or without PRI, zone and fraction (nanoseconds kept to microseconds) | `parsers/syslog.py` |
| A year after the day, which also carries to later lines without one | `parsers/syslog.py` |
| `host : message` (an ASA's space before the colon) | `parsers/syslog.py` |
| An address after the host name (Infoblox), kept as `extra.host_ip` | `parsers/syslog.py` |
| `program(module)[pid]:` tags, the module kept as `extra.module` | `parsers/syslog.py` |
| Hostname and second counter in IOS lines, an empty counter, the device's name taken as the host | `parsers/cisco.py` |
| Multi-part facilities and ASA class names | `parsers/cisco.py`, `parsers/firewall.py` |
| PAM failures in the older form, without `user=`, and `PAM n more` (count in `extra.more`) | `parsers/linux_auth.py` |
| Infoblox DHCP fields | `parsers/dhcp.py` |
| Infoblox DNS question-and-answer lines, read as `dns.reply` | `parsers/dns.py` |

Found on the way, in the synthetic DNS scenario rather than the real logs: BIND's `network unreachable resolving 'name/A/IN': server#53` was left unrecognized, against a test that requires every scenario line to be recognized. It is now `dns.upstream_error`.

## Step 4: after the fixes

| Source | Header read | Message recognized |
|---|---:|---:|
| Cisco ASA | 32.3% → **96.4%** | 28.2% → **92.5%** |
| Cisco IOS | 41.0% → **76.1%** | 36.8% → **74.4%** |
| Infoblox DHCP and DNS | 99.2% → 99.2% | 6.7% → **42.0%** |
| Older Red Hat (Loghub Linux) | 100% → 100% | 0.0% → **24.4%** |
| OpenSSH (Loghub) | 100% → 100% | 51.1% → **57.1%** |
| Linux auth (Elastic) | 97.3% → 99.3% | 70.1% → 71.4% |
| iptables | 92.1% → 97.4% | 68.4% → 73.7% |
| **All 5,037 lines** | 90.2% → **98.9%** | 27.3% → **49.1%** |

Detection is unchanged: the same five attacks found in the OpenSSH file, still no false alarms, and the older Red Hat attacks still missed, because that needs a rule change. The evaluation harness on the synthetic sets gives the same results as before the fixes.

"Recognized" stays below 100% on purpose: most of what is left are messages no rule uses (ftpd connections, `su` sessions, sshd's `Received disconnect`, zone transfers, NetFlow cache warnings).

## What still fails

- **Older Red Hat brute force is not detected.** The lines are now read, but the rule does not count them.
- **Hostnames as attackers.** When sshd logs a hostname instead of an address (`rhost=host.example.net`), it is kept as `extra.src_host`, and the brute-force rule, which groups by address, does not see it.
- **Infoblox DNS failure share.** An Infoblox line is read as an answer, with no separate question, so the DNS failure rule, which divides failed answers by questions, cannot fire on Infoblox logs. The NXDOMAIN burst rule does work.
- **Lines with only an uptime** (`2y10w: %SYS-...`), sent with no collector header, cannot be placed in time and stay unparsed. A collector header fixes this, and the live listener uses the arrival time.
- **Formats not attempted:** IOS XR (`RP/0/RP0/CPU0:...`), NX-OS (`2024 Aug 27 ...`), other vendors' Cisco-like codes (`%SNMP-W-...`), Kiwi Syslog's relay format, `LOCAL4.WARNING:` prefixes, Ubiquiti's `user.info kernel:`, times with offsets such as `UTC+07:30`, and timezone names other than UTC and GMT (`AEST`, `CET`), which fall back to the timezone given with `--timezone`.
- **No real network failures were tested.** Nothing here is a link going down, a routing neighbor lost or a DHCP pool running out on a real device. The incidents that make up most of the tool's purpose are still measured only on synthetic logs. A lab of real router images (prompt 0.4) is the next step.

## Proposed changes, not made

These need a decision, because they change what the rules find and five real files are too few to tune on:

1. **Count PAM failures for brute force, without counting twice.** Add `sshd.auth_failure` to `brute_force_login`, but only from hosts that log no `sshd.failed_password` in the same window, because a modern server logs both lines for every failure. This finds attackers G and H.
2. **Do not count `Failed none`.** An SSH client sends `none` first to ask which methods the server allows; it is not a guess. Attacker E would then have 18 failures and not be reported. Whether that is better is a judgment call: E was guessing.
3. **Group brute force by `extra.src_host` when there is no address**, so that an attacker logged by hostname is counted.
4. **DNS failure share for Infoblox:** let one `dns.reply` count as its own question when no separate query line exists.

## How to repeat this

The logs are public. Download them into a folder outside the repository and run, for each file:

```powershell
.venv\Scripts\netlog analyze C:\netlog-real\raw\loghub\OpenSSH_2k.log --year 2024 --min-severity info --no-llm
```

The report's first section gives the share of lines read and recognized, and the warnings list the most common lines that were not.
