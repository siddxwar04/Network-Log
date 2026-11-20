# Log report: 01\_link\_flap.log

## File

| | |
|---|---|
| Lines | 5,000 (100.0% parsed, 100.0% classified) |
| Devices | 8: R1, R2, R3, R4, SW1, SW2, dhcp1, srv1 |
| Time span | 2026-03-03 00:00:03 to 2026-03-03 05:59:58 UTC (5h 59m) |
| Templates | 28 (179 lines per template) |

## Verdict

**1 incident: 1 high (1 finding on 1 device)**

167 routine findings recorded (config changes, interfaces that went down). Use --min-severity info to list them.

## Incidents

### High: Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s

- **When:** 2026-03-03 02:35:21 to 02:38:42 UTC (3m 21s)
- **Devices:** R1
- **Findings:** 1 finding
- **Likely cause:** Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s
- **Confidence:** Medium: it is a single finding on one device; nothing else in these logs confirms or explains it.
- **Severity:** High: the most serious finding is "Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s".

**What happened**

- Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s

  ```text
    2083  Mar  3 02:35:20 R1 64397: Mar  3 02:35:21.630: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
    2091  Mar  3 02:35:41 R1 64401: Mar  3 02:35:42.276: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
    2186  Mar  3 02:38:41 R1 64441: Mar  3 02:38:42.356: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
  ```


**Not known from these logs**

- Why the interface went down. The logs show that it did, not whether a cable, an optic or the device at the other end was at fault.

**Explanation**

*For a senior reader. Written by the built-in templates, not an LLM (no LLM provider is configured).*

Likely root cause: Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s (confidence medium). Severity high.

Timeline:

- 02:35:21 UTC: Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s. *(lines 2083, 2091, 2099)*

Root-cause hypotheses:

1. Likely root cause: Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s. Accounts for 1 of 1 findings; confidence medium. *(lines 2083, 2091, 2099)*

Impact:

- Whatever is connected through this interface was interrupted every time it went down. *(lines 2083, 2091, 2099)*

What to do:

1. Look at the error counters of GigabitEthernet0/2 on R1: rising CRC or input errors point at the cable or the optic.
2. Check that speed and duplex match at both ends.
3. Reseat or replace the cable and the optic, one at a time, and watch whether the flapping stops.
4. **REVIEW BEFORE RUNNING:** Shut the interface if the flapping is disturbing the rest of the network and the link can be spared.

Commands to confirm (read-only):

```text
show interfaces GigabitEthernet0/2
```

Healthy: The interface is up, and the CRC, input error and interface reset counters are not rising.

```text
show logging | include UPDOWN
```

Healthy: No new up and down messages for this interface.

## Most frequent messages

| Count | Message type | Pattern |
|---:|---|---|
| 767 | dhcp.ack | DHCPACK on \<IP\> to \<MAC\> (\<HOST\>) via \<IF\> |
| 455 | dhcp.request | DHCPREQUEST for \<IP\> from \<MAC\> via \<IF\> |
| 389 | sshd.session\_opened | pam\_unix(sshd:session): session opened for user \<USER\>(uid=\<NUM\>) by (uid=\<NUM\>) |
| 374 | sshd.session\_closed | pam\_unix(sshd:session): session closed for user \<USER\> |
| 312 | dhcp.discover | DHCPDISCOVER from \<MAC\> via \<IF\> |
| 312 | dhcp.request | DHCPREQUEST for \<IP\> (\<IP\>) from \<MAC\> via \<IF\> |
| 312 | dhcp.offer | DHCPOFFER on \<IP\> to \<MAC\> via \<IF\> |
| 263 | sshd.accepted | Accepted publickey for \<USER\> from \<IP\> port \<NUM\> ssh2: ED25519 \<KEY\> |
| 201 | cron.session\_opened | pam\_unix(cron:session): session opened for user \<USER\>(uid=\<NUM\>) by (uid=\<NUM\>) |
| 201 | cron.session\_closed | pam\_unix(cron:session): session closed for user \<USER\> |

## Notes

- **Assumption:** The log lines carry no year; 2026 was used, as given.
- **Assumption:** The log lines carry no timezone; UTC was used, as given.
