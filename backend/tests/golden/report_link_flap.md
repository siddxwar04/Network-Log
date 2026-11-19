# Log report: 01\_link\_flap.log

## File

| | |
|---|---|
| Lines | 5,000 (100.0% parsed, 100.0% classified) |
| Devices | 8: R1, R2, R3, R4, SW1, SW2, dhcp1, srv1 |
| Time span | 2026-03-03 00:00:03 to 2026-03-03 05:59:58 UTC (5h 59m) |
| Templates | 28 (179 lines per template) |

## Verdict

**1 finding: 1 high**

167 lower-severity findings not shown (routine events such as config changes); use --min-severity info to list them.

## Findings

### High: Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s

- **When:** 2026-03-03 02:35:21 to 02:38:42 UTC (3m 21s)
- **Why this severity:** High: a flapping interface repeatedly interrupts whatever is connected through it; raised from medium because it went down at least twice as often as the threshold; no critical interfaces are configured, so its importance is not known.
- **Evidence:** 12 line(s), 5 shown

```text
  2083  Mar  3 02:35:20 R1 64397: Mar  3 02:35:21.630: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
  2091  Mar  3 02:35:41 R1 64401: Mar  3 02:35:42.276: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
  2099  Mar  3 02:35:55 R1 64405: Mar  3 02:35:56.626: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
  2173  Mar  3 02:38:22 R1 64437: Mar  3 02:38:24.132: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
  2186  Mar  3 02:38:41 R1 64441: Mar  3 02:38:42.356: %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down
```

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
