# Post-mortem: Interface GigabitEthernet0/1 on R1 was down for 8m 36s

> **Drafted automatically by netlog. Review every statement before filing it.**
> The facts come from deterministic rules applied to the log file; the explanation
> was written by the built-in templates, not an LLM (the LLM was switched off). Line numbers refer to the uploaded
> file 02\_cascade.log.

| | |
|---|---|
| Severity | **Critical**. Critical: the most serious finding is "BGP session from R1 to 10.255.0.2 went down". |
| Started | 2026-03-03 02:46:11 UTC |
| Ended | 2026-03-03 02:46:52 UTC |
| Duration | 41s |
| Devices | R1, R2, R3, R4 |
| Incident | inc-6f861a94c9 |

## Summary

Likely root cause: Interface GigabitEthernet0/1 on R1 was down for 8m 36s (confidence high). Severity critical. BGP session from R1 to 10.255.0.2 went down, with 11 related findings on R1, R2, R3, R4.

## Impact

- Everything that used this interface lost its path until the interface came back. (lines 2260, 2261, 2262, 2263, 2271, 2272, 2273, 2275 and 8 more)
- Direct effect: 3 findings, at once. (lines 2261, 2262, 2263, 2407)
- Plausible effect: 3 findings, 20.3s to 24.1s later. (lines 2271, 2272, 2273, 2413)
- Direct effect: 3 findings, 22.6s to 27.4s later. (lines 2275, 2279, 2281)
- Direct effect: 3 findings, 34.9s to 40.6s later. (lines 2284, 2287, 2288)

## Timeline

All times UTC, from the devices' own clocks.

| Time | Device | What happened | Lines |
|---|---|---|---|
| 02:46:11 | R1 | Interface GigabitEthernet0/1 on R1 was down for 8m 36s | 2260 |
| 02:46:11 | R1 | OSPF adjacency from R1 to 10.255.0.2 was lost | 2261 |
| 02:46:11 | R1 | OSPF adjacency from R1 to 10.255.0.3 was lost | 2262 |
| 02:46:11 | R1 | OSPF adjacency from R1 to 10.255.0.4 was lost | 2263 |
| 02:46:31 | R1 | BGP session from R1 to 10.255.0.2 went down | 2271 |
| 02:46:33 | R1 | BGP session from R1 to 10.255.0.4 went down | 2273 |
| 02:46:34 | R4 | BGP session from R4 to 10.255.0.1 went down | 2275 |
| 02:46:35 | R1 | BGP session from R1 to 10.255.0.3 went down | 2277 |
| 02:46:38 | R2 | BGP session from R2 to 10.255.0.1 went down | 2279 |
| 02:46:39 | R3 | BGP session from R3 to 10.255.0.1 went down | 2281 |
| 02:46:46 | R3 | OSPF adjacency from R3 to 10.255.0.1 was lost | 2284 |
| 02:46:51 | R4 | OSPF adjacency from R4 to 10.255.0.1 was lost | 2288 |
| 02:46:52 | R2 | OSPF adjacency from R2 to 10.255.0.1 was lost | 2287 |
| 02:54:47 | R1 | Recovered: Interface GigabitEthernet0/1 on R1 was down for 8m 36s | 2400 |
| 02:55:28 | R1 | Recovered: OSPF adjacency from R1 to 10.255.0.2 was lost | 2407 |
| 02:55:29 | R1 | Recovered: OSPF adjacency from R1 to 10.255.0.3 was lost | 2409 |
| 02:55:31 | R2 | Recovered: OSPF adjacency from R2 to 10.255.0.1 was lost | 2408 |
| 02:55:32 | R3 | Recovered: OSPF adjacency from R3 to 10.255.0.1 was lost | 2410 |
| 02:55:33 | R1 | Recovered: OSPF adjacency from R1 to 10.255.0.4 was lost | 2411 |
| 02:55:33 | R4 | Recovered: OSPF adjacency from R4 to 10.255.0.1 was lost | 2412 |
| 02:55:43 | R1 | Recovered: BGP session from R1 to 10.255.0.3 went down | 2413 |
| 02:55:45 | R3 | Recovered: BGP session from R3 to 10.255.0.1 went down | 2414 |
| 02:55:51 | R1 | Recovered: BGP session from R1 to 10.255.0.2 went down | 2417 |
| 02:55:53 | R2 | Recovered: BGP session from R2 to 10.255.0.1 went down | 2418 |
| 02:55:58 | R1 | Recovered: BGP session from R1 to 10.255.0.4 went down | 2419 |
| 02:55:58 | R4 | Recovered: BGP session from R4 to 10.255.0.1 went down | 2420 |

## Likely root cause

**Root cause:** Interface GigabitEthernet0/1 on R1 was down for 8m 36s

Confidence: **high**, because every finding is accounted for, the timing matches how the protocols behave, and 4 devices report it. It accounts for 12 of the incident's 12 findings.

- Likely root cause: Interface GigabitEthernet0/1 on R1 was down for 8m 36s. Accounts for 12 of 12 findings; confidence high. (lines 2260, 2261, 2262, 2263, 2271, 2273, 2275, 2279 and 6 more)

## Contributing factors

- OSPF adjacency lost on R1 (3 findings), at once (direct): OSPF runs over that interface, so the router dropped its neighbors there the moment the interface went down.
- BGP session down on R1 (3 findings), +20s to +24s (plausible): BGP between loopback addresses depends on OSPF for the route to its peer; once the OSPF adjacency was lost the BGP session timed out.
- BGP session down on R2, R3, R4, +23s to +27s (direct): BGP keepalives from the device whose interface failed stopped arriving, so its peers closed their sessions when the hold timer ran out.
- OSPF adjacency lost on R2, R3, R4, +35s to +41s (direct): The other routers stopped hearing OSPF hellos from the device whose interface failed, and gave up on it when the 40-second dead timer ran out.

## What was done, and what should be done

Seen in the logs:

- Interface GigabitEthernet0/1 on R1 was down for 8m 36s: recovered at 02:54:47, 8m 36s after it began
- OSPF adjacency from R1 to 10.255.0.2 was lost: recovered at 02:55:28, 9m 17s after it began
- OSPF adjacency from R1 to 10.255.0.3 was lost: recovered at 02:55:29, 9m 18s after it began
- OSPF adjacency from R2 to 10.255.0.1 was lost: recovered at 02:55:31, 8m 39s after it began
- OSPF adjacency from R3 to 10.255.0.1 was lost: recovered at 02:55:32, 8m 46s after it began
- OSPF adjacency from R1 to 10.255.0.4 was lost: recovered at 02:55:33, 9m 21s after it began
- OSPF adjacency from R4 to 10.255.0.1 was lost: recovered at 02:55:33, 8m 42s after it began
- BGP session from R1 to 10.255.0.3 went down: recovered at 02:55:43, 9m 7s after it began
- BGP session from R3 to 10.255.0.1 went down: recovered at 02:55:45, 9m 7s after it began
- BGP session from R1 to 10.255.0.2 went down: recovered at 02:55:51, 9m 19s after it began
- BGP session from R2 to 10.255.0.1 went down: recovered at 02:55:53, 9m 15s after it began
- BGP session from R1 to 10.255.0.4 went down: recovered at 02:55:58, 9m 25s after it began
- BGP session from R4 to 10.255.0.1 went down: recovered at 02:55:58, 9m 24s after it began

Recommended:

1. Look at the status and the error counters of GigabitEthernet0/1 on R1.
2. Inspect the cable and the optic at both ends, and confirm that the device at the other end is powered and its port is not shut.
3. If the port is in the err-disabled state, find out why before bringing it back.
4. **REVIEW BEFORE RUNNING:** Shut and no shut the interface only after the physical checks, and only if it is still down.

To check that it is fixed (these commands only read):

```text
show interfaces GigabitEthernet0/1
```
Healthy: The interface and the line protocol are both up, and the input error and CRC counters are not rising.

```text
show interfaces status err-disabled
```
Healthy: The port is not listed.

## What cannot be determined from these logs

- Why the interface went down. The logs show that it did, not whether a cable, an optic or the device at the other end was at fault.
- Neighbor addresses not matched to a device in these logs: 10.255.0.2, 10.255.0.3, 10.255.0.4. List them in a topology file to say which device each one is.

## Follow-up actions

For the team to fill in: who, and by when.

- [ ] Confirm the root cause with the people who were on call. Owner: ____ Due: ____
- [ ] Decide on a permanent fix, if one is needed. Owner: ____ Due: ____
- [ ] Add monitoring or an alert that would catch this earlier. Owner: ____ Due: ____
- [ ] Share this post-mortem with the team and the people affected. Owner: ____ Due: ____

## Appendix: evidence

The log lines behind this incident, by line number in 02\_cascade.log.

```text
2260  Mar  3 02:46:12 R1 89085: Mar  3 02:46:11.699: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
2261  Mar  3 02:46:12 R1 89086: Mar  3 02:46:11.719: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.2 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Interface down or detached
2262  Mar  3 02:46:12 R1 89087: Mar  3 02:46:11.723: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.3 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Interface down or detached
2263  Mar  3 02:46:12 R1 89088: Mar  3 02:46:11.727: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.4 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Interface down or detached
2271  Mar  3 02:46:33 R1 89090: Mar  3 02:46:31.997: %BGP-5-ADJCHANGE: neighbor 10.255.0.2 Down BGP Notification sent
2272  Mar  3 02:46:33 R1 89091: Mar  3 02:46:32.000: %BGP-3-NOTIFICATION: sent to neighbor 10.255.0.2 4/0 (hold time expired) 0 bytes
2273  Mar  3 02:46:34 R1 89092: Mar  3 02:46:33.833: %BGP-5-ADJCHANGE: neighbor 10.255.0.4 Down BGP Notification sent
2274  Mar  3 02:46:34 R1 89093: Mar  3 02:46:33.836: %BGP-3-NOTIFICATION: sent to neighbor 10.255.0.4 4/0 (hold time expired) 0 bytes
2275  Mar  3 02:46:35 R4 51513: Mar  3 02:46:34.266: %BGP-5-ADJCHANGE: neighbor 10.255.0.1 Down BGP Notification sent
2276  Mar  3 02:46:35 R4 51514: Mar  3 02:46:34.269: %BGP-3-NOTIFICATION: sent to neighbor 10.255.0.1 4/0 (hold time expired) 0 bytes
2277  Mar  3 02:46:36 R1 89094: Mar  3 02:46:35.815: %BGP-5-ADJCHANGE: neighbor 10.255.0.3 Down BGP Notification sent
2278  Mar  3 02:46:36 R1 89095: Mar  3 02:46:35.818: %BGP-3-NOTIFICATION: sent to neighbor 10.255.0.3 4/0 (hold time expired) 0 bytes
2279  Mar  3 02:46:37 R2 22750: Mar  3 02:46:38.988: %BGP-5-ADJCHANGE: neighbor 10.255.0.1 Down BGP Notification sent
2280  Mar  3 02:46:37 R2 22751: Mar  3 02:46:38.991: %BGP-3-NOTIFICATION: sent to neighbor 10.255.0.1 4/0 (hold time expired) 0 bytes
2281  Mar  3 02:46:37 R3 64326: Mar  3 02:46:39.119: %BGP-5-ADJCHANGE: neighbor 10.255.0.1 Down BGP Notification sent
2282  Mar  3 02:46:37 R3 64327: Mar  3 02:46:39.122: %BGP-3-NOTIFICATION: sent to neighbor 10.255.0.1 4/0 (hold time expired) 0 bytes
2284  Mar  3 02:46:45 R3 64328: Mar  3 02:46:46.555: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Dead timer expired
2287  Mar  3 02:46:51 R2 22752: Mar  3 02:46:52.302: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Dead timer expired
2288  Mar  3 02:46:52 R4 51515: Mar  3 02:46:51.316: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Dead timer expired
2400  Mar  3 02:54:48 R1 89100: Mar  3 02:54:47.374: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
2407  Mar  3 02:55:29 R1 89102: Mar  3 02:55:28.679: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.2 on GigabitEthernet0/1 from LOADING to FULL, Loading Done
2408  Mar  3 02:55:30 R2 22753: Mar  3 02:55:31.267: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1 on GigabitEthernet0/1 from LOADING to FULL, Loading Done
2409  Mar  3 02:55:30 R1 89103: Mar  3 02:55:29.495: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.3 on GigabitEthernet0/1 from LOADING to FULL, Loading Done
2410  Mar  3 02:55:30 R3 64329: Mar  3 02:55:32.063: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1 on GigabitEthernet0/1 from LOADING to FULL, Loading Done
2411  Mar  3 02:55:34 R1 89104: Mar  3 02:55:33.019: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.4 on GigabitEthernet0/1 from LOADING to FULL, Loading Done
2412  Mar  3 02:55:34 R4 51517: Mar  3 02:55:33.251: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.1 on GigabitEthernet0/1 from LOADING to FULL, Loading Done
2413  Mar  3 02:55:44 R1 89105: Mar  3 02:55:43.220: %BGP-5-ADJCHANGE: neighbor 10.255.0.3 Up
2414  Mar  3 02:55:44 R3 64330: Mar  3 02:55:45.688: %BGP-5-ADJCHANGE: neighbor 10.255.0.1 Up
2417  Mar  3 02:55:52 R1 89107: Mar  3 02:55:51.336: %BGP-5-ADJCHANGE: neighbor 10.255.0.2 Up
2418  Mar  3 02:55:52 R2 22754: Mar  3 02:55:53.824: %BGP-5-ADJCHANGE: neighbor 10.255.0.1 Up
2419  Mar  3 02:55:59 R1 89108: Mar  3 02:55:58.378: %BGP-5-ADJCHANGE: neighbor 10.255.0.4 Up
2420  Mar  3 02:55:59 R4 51518: Mar  3 02:55:58.510: %BGP-5-ADJCHANGE: neighbor 10.255.0.1 Up
```

