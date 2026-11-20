_These are synthetic logs from this project's own generator, so the numbers show the tool is consistent with its design, not that it works on every real network._

Matching rule: A found incident matches an expected one when it is of the same type (its likely cause, or one of its findings, is of that kind), its likely cause is on the same device, and their time spans overlap (within 10 seconds). Each expected incident matches at most one found incident. An unexpected incident counts as a false alarm at Medium or above.

| Set | Files | Lines | Incidents | Found | False alarms | Precision | Recall | F1 | Root cause | Severity | Devices | Split / merged |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Held-out** | 160 | 894,486 | 167 | 167 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 88.0% | 0 / 0 |
| Tuned | 10 | 94,918 | 9 | 9 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 88.9% | 0 / 0 |
| Noise only | 10 | 143,014 | 0 | 0 | 0 | n/a | n/a | n/a | n/a | n/a | n/a | 0 / 0 |

Held-out, by incident type:

| Type | Incidents | Found | False alarms | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| bgp_session_down | 20 | 20 | 0 | 100.0% | 100.0% | 100.0% |
| brute_force | 55 | 55 | 0 | 100.0% | 100.0% | 100.0% |
| device_reload | 20 | 20 | 0 | 100.0% | 100.0% | 100.0% |
| dhcp_exhaustion | 16 | 16 | 0 | 100.0% | 100.0% | 100.0% |
| link_failure | 20 | 20 | 0 | 100.0% | 100.0% | 100.0% |
| link_flap | 36 | 36 | 0 | 100.0% | 100.0% | 100.0% |

Other measures:

- False alarms on normal traffic: 0.00 per 10,000 lines (143,014 lines).
- Speed: 5,340 to 5,489 lines per second for reading, detection and correlation, by set.
- Compression: 94,918 lines of the tuned set become 299 message patterns, 317 to 1.
- Evidence pack, what an LLM would be shown: median 849 and largest 2931 tokens (estimated) for 9 incidents, against a limit of 3000.
- Explanations (citation validity, fallback rate, tokens and latency of real requests): not measured here, since it needs a real LLM and costs requests.

Where these numbers are weak:

- The held-out files come from the same generator as the tuned ones, with the same message wording. They vary how strong each incident is, how much traffic surrounds it and how many devices it reaches, not how devices word their messages. A perfect score here shows the rules hold across those variations; it says nothing about wording they have not seen. Logs from real devices are the real test.
- The rules and the generator were written from the same understanding of how protocols fail. A shared misunderstanding would not show here.
- Only the incident types the generator can make are measured: the CPU, memory and MAC flapping rules have no scenario yet.
- The devices involved are incomplete in 21 files: 07_device_reload (1), device_reload (20). Without a topology file the tool cannot know which router is cabled to a switch, so the router whose link drops when the switch reloads is left out. Run with --topology data/scenarios/topology.toml to measure it with one.
- Explanations are not measured: that needs a real LLM and costs requests. The manual rubric in docs/EXPLANATION_RUBRIC.md covers their quality.

Every miss, false alarm and wrong cause, severity or device list is in latest.json (21 items).
