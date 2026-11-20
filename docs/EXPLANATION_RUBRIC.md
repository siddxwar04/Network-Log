# Scoring Explanations by Hand

The evaluation harness measures detection with numbers. Whether an explanation is any good needs a person. This sheet is for scoring 20 explanations, each by three people working separately, so the scores can be compared.

**How to pick the 20.** Two from each tuned scenario that has an incident (01 to 07, 09, 10), plus two from held-out files, one with the junior and one with the senior wording where possible. Note for each whether an LLM or the built-in templates wrote it: the incident page says which.

**How to score.** Open the incident page, read the explanation, and check it against the evidence lines beside it. Score each of the four questions from 1 to 5. Do not discuss scores with the other scorers until all three have finished.

## The four questions

| Score | 1. Correct: is everything it says true? | 2. Complete: does it say what matters? | 3. Actionable: do you know what to do next? | 4. Clear: could the reader follow it? |
|---|---|---|---|---|
| **5** | Every statement is supported by the lines it cites; nothing is overstated | Cause, effects, timing, devices and what the logs cannot tell are all there | Concrete, ordered checks with the commands to run; risky steps marked | Reads easily on the first pass; terms explained for a junior reader |
| **4** | All true; one claim is stronger than the evidence | One minor thing missing (a device, a time) | Clear first steps; one step vague | Clear, with one awkward or jargon-heavy sentence |
| **3** | One statement unsupported, but the main story is right | The main cause is there; effects or limits are missing | You know where to look, not exactly what to check | Understandable after a second read |
| **2** | A wrong statement that could mislead an engineer | The cause or a main effect is missing | Steps are generic ("check the logs", "contact support") | Hard to follow; order or terms confuse |
| **1** | The main cause or a key fact is wrong, or a citation points at an unrelated line | Says little beyond the incident title | No useful next step, or a step that could make things worse without a warning | Cannot be followed |

## The sheet

Scorer: ____________________ Date: ____________

| # | File and incident | Audience | Written by (LLM / built-in) | Correct | Complete | Actionable | Clear | Notes |
|---:|---|---|---|---:|---:|---:|---:|---|
| 1 | | | | | | | | |
| 2 | | | | | | | | |
| 3 | | | | | | | | |
| 4 | | | | | | | | |
| 5 | | | | | | | | |
| 6 | | | | | | | | |
| 7 | | | | | | | | |
| 8 | | | | | | | | |
| 9 | | | | | | | | |
| 10 | | | | | | | | |
| 11 | | | | | | | | |
| 12 | | | | | | | | |
| 13 | | | | | | | | |
| 14 | | | | | | | | |
| 15 | | | | | | | | |
| 16 | | | | | | | | |
| 17 | | | | | | | | |
| 18 | | | | | | | | |
| 19 | | | | | | | | |
| 20 | | | | | | | | |
| | **Average** | | | | | | | |

## Afterwards

- Report the average of each question per scorer and over all scorers, and separately for LLM and built-in explanations.
- Where two scorers differ by 2 or more on the same item, look at it together and write down why. Large disagreement means the scale is unclear, not that one scorer is wrong.
- A score of 1 for Correct is a bug: open an issue with the incident and the statement.
