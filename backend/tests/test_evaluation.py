"""The evaluation harness: the scoring must give a perfect detector 100% and a wrong one a
bad score, the matching rule must do what it says, the held-out variants must be what
they claim, and the API must serve the latest results."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from test_api import build

from eval.harness import (
    Expected,
    Found,
    matches,
    problems,
    run_set,
    score_file,
    summarize,
    to_markdown,
)
from eval.heldout import SEED_BASE, heldout_variants, noise_variants, write_set
from generator.cli import generate
from generator.topology import ATTACKER_IP

SCENARIOS = Path("data/scenarios")


def labelled() -> list[tuple[str, int, list[Expected]]]:
    """Every tuned scenario's expected incidents."""
    out = []
    for path in sorted(SCENARIOS.glob("*.labels.json")):
        labels = json.loads(path.read_text(encoding="utf-8"))
        expected = [Expected.from_label(label) for label in labels["incidents"]]
        out.append((path.name.removesuffix(".labels.json"), labels["total_lines"], expected))
    return out


def perfect(exp: Expected) -> Found:
    """What a detector that is always right would report."""
    return Found(
        id=f"found-{exp.id}", types={exp.type, exp.cause_type}, cause_type=exp.cause_type,
        cause_devices=[exp.device], cause_entity=exp.entity, severity=exp.severity,
        start=exp.start, end=exp.end, lines=set(exp.lines), devices=list(exp.devices),
    )  # fmt: skip


# --- The scoring -----------------------------------------------------------------------------


def test_a_perfect_detector_scores_100_percent():
    results = [score_file(name, lines, exp, [perfect(e) for e in exp])
               for name, lines, exp in labelled()]  # fmt: skip
    summary = summarize(results)
    overall = summary["overall"]
    assert overall["expected"] == overall["found"] == 9
    assert overall["precision"] == overall["recall"] == overall["f1"] == 1.0
    for name in ("root_cause", "severity", "devices"):
        assert summary[name]["rate"] == 1.0
    assert summary["correlation"]["split"] == summary["correlation"]["merged"] == 0
    assert summary["false_alarms_per_10k_lines"] == 0
    assert problems(results, "tuned") == []


def test_a_wrong_detector_scores_badly():
    results = []
    for name, lines, expected in labelled():
        found = []
        for n, exp in enumerate(expected):
            # Right time, wrong device: not a match, and an alarm nobody expected.
            found.append(replace(perfect(exp), id=f"a{n}", cause_devices=["R9"]))
            # Right device and type, but an hour later: not a match either.
            later = replace(perfect(exp), id=f"b{n}", start=exp.start + timedelta(hours=1),
                            end=exp.end + timedelta(hours=1), lines=set())  # fmt: skip
            found.append(later)
        if not expected:  # a quiet file: a made-up alarm
            found.append(Found("noise", {"link_flap"}, "link_flap", ["SW1"], "Gi0/1", "high",
                               *_span(), devices=["SW1"]))  # fmt: skip
        results.append(score_file(name, lines, expected, found))
    overall = summarize(results)["overall"]
    assert overall["found"] == 0 and overall["recall"] == 0.0
    assert overall["precision"] == 0.0 and overall["f1"] == 0.0
    assert overall["false_alarms"] == 2 * 9 + 2  # every wrong report, plus the two made up
    kinds = {item["kind"] for item in problems(results, "tuned")}
    assert kinds == {"miss", "false alarm"}


def _span():
    exp = labelled()[0][2][0]
    return exp.start, exp.end


def test_wrong_severity_cause_and_devices_are_counted_but_still_detected():
    name, lines, (exp,) = next(item for item in labelled() if item[0] == "02_cascade")
    off = replace(perfect(exp), severity="high", cause_entity="Gi0/9", devices=["R1"])
    summary = summarize([score_file(name, lines, [exp], [off])])
    assert summary["overall"]["recall"] == 1.0
    assert summary["severity"]["rate"] == summary["root_cause"]["rate"] == 0.0
    assert summary["devices"]["rate"] == 0.0
    kinds = [p["kind"] for p in problems([score_file(name, lines, [exp], [off])], "tuned")]
    assert kinds == ["wrong cause", "wrong severity", "wrong devices"]


def test_the_matching_rule_allows_ten_seconds_and_no_more():
    exp = labelled()[0][2][0]
    found = perfect(exp)
    assert matches(exp, found)
    assert matches(exp, replace(found, start=exp.end + timedelta(seconds=10),
                                end=exp.end + timedelta(minutes=5)))  # fmt: skip
    assert not matches(exp, replace(found, start=exp.end + timedelta(seconds=11),
                                    end=exp.end + timedelta(minutes=5)))  # fmt: skip
    assert not matches(exp, replace(found, types={"brute_force"}))
    assert not matches(exp, replace(found, cause_devices=["R2"]))


def test_one_incident_found_as_two_is_a_split_and_two_found_as_one_a_merge():
    _name, _lines, (flap, brute) = next(item for item in labelled() if item[0] == "10_overlap")
    halves = sorted(flap.lines)
    first = replace(perfect(flap), id="x", lines=set(halves[: len(halves) // 2]))
    second = replace(perfect(flap), id="y", lines=set(halves[len(halves) // 2 :]))
    split = score_file("split", 1000, [flap, brute], [first, second, perfect(brute)])
    assert [e.id for e in split.split] == [flap.id] and split.false_alarms == []

    both = replace(perfect(flap), id="z", types={"link_flap", "brute_force"},
                   lines=flap.lines | brute.lines)  # fmt: skip
    merged = score_file("merged", 1000, [flap, brute], [both])
    assert [f.id for f in merged.merged] == ["z"] and [e.id for e in merged.missed] == [brute.id]


def test_a_routine_incident_below_medium_is_not_a_false_alarm():
    quiet = Found("c", {"config_change"}, "config_change", ["R1"], "admin", "low", *_span())
    loud = replace(quiet, id="d", severity="medium")
    result = score_file("noise", 10_000, [], [quiet, loud])
    assert [f.id for f in result.false_alarms] == ["d"]
    assert summarize([result])["false_alarms_per_10k_lines"] == 1.0


# --- The held-out set ------------------------------------------------------------------------


def test_the_held_out_set_has_20_variants_per_type_and_never_reuses_the_tuned_seed():
    variants = heldout_variants()
    assert len(variants) == 8 * 20 and len(noise_variants()) == 10
    assert min(v.seed for v in variants) == SEED_BASE > 1
    negatives = [v for v in variants if "nothing" in v.expect]
    assert len(negatives) == 13
    assert {v.scenario for v in negatives} == {"link_flap", "brute_force", "dhcp_exhaustion"}
    assert {v.lines for v in variants} == {2000, 3000, 5000, 8000, 10000}
    assert {v.settings["peers"] for v in variants if v.scenario == "cascade"} == {1, 2, 3}


def test_generator_defaults_still_give_the_tuned_files():
    text, labels = generate("link_flap")
    assert text == (SCENARIOS / "01_link_flap.log").read_text(encoding="utf-8")
    assert "settings" not in labels


def test_variant_settings_change_the_incident_and_its_label():
    _text, labels = generate("cascade", seed=5, lines=1000, settings={"peers": 1})
    (incident,) = labels["incidents"]
    assert incident["devices"] == ["R1", "R2"] and labels["settings"] == {"peers": 1}
    assert incident["title"].endswith("dropped on R2")

    _text, labels = generate("link_flap", seed=5, lines=1000, settings={"cycles": 6},
                             expect={"severity": "medium"})  # fmt: skip
    assert labels["incidents"][0]["expected_severity"] == "medium"
    assert labels["incidents"][0]["facts"] == {"down_transitions": 6}

    text, labels = generate("brute_force", seed=5, lines=1000,
                            settings={"attempts": 12, "minutes": 8, "succeed": False},
                            expect={"nothing": "12 failures, too few"})  # fmt: skip
    assert labels["incidents"] == [] and labels["negative"] == "12 failures, too few"
    attacker = [line for line in text.splitlines() if f"from {ATTACKER_IP} " in line]
    assert sum("Failed password" in line for line in attacker) == 12
    assert not any("Accepted" in line for line in attacker)


def test_the_harness_runs_the_real_tool_on_generated_variants(tmp_path):
    chosen = [v for v in heldout_variants() if v.name in
              ("link_flap-1001", "link_flap-1006", "cascade-1001")]  # fmt: skip
    chosen = [replace(v, lines=1500, hours=3.0) for v in chosen]
    write_set(chosen, tmp_path / "set")
    results = run_set(tmp_path / "set")
    summary = summarize(results)
    # link_flap-1001 has 3 downs, short of the rule's 5: it must give nothing.
    assert summary["overall"]["expected"] == 2 and summary["overall"]["found"] == 2
    assert summary["overall"]["false_alarms"] == 0 and summary["lines_per_second"] > 0
    assert "Matching rule:" in to_markdown({"sets": {"heldout": summary}, "problems": []})


# --- The API ---------------------------------------------------------------------------------


def test_the_api_serves_the_latest_results_or_says_how_to_make_them(tmp_path):
    missing = tmp_path / "none.json"
    with TestClient(build(tmp_path, evaluation_results=str(missing))) as client:
        answer = client.get("/api/evaluation")
        assert answer.status_code == 404 and answer.json()["error"]["code"] == "no_results"
        assert "python -m eval.harness" in answer.json()["error"]["message"]

    results = tmp_path / "latest.json"
    results.write_text(json.dumps({"sets": {"heldout": {"files": 160}}, "problems": []}))
    with TestClient(build(tmp_path, evaluation_results=str(results))) as client:
        assert client.get("/api/evaluation").json()["sets"]["heldout"]["files"] == 160

    results.write_text("not json")
    with TestClient(build(tmp_path, evaluation_results=str(results))) as client:
        assert client.get("/api/evaluation").json()["error"]["code"] == "bad_results"


def test_the_committed_results_are_well_formed():
    data = json.loads(Path("eval/results/latest.json").read_text(encoding="utf-8"))
    assert set(data["sets"]) == {"tuned", "heldout", "noise"}
    assert data["limits"].startswith("These are synthetic logs")
    assert data["sets"]["heldout"]["files"] == 160
