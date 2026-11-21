from pathlib import Path

import pytest

from eval.scorecard import score_all, to_markdown
from netlog.correlation.topology import load_topology

SCENARIOS = Path("data/scenarios")


@pytest.fixture(scope="module")
def with_topology():
    return score_all(SCENARIOS, load_topology(SCENARIOS / "topology.toml"))


@pytest.fixture(scope="module")
def logs_only():
    return score_all(SCENARIOS)


def test_every_scenario_passes_when_the_topology_is_known(with_topology):
    failed = {check.scenario: check.problems for check in with_topology if not check.passed}

    assert failed == {}
    assert len(with_topology) == 12
    assert "12 of 12 scenarios pass." in to_markdown(with_topology)


def test_from_the_logs_alone_only_the_unseen_cable_is_missed(logs_only):
    failed = {check.scenario: check.problems for check in logs_only if not check.passed}

    # Nothing in the logs says R3 and SW1 are connected, and the tool does not guess.
    assert failed == {"07_device_reload": ["devices SW1, expected SW1, R3"]}
    reload = next(check for check in logs_only if check.scenario == "07_device_reload")
    assert reload.root_cause and reload.severity and reload.start and not reload.devices


def test_scorecard_table(logs_only):
    table = to_markdown(logs_only)

    assert "| 02_cascade | 1 | 1 | yes | yes | yes | yes | pass |" in table
    assert "| 08_noise_50k | 0 | 0 | n/a | n/a | n/a | n/a | pass |" in table
    assert "| 09_prompt_injection | 1 | 1 | yes | yes | yes | yes | pass |" in table
    assert "| 07_device_reload | 1 | 1 | yes | yes | NO | yes | FAIL |" in table
    assert "- 07_device_reload: devices SW1, expected SW1, R3" in table
