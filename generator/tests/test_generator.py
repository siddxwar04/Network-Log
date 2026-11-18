import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from generator import topology as topo
from generator.cli import generate
from generator.messages import MONTHS
from generator.scenarios import SCENARIOS

HEADER = re.compile(r"^([A-Z][a-z]{2}) ([ \d]\d) (\d\d):(\d\d):(\d\d) (\S+) ")
LINK_DOWN = re.compile(r"^.{15} (\S+) .*%LINK-3-UPDOWN: Interface (\S+), changed state to down")
FAILED_LOGIN = re.compile(r"Failed password for .* from (\S+) port")
ROUTING_OR_REBOOT = ("ADJCHG", "ADJCHANGE", "BGP-3-NOTIFICATION", "SYS-5-RELOAD", "SYS-5-RESTART")


def header_time(line: str, year: int = 2026) -> datetime:
    mon, day, hh, mm, ss, _ = HEADER.match(line).groups()
    return datetime(year, MONTHS.index(mon) + 1, int(day), int(hh), int(mm), int(ss))


def host_of(line: str) -> str:
    return HEADER.match(line).group(6)


def max_in_window(times: list[datetime], seconds: int) -> int:
    """The largest number of events that fall inside any window of the given length."""
    times = sorted(times)
    best = start = 0
    for end, t in enumerate(times):
        while t - times[start] > timedelta(seconds=seconds):
            start += 1
        best = max(best, end - start + 1)
    return best


@pytest.fixture(scope="module")
def generated():
    return {name: generate(name) for name in SCENARIOS}


def lines_of(generated, name):
    return generated[name][0].splitlines()


def incident_lines(generated, name, index=0):
    text, labels = generated[name]
    lines = text.splitlines()
    return [lines[n - 1] for n in labels["incidents"][index]["lines"]]


# --- Properties every scenario must have -------------------------------------------------


def test_same_seed_gives_identical_output():
    assert generate("cascade", seed=7) == generate("cascade", seed=7)


def test_different_seeds_give_different_output():
    assert generate("cascade", seed=7)[0] != generate("cascade", seed=8)[0]


@pytest.mark.parametrize("name", SCENARIOS)
def test_lines_are_in_timestamp_order(generated, name):
    times = [header_time(line) for line in lines_of(generated, name)]
    assert times == sorted(times)


@pytest.mark.parametrize("name", SCENARIOS)
def test_every_line_has_a_known_host(generated, name):
    known = set(topo.CISCO_HOSTS + topo.LINUX_HOSTS)
    assert {host_of(line) for line in lines_of(generated, name)} <= known


@pytest.mark.parametrize("name", SCENARIOS)
def test_line_count_is_close_to_the_target(generated, name):
    assert 4500 <= generated[name][1]["total_lines"] <= 6000


@pytest.mark.parametrize("name", SCENARIOS)
def test_labels_point_at_lines_of_their_incident(generated, name):
    text, labels = generated[name]
    lines = text.splitlines()
    assert labels["total_lines"] == len(lines)
    for incident in labels["incidents"]:
        start = datetime.fromisoformat(incident["start"].rstrip("Z"))
        end = datetime.fromisoformat(incident["end"].rstrip("Z"))
        assert incident["lines"] == sorted(set(incident["lines"]))
        for number in incident["lines"]:
            line = lines[number - 1]
            assert host_of(line) in incident["devices"]
            # Device clocks are up to 2s off and the collector adds a short delay.
            assert start - timedelta(seconds=4) <= header_time(line) <= end + timedelta(seconds=4)


def test_generator_does_not_import_the_backend():
    imports_backend = re.compile(r"^\s*(from|import)\s+netlog\b", re.MULTILINE)
    for path in Path(__file__).parent.parent.glob("*.py"):
        assert not imports_backend.search(path.read_text(encoding="utf-8")), path.name


# --- Each scenario contains what it claims -----------------------------------------------


def test_link_flap_has_twelve_down_transitions_within_five_minutes(generated):
    downs = [line for line in incident_lines(generated, "link_flap") if LINK_DOWN.match(line)]
    assert len(downs) == 12
    assert all(LINK_DOWN.match(d).groups() == ("R1", topo.SERVER_LAN_IF) for d in downs)
    assert max_in_window([header_time(d) for d in downs], 300) == 12


def test_cascade_starts_at_r1_and_reaches_three_routers(generated):
    lines = incident_lines(generated, "cascade")
    incident = generated["cascade"][1]["incidents"][0]

    assert incident["root_cause"] == {
        "kind": "link_failure",
        "device": "R1",
        "entity": topo.TRANSIT_IF,
    }
    assert host_of(lines[0]) == "R1" and "%LINK-3-UPDOWN" in lines[0] and "to down" in lines[0]
    for peer in ("R2", "R3", "R4"):
        mine = [line for line in lines if host_of(line) == peer]
        assert any("FULL to DOWN, Neighbor Down: Dead timer expired" in line for line in mine)
        assert any("%BGP-5-ADJCHANGE: neighbor 10.255.0.1 Down" in line for line in mine)
        assert any("%BGP-5-ADJCHANGE: neighbor 10.255.0.1 Up" in line for line in mine)
        # Only R1 sees the interface fail; the others see only the effects.
        assert not any("%LINK-3-UPDOWN" in line for line in mine)


def test_cascade_effects_follow_the_cause_in_protocol_order(generated):
    lines = incident_lines(generated, "cascade")
    link_down = header_time(lines[0])
    bgp = [header_time(x) for x in lines if "Down BGP Notification sent" in x]
    ospf = [header_time(x) for x in lines if "Dead timer expired" in x]

    assert all(timedelta(seconds=17) <= t - link_down <= timedelta(seconds=33) for t in bgp)
    assert all(timedelta(seconds=27) <= t - link_down <= timedelta(seconds=43) for t in ospf)


def test_config_change_comes_shortly_before_the_bgp_drop(generated):
    lines = incident_lines(generated, "config_bgp")
    change = next(line for line in lines if "%SYS-5-CONFIG_I" in line)
    drop = next(line for line in lines if "%BGP-5-ADJCHANGE" in line and "Down" in line)

    assert "by jdoe" in change
    assert "neighbor 203.0.113.1 Down" in drop
    assert timedelta(seconds=15) <= header_time(drop) - header_time(change) <= timedelta(seconds=30)


def test_brute_force_has_400_failures_then_a_success(generated):
    all_lines = lines_of(generated, "brute_force")
    labelled = incident_lines(generated, "brute_force")
    failures = [x for x in all_lines if "Failed password" in x and topo.ATTACKER_IP in x]
    accepted = [x for x in all_lines if "Accepted" in x and topo.ATTACKER_IP in x]

    assert len(failures) == 400
    assert len(accepted) == 1
    assert set(failures) <= set(labelled) and accepted[0] in labelled
    assert header_time(accepted[0]) >= max(header_time(f) for f in failures)


def test_dhcp_exhaustion_refuses_new_clients_and_hands_out_nothing(generated):
    text, labels = generated["dhcp_exhaustion"]
    lines = text.splitlines()
    incident = labels["incidents"][0]
    refused = [n for n, line in enumerate(lines, 1) if "no free leases" in line]

    assert refused == incident["lines"]
    assert len(refused) == incident["facts"]["refused_requests"] >= 90
    first, last = header_time(lines[refused[0] - 1]), header_time(lines[refused[-1] - 1])
    offers = [x for x in lines if "DHCPOFFER" in x and first <= header_time(x) <= last]
    assert offers == []


def test_reloading_switch_is_silent_then_boots_with_a_reset_counter(generated):
    lines = lines_of(generated, "device_reload")
    sw1 = [(n, line) for n, line in enumerate(lines) if host_of(line) == "SW1"]
    reload_at = next(i for i, (_, line) in enumerate(sw1) if "%SYS-5-RELOAD" in line)
    _, reload_line = sw1[reload_at]
    _, next_line = sw1[reload_at + 1]

    assert "%SYS-5-RESTART" in next_line
    assert header_time(next_line) - header_time(reload_line) >= timedelta(seconds=175)
    assert next_line.split()[4] == "1:"  # message counter restarted
    assert " *Mar  1 00:00:52" in next_line  # clock not yet synchronized
    labelled = incident_lines(generated, "device_reload")
    assert any(host_of(x) == "R3" and "GigabitEthernet0/3, changed state to down" in x
               for x in labelled)


def test_overlap_has_two_separate_incidents_at_the_same_time(generated):
    first, second = generated["overlap"][1]["incidents"]

    assert (first["type"], second["type"]) == ("link_flap", "brute_force")
    assert set(first["devices"]).isdisjoint(second["devices"])
    assert first["start"] < second["end"] and second["start"] < first["end"]
    flap, brute = incident_lines(generated, "overlap", 0), incident_lines(generated, "overlap", 1)
    assert len([x for x in flap if LINK_DOWN.match(x)]) == 10
    assert len([x for x in brute if "Failed password" in x]) == 300


# --- Noise must never look like an incident ----------------------------------------------


@pytest.mark.parametrize(("seed", "lines", "hours"), [(1, 5000, 6), (2, 5000, 6), (1, 50000, 24)])
def test_noise_contains_no_incident_signature(seed, lines, hours):
    text, labels = generate("noise", seed=seed, lines=lines, hours=hours)
    log = text.splitlines()

    assert labels["incidents"] == []
    assert not any(marker in line for line in log for marker in ROUTING_OR_REBOOT)
    assert not any("no free leases" in line for line in log)

    downs: dict[tuple[str, str], list[datetime]] = {}
    failures: dict[str, list[datetime]] = {}
    for line in log:
        if match := LINK_DOWN.match(line):
            downs.setdefault(match.groups(), []).append(header_time(line))
        elif match := FAILED_LOGIN.search(line):
            failures.setdefault(match.group(1), []).append(header_time(line))

    assert downs and failures  # the look-alikes are present...
    # ...but stay far below the thresholds: 5 downs in 5 minutes, 20 failures in 10 minutes.
    assert max(max_in_window(t, 300) for t in downs.values()) == 1
    assert max(max_in_window(t, 600) for t in failures.values()) <= 6


def test_noise_includes_deliberate_shutdowns_and_short_interface_names():
    text, _ = generate("noise", lines=50000, hours=24)

    assert "administratively down" in text
    assert "%ILPOWER-5-POWER_GRANTED: Interface Gi0/" in text
