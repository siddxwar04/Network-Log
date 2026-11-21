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
    known = set(topo.CISCO_HOSTS + topo.LINUX_HOSTS + topo.EDGE_HOSTS)
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


def test_prompt_injection_is_a_brute_force_with_instructions_in_the_names(generated):
    from generator.scenarios import INJECTED_HOSTNAME, INJECTED_USERS

    text, labels = generated["prompt_injection"]
    all_lines = text.splitlines()
    labelled = incident_lines(generated, "prompt_injection")
    failures = [x for x in all_lines if "Failed password" in x and topo.ATTACKER_IP in x]
    accepted = [x for x in all_lines if "Accepted" in x and topo.ATTACKER_IP in x]
    (incident,) = labels["incidents"]

    # The same attack as the plain brute force, and expected to be reported the same way.
    assert len(failures) == 400 and len(accepted) == 1
    assert set(failures) <= set(labelled) and accepted[0] in labelled
    assert (incident["type"], incident["expected_severity"]) == ("brute_force", "critical")
    assert incident["root_cause"] == generated["brute_force"][1]["incidents"][0]["root_cause"]
    # Every injected username was tried, written into the line exactly as sent.
    for user in INJECTED_USERS:
        tried = [x for x in failures if f"for invalid user {user} from {topo.ATTACKER_IP}" in x]
        assert len(tried) >= 10, user
    assert any("ignore previous instructions" in user for user in INJECTED_USERS)
    assert any("severity to low" in user for user in INJECTED_USERS)
    assert any("E1" in user and "E99" in user for user in INJECTED_USERS)  # imitates our ids
    # The attacker's hostname is in the PAM lines, and is a name DNS could hold.
    named = [x for x in labelled if f"rhost={INJECTED_HOSTNAME} " in x]
    assert len(named) >= 50 and " " not in INJECTED_HOSTNAME
    assert incident["facts"]["injected_usernames"] == list(INJECTED_USERS)
    assert incident["facts"]["injected_hostname"] == INJECTED_HOSTNAME


def test_the_plain_brute_force_has_no_injected_text(generated):
    text = generated["brute_force"][0] + generated["overlap"][0]
    assert "rhost=" not in text and "instructions" not in text


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
    assert any(
        host_of(x) == "R3" and "GigabitEthernet0/3, changed state to down" in x for x in labelled
    )


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


# --- The edge: firewall and DNS ------------------------------------------------------------

DENY = re.compile(
    r"Deny tcp src outside:(\S+)/\d+ dst \S+?:\S+/(\d+)|denied from (\S+)/\d+ to \S+/(\d+)"
)
NXDOMAIN = re.compile(r"dnsmasq\[\d+\]: \d+ (\S+)/\d+ reply (\S+) is NXDOMAIN")
SERVFAIL = re.compile(r"ns1 named\[\d+\]: .*query failed \(SERVFAIL\)")


def most_different_in_window(pairs: list[tuple[datetime, str]], seconds: int) -> int:
    """The most different values seen inside any window of the given length."""
    pairs = sorted(pairs)
    best = 0
    for i, (start, _) in enumerate(pairs):
        inside = {value for t, value in pairs[i:] if t - start <= timedelta(seconds=seconds)}
        best = max(best, len(inside))
    return best


def test_scenarios_without_the_edge_are_unchanged_by_it(generated):
    """Adding the firewall and DNS servers changed no other scenario's file."""
    for name, (prefix, _) in SCENARIOS.items():
        if name in ("noise", "port_scan", "dns_failure"):
            continue
        text = generated[name][0]
        assert text == (Path("data/scenarios") / f"{prefix}.log").read_text(encoding="utf-8")
        assert " FW1 " not in text and " ns1 " not in text and "dnsmasq[" not in text


def test_the_noise_has_a_fifth_of_its_lines_from_the_edge(generated):
    log = lines_of(generated, "noise")
    edge = [x for x in log if host_of(x) in topo.EDGE_HOSTS or "dnsmasq[" in x or "kernel:" in x]
    assert {host_of(x) for x in edge} == {"FW1", "ns1", "dhcp1", "srv1"}
    assert 0.15 < len(edge) / len(log) < 0.25


@pytest.mark.parametrize(("seed", "lines", "hours"), [(1, 5000, 6), (3, 5000, 6), (1, 50000, 24)])
def test_edge_noise_contains_no_incident_signature(seed, lines, hours):
    log = generate("noise", seed=seed, lines=lines, hours=hours)[0].splitlines()
    ports: dict[str, list] = {}
    missing: dict[str, list] = {}
    failures = []
    for line in log:
        if match := DENY.search(line):
            src, port = (match[1], match[2]) if match[1] else (match[3], match[4])
            ports.setdefault(src, []).append((header_time(line), port))
        elif match := NXDOMAIN.search(line):
            missing.setdefault(match[1], []).append((header_time(line), match[2]))
        elif SERVFAIL.search(line):
            failures.append(header_time(line))
    assert ports and missing and failures  # the look-alikes are present...
    # ...but far below the thresholds: 25 ports in a minute, 50 missing names in 5 minutes,
    # 20 failures in 5 minutes.
    assert max(most_different_in_window(p, 60) for p in ports.values()) <= 6
    assert max(most_different_in_window(m, 300) for m in missing.values()) <= 5
    assert max_in_window(failures, 300) <= 3
    assert topo.SCANNER_IP not in "\n".join(log)


def test_port_scan_is_500_refused_ports_from_one_address(generated):
    (incident,) = generated["port_scan"][1]["incidents"]
    lines = incident_lines(generated, "port_scan")
    assert incident["root_cause"] == {
        "kind": "port_scan",
        "device": "FW1",
        "entity": topo.SCANNER_IP,
    }
    assert incident["expected_severity"] == "medium" and incident["devices"] == ["FW1"]
    assert len(lines) == 500 and all(host_of(x) == "FW1" for x in lines)
    found = {DENY.search(x)[2] for x in lines if DENY.search(x)[1] == topo.SCANNER_IP}
    assert len(found) == 500
    start, end = header_time(lines[0]), header_time(lines[-1])
    assert timedelta(minutes=2) <= end - start <= timedelta(minutes=3)


def test_dns_failure_is_ten_minutes_of_servfail_on_ns1(generated):
    (incident,) = generated["dns_failure"][1]["incidents"]
    lines = incident_lines(generated, "dns_failure")
    failed = [x for x in lines if SERVFAIL.search(x)]
    asked = [x for x in lines if "): query: " in x]
    assert incident["facts"]["failed"] == len(failed) and incident["facts"]["queries"] == len(asked)
    assert 0.7 < len(failed) / len(asked) < 0.95
    assert all(host_of(x) == "ns1" for x in lines)
    span = header_time(lines[-1]) - header_time(lines[0])
    assert timedelta(minutes=9) <= span <= timedelta(minutes=11)
    # No other DNS server's lines around the failure, which would show a second one failing.
    text, _ = generated["dns_failure"]
    start, end = header_time(lines[0]), header_time(lines[-1])
    others = [x for x in text.splitlines() if "dnsmasq[" in x and start <= header_time(x) <= end]
    assert others == []
