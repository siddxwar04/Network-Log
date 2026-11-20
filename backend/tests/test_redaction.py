import json
import re
import sqlite3
from pathlib import Path

import pytest

from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.llm.evidence import build_pack, outgoing_pack, outgoing_packs, redact_pack
from netlog.mining.templates import mine_templates
from netlog.redaction.redactor import REMOVED, Redactor, _strings
from netlog.storage.database import _MIGRATIONS, SCHEMA_VERSION, Database

SCENARIOS = Path("data/scenarios")
WITH_INCIDENTS = [
    "01_link_flap",
    "02_cascade",
    "03_config_bgp",
    "04_brute_force",
    "05_dhcp_exhaustion",
    "07_device_reload",
    "10_overlap",
]
TOKEN = re.compile(r"\b(?:IP|USER|HOST|MAC|TEXT)_\d+\b")


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


def analyze(db, name):
    upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)
    mine_templates(db, upload)
    detect(db, upload)
    return upload, correlate(db, upload)


def settings(**redaction):
    config = load_config()
    config["redaction"] = {**config["redaction"], **redaction}
    return config


def appears(value: str, text: str) -> bool:
    """Whether `value` occurs in `text` as a whole word."""
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(value)}(?![A-Za-z0-9_])", text) is not None


def originals(db, upload, incident) -> set[str]:
    """Every address, username, hostname and MAC address that the incident's log lines
    hold, taken from the parsed events and not from the redactor."""
    values = {host for host, _ in db.count_by(upload, "host") if host}
    by_id = {f.id: f for f in db.findings(upload)}
    for finding_id in incident.finding_ids + incident.context_ids:
        for event in db.events_by_id(by_id[finding_id].evidence):
            entities = event.entities
            for value in (
                entities.src_ip,
                entities.dst_ip,
                entities.neighbor_ip,
                entities.username,
                entities.mac,
                entities.extra.get("hostname"),
                entities.extra.get("network", "").split("/")[0],
            ):
                if value:
                    values.add(value)
    return values


# --- Nothing real is left in the pack ----------------------------------------------------


@pytest.mark.parametrize("name", WITH_INCIDENTS)
def test_no_original_value_is_left_anywhere_in_the_pack(analyzed, name):
    db, upload, incidents = analyzed(name)
    packs, redactor = outgoing_packs(db, upload)

    assert len(packs) == len(incidents) > 0
    for incident, pack in packs:
        # Everything in the pack except the fields that hold the tool's own words, such
        # as the severity and the item ids: no log text can get into those.
        text = "\n".join(_strings(pack.data))
        searched = originals(db, upload, incident) | set(redactor.mapping.values())
        assert len(searched) >= 2
        leaked = sorted(value for value in searched if appears(value, text))
        assert leaked == []
        # Addresses and MAC addresses cannot be mistaken for anything else, so for
        # those the whole pack is searched, field names and all.
        whole = pack.to_json()
        shaped = {v for v in searched if re.fullmatch(r"[0-9A-Fa-f:.]{7,}", v)}
        assert [value for value in shaped if value in whole] == []
        assert pack.redacted and not pack.hostnames and not pack.usernames
        assert REMOVED not in whole  # the sample logs hold no secrets


def test_the_story_can_still_be_followed(analyzed):
    db, upload, _ = analyzed("02_cascade")
    ((_, pack),), redactor = outgoing_packs(db, upload)
    data = pack.data

    # What is not sensitive is untouched: the interface, the message codes, the times.
    assert data["root_cause"]["entity"] == "GigabitEthernet0/1"
    assert "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down" in (
        data["evidence"][0]["text"]
    )
    assert "02:46:11.699" in data["evidence"][0]["text"]
    assert data["incident"]["severity"] == "critical"
    assert [f["role"] for f in data["findings"]] == ["root_cause"] + ["problem"] * 12
    # The device that failed is the same token in the headline, the finding and the line.
    r1 = next(token for token, value in redactor.mapping.items() if value == "R1")
    assert r1 in data["root_cause"]["summary"]
    assert data["root_cause"]["devices"] == [r1]
    assert data["findings"][0]["device"] == r1
    assert f" {r1} " in data["evidence"][0]["text"]


def test_the_same_address_gets_the_same_token_wherever_it_appears(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    plain = build_pack(db, upload, incident, None)
    redactor = Redactor()
    sent = redact_pack(plain, redactor)
    token = next(t for t, value in redactor.mapping.items() if value == "10.255.0.1")

    def texts(data):
        found = [item["text"] for item in data["evidence"]]
        found += [item["title"] for item in data["findings"]]
        return found + data["unknowns"]

    places = 0
    for before, after in zip(texts(plain.data), texts(sent.data), strict=True):
        count = len(re.findall(r"(?<![\d.])10\.255\.0\.1(?![\d.])", before))
        assert after.count(token) - after.count(token + "0") == count
        places += count > 0
    assert places >= 4
    # One value, one token; one token, one value.
    values = list(redactor.mapping.values())
    assert len(values) == len(set(values))


def test_tokens_are_the_same_across_the_incidents_of_an_upload(analyzed):
    db, upload, incidents = analyzed("10_overlap")
    packs, redactor = outgoing_packs(db, upload)
    assert len(packs) == 2

    stored = {token: original for token, _, original in db.redaction_map(upload)}
    assert stored == redactor.mapping
    # A redactor loaded later gives a known value the token it already has.
    later = Redactor.load(db, upload)
    for token, original in stored.items():
        assert later.redact_text(f"seen {original} again") == f"seen {token} again"
    # And a new value gets a new number, not a reused one.
    assert later.redact_text("from 198.51.100.200") not in {f"from {t}" for t in stored}


# --- Putting the real values back --------------------------------------------------------


@pytest.mark.parametrize("name", WITH_INCIDENTS)
def test_restoring_the_tokens_gives_back_the_original_pack(analyzed, name):
    db, upload, incidents = analyzed(name)
    redactor = Redactor()
    for incident in incidents:
        plain = build_pack(db, upload, incident)
        sent = redact_pack(plain, redactor)
        data = dict(sent.data)
        legend = data.pop("redaction")
        text = json.dumps(data, ensure_ascii=False, indent=2)

        assert TOKEN.search(text)
        assert redactor.restore(text) == plain.to_json(indent=2)
        assert set(legend["addresses"]) == set(re.findall(r"\bIP_\d+\b", text))


@pytest.mark.parametrize(
    "text",
    [
        "Mar  3 02:46:12 R1 89086: Mar  3 02:46:11.719: Nbr 10.255.0.2 on Gi0/1 from FULL to DOWN",
        "Failed password for invalid user user from 192.0.2.77 port 35569 ssh2",
        "sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/cat /etc/hosts",
        "DHCPACK on 10.20.0.31 to 70:85:c2:23:f3:5a (jdoe-laptop) via eth1",
        "MAC 0011.2233.4455 moved, also seen as 00-11-22-33-44-55 and 00:11:22:33:44:55",
        "route 10.20.0.0/24 via fe80::1, 2001:db8::10 and ::ffff:192.0.2.1",
        "R1 R10 R1.example.net r1 xR1 R1_backup 10.0.0.1 10.0.0.10 110.0.0.1 10.0.0.1.5",
        "copy https://backup@198.51.100.7/cfg?device=R1 startup-config",
        "user called 10 from 10.0.0.1 at 10:10:10 with ab on ab:cd:ef:01:02:03",
        "the log already says IP_1, USER_2 and HOST_3 but not XIP_1 or IP_x",
        "   leading, trailing and  double  spaces  ",
        "",
    ],
)
def test_restore_gives_back_the_text_exactly(text):
    redactor = Redactor()
    redactor.add_known("HOST", ["R1", "R10", "srv1", "jdoe-laptop"])
    redactor.add_known("USER", ["jdoe", "user", "root", "10", "ab"])
    redacted = redactor.redact_text(text)

    assert redactor.restore(redacted) == text
    assert REMOVED not in redacted


def test_text_that_looks_like_a_token_gets_a_token_of_its_own():
    redactor = Redactor()
    redactor.add_known("USER", ["IP_1"])  # an attacker who names himself after our tokens
    text = "Failed password for IP_1 from 192.0.2.77, see E1 and USER_7"
    redacted = redactor.redact_text(text)

    assert "192.0.2.77" not in redacted
    tokens = TOKEN.findall(redacted)
    assert len(tokens) == len(set(tokens)) == 3
    # The real address is never confused with the text that imitated its token.
    address = next(t for t, value in redactor.mapping.items() if value == "192.0.2.77")
    imitation = next(t for t, value in redactor.mapping.items() if value == "IP_1")
    assert address != imitation and imitation != "IP_1"
    assert redactor.restore(redacted) == text


def test_a_token_that_was_never_handed_out_is_left_alone():
    redactor = Redactor()
    redactor.redact_text("from 192.0.2.77")
    assert redactor.restore("IP_1 attacked; IP_99 and USER_5 are unknown") == (
        "192.0.2.77 attacked; IP_99 and USER_5 are unknown"
    )


# --- What is recognized ------------------------------------------------------------------


def test_addresses_and_macs_are_found_by_their_shape():
    redactor = Redactor()
    redacted = redactor.redact_text(
        "10.0.0.1 2001:db8::1 70:85:c2:23:f3:5a 0011.2233.4455 10.20.0.0/24 at 02:46:12"
    )
    assert re.fullmatch(r"IP_1 IP_2 MAC_1 MAC_2 IP_3/24 at 02:46:12", redacted)


def test_things_that_only_look_like_addresses_are_left_alone():
    redactor = Redactor()
    for text in (
        "at 02:46:12 on Mar  3",
        "version 300.1.2.999",
        "release 10.0.0.1.5",
        "seq 89086: 4/0",
        "a::b::c",
    ):
        assert redactor.redact_text(text) == text
    assert redactor.mapping == {}


def test_a_name_inside_a_longer_name_is_not_replaced():
    redactor = Redactor()
    redactor.add_known("HOST", ["R1", "R10", "core"])
    redacted = redactor.redact_text("R1 R10 R100 score core-sw1 core")
    r1, r10, core = (redactor.redact_text(name) for name in ("R1", "R10", "core"))
    assert redacted == f"{r1} {r10} R100 score {core}-sw1 {core}"
    assert len({r1, r10, core}) == 3


def test_a_username_is_replaced_wherever_it_stands_as_a_word():
    redactor = Redactor()
    redactor.add_known("USER", ["jdoe"])
    redacted = redactor.redact_text("jdoe : PWD=/home/jdoe ; COMMAND=/bin/su jdoe2")
    assert redacted == "USER_1 : PWD=/home/USER_1 ; COMMAND=/bin/su jdoe2"


def test_a_username_made_of_digits_does_not_break_an_address():
    redactor = Redactor()
    redactor.add_known("USER", ["10", "ab"])
    redacted = redactor.redact_text("user 10 from 10.0.0.1 on ab:cd:ef:01:02:03 as ab")
    assert redacted == "user USER_1 from IP_1 on MAC_1 as USER_2"


def test_a_username_that_contains_an_address_is_one_value():
    redactor = Redactor()
    odd = "admin from 10.0.0.1 port 22"
    redactor.add_known("USER", [odd])
    redacted = redactor.redact_text(f"Failed password for {odd} from 192.0.2.77 port 4000 ssh2")
    assert redacted == "Failed password for USER_1 from IP_1 port 4000 ssh2"
    assert redactor.mapping == {"USER_1": odd, "IP_1": "192.0.2.77"}


def test_only_private_or_public_is_told_about_an_address():
    redactor = Redactor()
    values = {
        "10.255.0.1": "private",
        "172.16.9.9": "private",
        "192.168.1.1": "private",
        "192.0.2.77": "public",  # a documentation range standing in for the internet
        "203.0.113.1": "public",
        "8.8.8.8": "public",
        "fd00::1": "private",
        "fe80::1": "private",
        "2001:db8::1": "public",
    }
    data = redactor.redact_data({"unknowns": [" ".join(values)]})

    legend = data["redaction"]["addresses"]
    assert list(legend) == [f"IP_{n}" for n in range(1, len(values) + 1)]
    assert list(legend.values()) == list(values.values())
    assert set(legend.values()) == {"private", "public"}
    assert not any(value in json.dumps(data) for value in values)


def test_private_ranges_come_from_the_settings():
    redactor = Redactor(settings(private_networks=["198.51.100.0/24"]))
    data = redactor.redact_data({"unknowns": ["198.51.100.7 and 10.0.0.1"]})
    assert list(data["redaction"]["addresses"].values()) == ["private", "public"]
    with pytest.raises(ValueError, match="private_networks"):
        Redactor(settings(private_networks=["not a network"]))


# --- The structure of the pack survives --------------------------------------------------


def test_names_that_match_the_tools_own_words_cannot_damage_the_structure(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    plain = build_pack(db, upload, incident)
    redactor = Redactor()
    redactor.add_known("USER", ["root", "critical", "high", "problem", "direct", "F1", "E1"])
    redactor.add_known("HOST", ["interface_down", "recovered"])
    sent = redact_pack(plain, redactor).data

    for before, after in zip(plain.data["findings"], sent["findings"], strict=True):
        for key in ("id", "rule", "role", "severity", "start", "evidence"):
            assert after[key] == before[key]
        assert after.get("flags") == before.get("flags")
    assert sent["incident"]["severity"] == "critical"
    assert sent["incident"]["confidence"] == "high"
    assert sent["root_cause"]["kind"] == "interface_down"
    assert sent["root_cause"]["findings"] == plain.data["root_cause"]["findings"]
    assert sent["chain"] == plain.data["chain"] or all(
        a["certainty"] == b["certainty"] and a["links"] == b["links"]
        for a, b in zip(sent["chain"], plain.data["chain"], strict=True)
    )
    assert [t["examples"] for t in sent["templates"]] == [
        t["examples"] for t in plain.data["templates"]
    ]
    assert [e["line"] for e in sent["evidence"]] == [e["line"] for e in plain.data["evidence"]]


def test_values_recorded_by_rules_are_redacted_whatever_their_name(analyzed):
    db, upload, (incident,) = analyzed("04_brute_force")
    packs, redactor = outgoing_packs(db, upload)
    (finding,) = packs[0][1].data["findings"]

    assert redactor.restore(finding["details"]["succeeded_username"]) == "deploy"
    assert finding["details"]["succeeded_username"].startswith("USER_")
    assert redactor.restore(finding["details"]["hosts"][0]) == "srv1"
    assert finding["details"]["count"] == 400


# --- Secrets -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "secret"),
    [
        ("%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:username bob password 0 hunter2",
         "hunter2"),
        ("logged command:username bob privilege 15 secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
         "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0"),
        ("logged command:enable secret Sup3rS3cret", "Sup3rS3cret"),
        ("logged command:enable password 7 094F471A1A0A", "094F471A1A0A"),
        ("logged command:snmp-server community s3cr3tRO RO", "s3cr3tRO"),
        ("snmpd: authentication failure, community string: n0tpublic", "n0tpublic"),
        ("logged command:neighbor 10.0.0.2 password 7 13061E010803", "13061E010803"),
        ("logged command:tacacs-server key 0 T4c4csK3y", "T4c4csK3y"),
        ("logged command:radius-server host 10.1.1.1 key R4diusK3y", "R4diusK3y"),
        ("logged command:key-string 7 0822455D0A16", "0822455D0A16"),
        ("logged command:ip ospf authentication-key Osp4Key", "Osp4Key"),
        ("copy https://backup:pa55w0rd@198.51.100.7/cfg startup-config", "pa55w0rd"),
        ("GET /api/config?token=abc123def456&device=R1", "abc123def456"),
        ("login failed password=hunter2 user=bob", "hunter2"),
        ('api_key: "sk-live-0123456789"', "sk-live-0123456789"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc", "eyJhbGciOiJIUzI1NiJ9.e30.abc"),
        ("-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA7", "MIIEowIBAAKCAQEA7"),
    ],
)
def test_a_secret_is_removed_and_cannot_be_brought_back(line, secret):
    redactor = Redactor()
    redacted = redactor.redact_text(line)

    assert secret not in redacted
    assert REMOVED in redacted
    assert secret not in redactor.restore(redacted)
    # It was removed, not given a token: it is not in the map either.
    assert not any(secret in value for value in redactor.mapping.values())
    # Removing secrets a second time finds nothing more to remove.
    assert Redactor(settings(enabled=False)).redact_text(redacted) == redacted


@pytest.mark.parametrize(
    "line",
    [
        "Failed password for invalid user git from 192.0.2.77 port 35569 ssh2",
        "Accepted password for deploy from 10.10.10.50 port 40263 ssh2",
        "%SYS-5-CONFIG_I: Configured from console by jdoe on vty0 (10.10.10.53)",
        "%BGP-3-NOTIFICATION: sent to neighbor 10.255.0.2 4/0 (hold time expired) 0 bytes",
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 tty=ssh ruser= rhost=h1",
        "sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/cat /etc/hosts",
        "%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Reason: Login Authentication]",
    ],
)
def test_ordinary_lines_lose_nothing_to_secret_removal(line):
    redactor = Redactor(settings(enabled=False))
    assert redactor.redact_text(line) == line


def test_a_secret_in_a_log_line_does_not_reach_the_pack(analyzed):
    db, upload, (incident,) = analyzed("03_config_bgp")
    plain = build_pack(db, upload, incident)
    plain.data["evidence"][0]["text"] += " snmp-server community s3cr3tRO RO"
    plain.data["findings"][0]["details"]["command"] = "username bob password 0 hunter2"

    for config in (None, settings(enabled=False)):
        redactor = Redactor(config)
        text = redact_pack(plain, redactor).to_json()
        assert "s3cr3tRO" not in text and "hunter2" not in text
        assert text.count(REMOVED) == 2
        assert "s3cr3tRO" not in json.dumps(redactor.mapping)


def test_a_bad_secret_pattern_is_reported():
    broken = [{"name": "broken", "pattern": "(unclosed"}]
    with pytest.raises(ValueError, match="broken"):
        Redactor(settings(secrets=broken))
    unnamed = [{"name": "no group", "pattern": r"password \S+"}]
    with pytest.raises(ValueError, match="secret"):
        Redactor(settings(secrets=unnamed))


# --- Switching it off --------------------------------------------------------------------


def test_redaction_is_on_by_default_and_can_be_switched_off(analyzed):
    assert load_config()["redaction"]["enabled"] is True
    db, upload, (incident,) = analyzed("02_cascade")
    plain = build_pack(db, upload, incident)

    config = settings(enabled=False)
    redactor = Redactor(config)
    sent = outgoing_pack(db, upload, incident, redactor, config)
    assert sent.to_json() == plain.to_json()
    assert sent.redacted is False
    assert "redaction" not in sent.data
    assert redactor.mapping == {}
    assert redactor.redact_text("R1 at 10.255.0.1") == "R1 at 10.255.0.1"


# --- The map stays on this machine -------------------------------------------------------


def test_the_map_is_kept_in_the_database_and_not_in_the_pack(analyzed):
    db, upload, _ = analyzed("03_config_bgp")
    packs, redactor = outgoing_packs(db, upload)
    stored = db.redaction_map(upload)

    assert {(token, original) for token, _, original in stored} == set(redactor.mapping.items())
    assert {kind for _, kind, _ in stored} == {"HOST", "IP", "USER"}
    assert ("USER_1", "USER", "jdoe") in stored
    text = "\n".join(_strings(packs[0][1].data))
    for _, _, original in stored:
        assert not appears(original, text)
    assert set(packs[0][1].data["redaction"]) == {"note", "addresses"}

    # Saving again changes nothing, and a token never changes its meaning.
    redactor.save(db, upload)
    db.save_redaction_map(upload, [("USER_1", "USER", "somebody-else")])
    assert db.redaction_map(upload) == stored


def test_the_map_is_deleted_with_its_upload(db):
    upload, _ = analyze(db, "03_config_bgp")
    outgoing_packs(db, upload)
    other, _ = analyze(db, "01_link_flap")
    outgoing_packs(db, other)
    assert db.redaction_map(upload) and db.redaction_map(other)

    db.delete_upload(upload)
    assert db.redaction_map(upload) == []
    assert db.redaction_map(other)


def test_trying_a_pack_on_a_copy_hands_out_no_tokens():
    redactor = Redactor()
    redactor.redact_text("from 10.0.0.1")
    copy = redactor.fork()
    copy.add_known("USER", ["jdoe"])
    assert copy.redact_text("jdoe from 10.0.0.1 and 10.0.0.2") == "USER_1 from IP_1 and IP_2"

    assert redactor.mapping == {"IP_1": "10.0.0.1"}
    assert redactor.redact_text("jdoe from 10.0.0.3") == "jdoe from IP_2"


def test_only_hostnames_and_usernames_can_be_told():
    redactor = Redactor()
    with pytest.raises(ValueError, match="kind"):
        redactor.add_known("SECRET", ["x"])
    redactor.add_known("USER", ["", "   ", None])
    assert redactor.redact_text("nothing to hide") == "nothing to hide"


def test_an_older_database_gains_the_redaction_table(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.executescript("".join(f"BEGIN; {step} COMMIT;" for step in _MIGRATIONS[:5]))
    raw.execute("PRAGMA user_version = 5")
    raw.commit()
    raw.close()

    with Database(path) as database:
        assert database.schema_version == SCHEMA_VERSION >= 6
        upload = database.create_upload("old.log")
        database.save_redaction_map(upload, [("IP_1", "IP", "10.0.0.1")])
        assert database.redaction_map(upload) == [("IP_1", "IP", "10.0.0.1")]
