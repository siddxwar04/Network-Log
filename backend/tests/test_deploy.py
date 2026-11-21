"""The Docker install: settings from environment variables, the files under deploy/, and
the smoke test script run against a real server (Docker itself is not needed here)."""

import importlib.util
import re
import socket
import threading
import time
import tomllib
from pathlib import Path

import pytest
import uvicorn

from netlog.api.app import api_settings, create_app
from netlog.config import load_config
from netlog.llm.settings import llm_settings

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"


def env_lines(path: Path) -> dict[str, str]:
    """NAME=value lines of an environment file, comments left out."""
    found = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, _, value = line.partition("=")
            found[name.strip()] = value.strip()
    return found


# --- Settings from the environment ------------------------------------------------------


def test_environment_sets_numbers_switches_lists_and_text():
    config = load_config(
        environ={
            "NETLOG__LIVE__PORT": "6514",
            "NETLOG__LIVE__UDP": "false",
            "NETLOG__LIVE__ALLOWED_SENDERS": '["10.0.0.1", "10.0.0.2"]',
            "NETLOG__LIVE__TIMEZONE": "+05:30",
            "NETLOG__ALERTS__MIN_SEVERITY": "critical",
            "NETLOG__API__UPLOAD_DIR": "/data/uploads",
        }
    )
    assert config["live"]["port"] == 6514
    assert config["live"]["udp"] is False
    assert config["live"]["allowed_senders"] == ["10.0.0.1", "10.0.0.2"]
    assert config["live"]["timezone"] == "+05:30"
    assert config["alerts"]["min_severity"] == "critical"
    assert config["api"]["upload_dir"] == "/data/uploads"
    # Everything else keeps its default.
    assert config["live"]["tcp"] is True
    assert (
        config["correlation"]["gap_seconds"]
        == load_config(environ={})["correlation"]["gap_seconds"]
    )


def test_environment_names_are_not_case_sensitive_and_reach_nested_tables():
    config = load_config(environ={"netlog__llm__default_models__openai": "some-model"})
    assert config["llm"]["default_models"]["openai"] == "some-model"


def test_an_empty_value_changes_nothing_and_quotes_give_empty_text():
    defaults = load_config(environ={})
    assert load_config(environ={"NETLOG__ALERTS__LINK_BASE": ""}) == defaults
    assert load_config(environ={"NETLOG__LLM__PROVIDER": '""'})["llm"]["provider"] == ""


def test_a_text_setting_keeps_digits_as_text_and_a_decimal_takes_a_whole_number():
    assert load_config(environ={"NETLOG__LLM__MODEL": "4"})["llm"]["model"] == "4"
    config = load_config(environ={"NETLOG__MINING__SIMILARITY_THRESHOLD": "1"})
    assert config["mining"]["similarity_threshold"] == 1


def test_the_environment_wins_over_a_settings_file(tmp_path):
    user = tmp_path / "settings.toml"
    user.write_text("[live]\nport = 7000\nqueue_size = 5\n", encoding="utf-8")
    config = load_config(user, environ={"NETLOG__LIVE__PORT": "8000"})
    assert config["live"]["port"] == 8000
    assert config["live"]["queue_size"] == 5


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("NETLOG__LIVE__PROT", "5514", "does not exist: live.prot"),
        ("NETLOG__NOPE__PORT", "5514", "does not exist: nope"),
        ("NETLOG__LIVE", "1", "must name a section and a setting"),
        ("NETLOG__LIVE____PORT", "1", "must name a section and a setting"),
        ("NETLOG__LLM__DEFAULT_MODELS", "x", "whole section"),
        ("NETLOG__LIVE__PORT", "many", "must be int"),
        ("NETLOG__LIVE__UDP", "1", "must be bool"),
        ("NETLOG__LIVE__ALLOWED_SENDERS", "10.0.0.1", "must be list"),
        ("NETLOG__LIVE__ALLOWED_SENDERS", '["10.0.0.1"', "not a valid value"),
        # The key is never a setting, so it cannot be put in one this way either.
        ("NETLOG__LLM__API_KEY", "sk-test", "does not exist: llm.api_key"),
    ],
)
def test_a_wrong_variable_stops_with_a_message_naming_it(name, value, message):
    with pytest.raises(ValueError, match=re.escape(message)) as problem:
        load_config(environ={name: value})
    assert name in str(problem.value)


def test_other_netlog_variables_are_left_alone():
    defaults = load_config(environ={})
    assert load_config(environ={"NETLOG_LIVE": "1", "NETLOG_DB_PATH": "x.db"}) == defaults


# --- The files under deploy/ -------------------------------------------------------------


def test_every_setting_in_the_env_example_exists_and_shows_its_default():
    defaults = load_config(environ={})
    settings = {k: v for k, v in env_lines(DEPLOY / ".env.example").items() if "__" in k}
    assert len(settings) >= 10
    for name, value in settings.items():
        if not value:
            continue  # empty keeps the default
        path = name.removeprefix("NETLOG__").lower().split("__")
        expected = defaults
        for part in path:
            expected = expected[part]
        assert load_config(environ={name: value}) == defaults, f"{name} differs from default"
        assert expected is not None


def test_every_compose_variable_is_documented_in_the_env_example():
    compose = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
    used = set(re.findall(r"\$\{([A-Z0-9_]+)", compose))
    # Set by the smoke test only, to keep your own .env out of its stack.
    used.discard("NETLOG_COMPOSE_ENV_FILE")
    documented = set(env_lines(DEPLOY / ".env.example"))
    assert used <= documented, f"not in .env.example: {sorted(used - documented)}"
    assert {"NETLOG_LLM_API_KEY", "NETLOG_ALERT_SLACK_URL", "NETLOG_ALERT_WEBHOOK_URL"} <= (
        documented
    )


def test_the_env_example_matches_the_development_one_for_shared_variables():
    """The LLM and alert variables have the same names in both files."""
    develop = env_lines(ROOT / ".env.example")
    deploy = env_lines(DEPLOY / ".env.example")
    for name in ("NETLOG_LLM_PROVIDER", "NETLOG_LLM_MODEL", "NETLOG_LLM_API_KEY"):
        assert name in develop and name in deploy
        assert deploy[name] == ""  # no key, no provider: demo mode


def test_only_the_web_and_syslog_ports_are_published_and_only_on_this_computer_by_default():
    compose = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
    mappings = re.findall(r'^\s+- "(\$\{[^"]+)"$', compose, flags=re.M)
    published = [m for m in mappings if re.search(r":\d+(/udp|/tcp)?$", m)]
    assert len(published) == 3, published
    web = [m for m in published if m.endswith(":8080")]
    syslog = [m for m in published if ":5514/" in m]
    assert len(web) == 1 and len(syslog) == 2
    for mapping in published:
        assert mapping.startswith(
            ("${NETLOG_WEB_BIND:-127.0.0.1}:", "${NETLOG_SYSLOG_BIND:-127.0.0.1}:")
        )
    assert "8000:" not in compose  # the API is reached through the web container only
    defaults = env_lines(DEPLOY / ".env.example")
    assert defaults["NETLOG_WEB_BIND"] == "127.0.0.1"
    assert defaults["NETLOG_SYSLOG_BIND"] == "127.0.0.1"


def test_data_lives_in_a_named_volume_and_containers_run_without_root():
    compose = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
    assert "- data:/data" in compose
    assert re.search(r"^volumes:\n(?:\s*#.*\n)*\s+data:", compose, flags=re.M)
    assert compose.count("read_only: true") == 2
    assert compose.count("cap_drop: [ALL]") == 2
    backend = (DEPLOY / "backend.Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^USER netlog$", backend, flags=re.M)
    assert "NETLOG_DB_PATH=/data/netlog.db" in backend
    assert "HEALTHCHECK" in backend
    frontend = (DEPLOY / "frontend.Dockerfile").read_text(encoding="utf-8")
    assert "nginx-unprivileged" in frontend and "HEALTHCHECK" in frontend
    # Two stages each: the final images start from a clean base.
    assert backend.count("FROM ") == 2 and frontend.count("FROM ") == 2


def test_the_container_settings_name_real_settings():
    backend = (DEPLOY / "backend.Dockerfile").read_text(encoding="utf-8")
    names = dict(re.findall(r"(NETLOG__[A-Z_]+)=(\S+)", backend))
    assert names["NETLOG__LIVE__BIND"] == "0.0.0.0"
    config = load_config(environ=names)
    assert config["api"]["upload_dir"] == "/data/uploads"
    assert config["rules"]["user_file"] == "/data/rules.toml"


def test_the_images_leave_out_secrets_and_local_data():
    for name in ("backend", "frontend"):
        ignore = (DEPLOY / f"{name}.Dockerfile.dockerignore").read_text(encoding="utf-8")
        lines = [x for x in ignore.splitlines() if x and not x.startswith("#")]
        assert lines[0] == "*", "the ignore file lists what is sent, everything else stays out"
        assert not any(".env" in x or x.startswith("!data/uploads") for x in lines)
        assert not any(x.startswith("!docs") for x in lines)


def test_nginx_passes_the_api_on_and_serves_app_addresses():
    nginx = (DEPLOY / "nginx.conf").read_text(encoding="utf-8")
    assert "proxy_pass http://backend:8000;" in nginx
    assert "try_files $uri $uri/ /index.html;" in nginx
    assert "listen 8080;" in nginx
    limit = int(re.search(r"client_max_body_size (\d+)m;", nginx).group(1))
    assert limit >= load_config(environ={})["api"]["max_upload_mb"]


# --- The smoke test script ----------------------------------------------------------------


def smoke_module():
    spec = importlib.util.spec_from_file_location("smoke_test", DEPLOY / "smoke_test.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_smoke_stack_never_uses_your_env_file_or_your_ports():
    smoke = smoke_module()
    env = smoke.compose_env(18080, 15514)
    assert env["NETLOG_COMPOSE_ENV_FILE"] == ".env.example"
    assert env["NETLOG_WEB_BIND"] == env["NETLOG_SYSLOG_BIND"] == "127.0.0.1"
    command = smoke.compose_command("up")
    assert command[command.index("-p") + 1] == "netlog-smoke"
    assert command[command.index("--env-file") + 1].endswith(".env.example")
    assert env_lines(DEPLOY / ".env.example")["NETLOG_LLM_API_KEY"] == ""


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_the_smoke_checks_pass_against_a_real_server(tmp_path, monkeypatch):
    """The same checks the Docker smoke test runs, against the API on a real port with
    the live listener on, so the script cannot drift from the API."""
    syslog_port = free_port()
    monkeypatch.setenv("NETLOG_LIVE", "1")
    config = load_config(
        environ={
            "NETLOG__API__UPLOAD_DIR": str(tmp_path / "uploads"),
            "NETLOG__API__DEMO_DIR": str(ROOT / "data" / "scenarios"),
            "NETLOG__RULES__USER_FILE": str(tmp_path / "rules.toml"),
            "NETLOG__LIVE__PORT": str(syslog_port),
            "NETLOG__LIVE__DETECT_EVERY_SECONDS": "1",
        }
    )
    app = create_app(
        config,
        settings=api_settings(config, tmp_path / "netlog.db"),
        llm=llm_settings(config, environ={}),
    )
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=free_port(), log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started:
            assert time.monotonic() < deadline, "server did not start"
            time.sleep(0.05)
        base = f"http://127.0.0.1:{server.config.port}"
        smoke = smoke_module()
        first = smoke.check_demo(base, timeout=120, expect_demo=True)
        assert first["severity"] in ("critical", "high")
        smoke.check_syslog(base, "127.0.0.1", syslog_port, timeout=20)
        # Through main, as a person would run it against a running server.
        assert smoke.main(["--url", base, "--api-only", "--timeout", "120"]) == 0
    finally:
        server.should_exit = True
        thread.join(timeout=20)


def test_the_smoke_checks_fail_loudly_when_nothing_answers():
    smoke = smoke_module()
    port = free_port()
    with pytest.raises(smoke.SmokeFailure, match="not healthy"):
        smoke.wait_for_health(f"http://127.0.0.1:{port}", timeout=1.5)


def test_demo_dir_default_is_inside_the_image():
    """The image copies data/scenarios to /app/data/scenarios and runs in /app, so the
    default relative paths find the scenarios and the accuracy results."""
    defaults = tomllib.loads(
        (ROOT / "backend" / "netlog" / "config" / "defaults.toml").read_text(encoding="utf-8")
    )
    backend = (DEPLOY / "backend.Dockerfile").read_text(encoding="utf-8")
    assert defaults["api"]["demo_dir"] == "data/scenarios"
    assert "COPY data/scenarios data/scenarios" in backend
    assert f"COPY {defaults['api']['evaluation_results']} " in backend
    assert "WORKDIR /app" in backend
