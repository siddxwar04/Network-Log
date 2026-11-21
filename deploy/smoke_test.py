"""Smoke test for the Docker install.

Starts the whole stack under a project name of its own (netlog-smoke) on spare ports, waits
until Compose reports it healthy, loads a demo scenario through the API, checks that an
incident comes back, sends one syslog message over UDP and one over TCP and checks that the
listener counted them, then removes the stack and its volume. Your own install, its data
and your .env are never touched: the smoke stack reads .env.example, so it runs in demo
mode with no LLM key.

    python deploy/smoke_test.py               build, start, check, remove
    python deploy/smoke_test.py --keep        leave the smoke stack running afterwards
    python deploy/smoke_test.py --url http://127.0.0.1:8000 --api-only
                                              check a server that is already running

Standard library only, so it runs with any Python 3.11 or newer, without the project
installed. Exit status 0 means every check passed.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent
PROJECT = "netlog-smoke"
SCENARIO = "02_cascade"
WEB_PORT = 18080
SYSLOG_PORT = 15514


class SmokeFailure(Exception):
    pass


def say(text: str) -> None:
    print(text, flush=True)


def request(method: str, url: str, timeout: float = 10) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method=method, headers={"Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def get_json(url: str, method: str = "GET", expect: int = 200) -> dict:
    status, body = request(method, url)
    if status != expect:
        raise SmokeFailure(f"{method} {url} answered {status}, expected {expect}: {body[:300]!r}")
    return json.loads(body)


def wait_for_health(base: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    problem = "no answer"
    while time.monotonic() < deadline:
        try:
            status, body = request("GET", f"{base}/api/health", timeout=5)
            if status == 200:
                return json.loads(body)
            problem = f"status {status}"
        except (OSError, ValueError) as error:
            problem = str(error)
        time.sleep(1)
    raise SmokeFailure(f"{base}/api/health not healthy after {timeout:.0f} s: {problem}")


def check_pages(base: str) -> None:
    """The web container serves the app, and any app address (a deep link) gets it too."""
    for path in ("/", "/uploads/1/incidents/1"):
        status, body = request("GET", base + path)
        if status != 200 or b'id="root"' not in body:
            raise SmokeFailure(f"GET {path} did not return the app page (status {status})")
    say("  ok  web pages served, deep links included")


def check_demo(base: str, timeout: float, expect_demo: bool) -> dict:
    """Load a demo scenario through the API and wait for an incident."""
    health = wait_for_health(base, 30)
    if health.get("status") != "ok":
        raise SmokeFailure(f"health says {health.get('status')!r}")
    if expect_demo and not health["demo"]["active"]:
        raise SmokeFailure("expected demo mode (no LLM configured), but an LLM is configured")
    say(f"  ok  API healthy, version {health['version']}, demo mode {health['demo']['active']}")

    names = [s["name"] for s in get_json(f"{base}/api/demo/scenarios")["items"]]
    if SCENARIO not in names:
        raise SmokeFailure(f"demo scenario {SCENARIO} missing; found {names}")
    say(f"  ok  {len(names)} demo scenarios available")

    upload = get_json(f"{base}/api/demo/scenarios/{SCENARIO}", method="POST", expect=202)
    upload_id = upload["id"]
    deadline = time.monotonic() + timeout
    while True:
        status = get_json(f"{base}/api/uploads/{upload_id}/status")
        if status["finished"]:
            break
        if time.monotonic() > deadline:
            raise SmokeFailure(f"upload {upload_id} still at stage {status['stage']!r}")
        time.sleep(0.5)
    if status["status"] != "done":
        raise SmokeFailure(f"pipeline failed at {status['failed_stage']}: {status['error']}")
    say(f"  ok  {SCENARIO} loaded as upload {upload_id} and processed")

    incidents = get_json(f"{base}/api/uploads/{upload_id}/incidents")
    if incidents["total"] < 1:
        raise SmokeFailure(f"no incident found in {SCENARIO}")
    first = incidents["items"][0]
    say(f"  ok  {incidents['total']} incident(s); first: [{first['severity']}] {first['headline']}")
    return first


def check_syslog(base: str, host: str, port: int, timeout: float = 30) -> None:
    """One message over UDP and one over TCP reach the listener and are counted."""
    before = get_json(f"{base}/api/live")
    if not before.get("enabled"):
        raise SmokeFailure("the live listener is not running")
    received = before["counters"]["received"]
    now = datetime.now(UTC)
    stamp = f"{now:%b} {now.day:>2} {now:%H:%M:%S}"
    line = f"<189>{stamp} SMOKE-R1 %SYS-5-CONFIG_I: Configured from console by smoke on vty0"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.sendto(line.encode(), (host, port))
    with socket.create_connection((host, port), timeout=5) as tcp:
        tcp.sendall((line + "\n").encode())
    deadline = time.monotonic() + timeout
    while True:
        counters = get_json(f"{base}/api/live")["counters"]
        if counters["received"] >= received + 2:
            break
        if time.monotonic() > deadline:
            raise SmokeFailure(f"listener counted {counters['received'] - received} of 2 messages")
        time.sleep(0.5)
    say(f"  ok  syslog port {port} received one message over UDP and one over TCP")


def compose_command(*args: str) -> list[str]:
    return [
        "docker", "compose",
        "--project-directory", str(DEPLOY),
        "-f", str(DEPLOY / "compose.yaml"),
        "-p", PROJECT,
        "--env-file", str(DEPLOY / ".env.example"),
        *args,
    ]  # fmt: skip


def compose_env(web_port: int, syslog_port: int) -> dict[str, str]:
    """The environment for Compose: spare ports on this computer only, the listener on,
    and .env.example (no key, every default) in place of your .env."""
    env = dict(os.environ)
    env.update(
        NETLOG_WEB_BIND="127.0.0.1",
        NETLOG_WEB_PORT=str(web_port),
        NETLOG_SYSLOG_BIND="127.0.0.1",
        NETLOG_SYSLOG_PORT=str(syslog_port),
        NETLOG_LIVE="1",
        NETLOG_COMPOSE_ENV_FILE=".env.example",
    )
    return env


def run_compose(args: argparse.Namespace) -> int:
    env = compose_env(args.web_port, args.syslog_port)
    base = f"http://127.0.0.1:{args.web_port}"
    started = time.monotonic()
    try:
        say(f"Building and starting the {PROJECT} stack (the first build takes a few minutes)")
        subprocess.run(
            compose_command("up", "-d", "--build", "--wait", "--wait-timeout", str(args.timeout)),
            env=env,
            check=True,
        )
        say(f"  ok  stack healthy after {time.monotonic() - started:.0f} s")
        check_pages(base)
        check_demo(base, args.timeout, expect_demo=True)
        check_syslog(base, "127.0.0.1", args.syslog_port)
    except (SmokeFailure, subprocess.CalledProcessError, OSError) as problem:
        say(f"FAILED: {problem}")
        subprocess.run(compose_command("ps", "-a"), env=env, check=False)
        subprocess.run(compose_command("logs", "--tail", "60"), env=env, check=False)
        return 1
    finally:
        if args.keep:
            say(f"Left running at {base}. Remove it with:")
            say("  " + " ".join(compose_command("down", "-v")))
        else:
            subprocess.run(compose_command("down", "-v", "--remove-orphans"), env=env, check=False)
    say(f"PASSED in {time.monotonic() - started:.0f} s")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--keep", action="store_true", help="leave the smoke stack running")
    parser.add_argument("--timeout", type=int, default=180, help="seconds to wait at each step")
    parser.add_argument("--web-port", type=int, default=WEB_PORT)
    parser.add_argument("--syslog-port", type=int, default=SYSLOG_PORT)
    parser.add_argument("--url", help="check a server already running here; Docker is not used")
    parser.add_argument(
        "--api-only", action="store_true", help="with --url: the API alone, no pages or syslog"
    )
    args = parser.parse_args(argv)

    if not args.url:
        return run_compose(args)
    try:
        if not args.api_only:
            check_pages(args.url)
        check_demo(args.url, args.timeout, expect_demo=False)
        if not args.api_only:
            check_syslog(args.url, "127.0.0.1", args.syslog_port)
    except (SmokeFailure, OSError) as problem:
        say(f"FAILED: {problem}")
        return 1
    say("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
