"""Background noise from the network's edge: the firewall and DNS, on a normal day.

Used only by the noise-only scenario and the scenarios about the edge (the port scan and
the DNS failure), so every other scenario's file stays exactly as it was.

Some of it is deliberately close to an incident without being one:
  - addresses on the internet try one to three ports and are refused (everyday scanning
    noise, not a port scan),
  - clients look up names that do not exist (wpad, printers, typing mistakes) at a normal
    rate, never dozens of different ones at once,
  - the resolver now and then fails to answer for one broken domain.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from generator import messages as m
from generator import topology as topo
from generator.records import Rec, sec

# (kind, relative frequency, lines per group roughly)
_EVENTS = (
    ("asa_deny", 18),
    ("asa_connection", 22),
    ("ufw_block", 6),
    ("server_lookup", 20),
    ("client_lookup", 32),
    ("broken_domain", 1),
)

# Ports the internet tries all day long.
_PROBED_PORTS = (22, 23, 445, 1433, 3389, 5900, 8080, 8443, 2323, 6379)
# Names the documentation ranges allow: example.com, example.net, example.org.
_NAMES = (
    "example.com", "www.example.com", "mail.example.com", "updates.example.net",
    "cdn.example.net", "api.example.org", "time.example.org", "repo.example.net",
    "login.example.com", "static.example.org", "news.example.com", "files.example.net",
)  # fmt: skip
# Names that do not exist, looked up by ordinary clients: proxy discovery, old printers,
# local names asked of the wrong server, typing mistakes.
_MISSING = (
    "wpad.lan", "printer-2f.lan", "nas.lan", "_ldap._tcp.dc._msdcs.lan", "exmaple.com",
    "isatap.lan", "old-fileserver.lan", "www.exampel.org",
)  # fmt: skip
_BROKEN = "legacy.example.net"
_QTYPES = ("A", "A", "A", "AAAA", "AAAA", "HTTPS", "MX")


def _internet_ip(rng: random.Random) -> str:
    """A random address on the internet, from the documentation ranges, never one that a
    scenario uses."""
    while True:
        prefix = rng.choice(("192.0.2", "198.51.100", "203.0.113"))
        ip = f"{prefix}.{rng.randrange(2, 254)}"
        taken = (topo.ATTACKER_IP, topo.SCANNER_IP, topo.FIREWALL_OUTSIDE_IP)
        if ip not in taken and not ip.endswith(".1"):  # .1 are the ISP routers
            return ip


class EdgeNoise:
    def __init__(self, rng: random.Random, start: datetime, end: datetime) -> None:
        self.rng = rng
        self.start = start
        self.end = end
        self.boot = start - timedelta(days=3, hours=rng.uniform(0, 20))
        self.conn = rng.randrange(100000, 900000)
        self.serial = rng.randrange(1000, 5000)
        self.named_pid = rng.randrange(600, 900)
        self.dnsmasq_pid = rng.randrange(400, 600)
        self.clients = [f"10.20.0.{n}" for n in range(topo.DHCP_POOL_FIRST, 200)]

    def generate(self, target_lines: int) -> list[Rec]:
        kinds = [k for k, _ in _EVENTS]
        weights = [w for _, w in _EVENTS]
        span = (self.end - self.start).total_seconds()
        recs: list[Rec] = []
        while len(recs) < target_lines:
            t = self.start + sec(self.rng.uniform(0, span))
            kind = self.rng.choices(kinds, weights)[0]
            group = getattr(self, f"_{kind}")(t)
            for rec in group:
                rec.kind = kind
                rec.group_t = t
            recs.extend(r for r in group if r.t < self.end)
        return recs

    # --- Firewall -----------------------------------------------------------------------

    def _asa_deny(self, t: datetime) -> list[Rec]:
        """An address on the internet tries one to three ports and is refused."""
        rng = self.rng
        src = _internet_ip(rng)
        out = []
        for port in rng.sample(_PROBED_PORTS, rng.randrange(1, 4)):
            sport = rng.randrange(1024, 65000)
            if rng.random() < 0.8:
                body = m.asa_deny_acl("tcp", src, sport, "outside", topo.FIREWALL_OUTSIDE_IP, port)
            else:
                body = m.asa_deny_inbound_tcp(src, sport, topo.FIREWALL_OUTSIDE_IP, port)
            out.append(Rec(t, topo.FIREWALL, body))
            t = t + sec(rng.uniform(0.5, 30))
        return out

    def _asa_connection(self, t: datetime) -> list[Rec]:
        """A client opens a web connection to the internet and closes it later."""
        rng = self.rng
        self.conn += rng.randrange(1, 40)
        local, lport = rng.choice(self.clients), rng.randrange(49152, 65535)
        remote, rport = _internet_ip(rng), rng.choice((443, 443, 443, 80))
        seconds = rng.uniform(0.2, 600)
        duration = f"{int(seconds // 3600)}:{int(seconds % 3600 // 60):02d}:{int(seconds % 60):02d}"
        reason = rng.choice(("TCP FINs", "TCP FINs", "TCP Reset-O", "TCP Reset-I"))
        return [
            Rec(t, topo.FIREWALL, m.asa_built_outbound(
                self.conn, remote, rport, local, lport, topo.FIREWALL_OUTSIDE_IP)),
            Rec(t + sec(seconds), topo.FIREWALL, m.asa_teardown(
                self.conn, remote, rport, local, lport, duration, rng.randrange(400, 900000),
                reason)),
        ]  # fmt: skip

    def _ufw_block(self, t: datetime) -> list[Rec]:
        """srv1's own firewall drops a probe that got past the edge to a closed port."""
        rng = self.rng
        uptime = (t - self.boot).total_seconds()
        src = _internet_ip(rng)
        return [
            Rec(t, topo.SERVER, m.ufw_block(
                uptime, "eth0", src, topo.DMZ_WEB, "TCP", rng.randrange(1024, 65000),
                rng.choice(_PROBED_PORTS), rng.randrange(40, 120), rng.randrange(1, 65535)))
        ]  # fmt: skip

    # --- DNS ----------------------------------------------------------------------------

    def _handle(self) -> str:
        return f"7f{self.rng.randrange(0x10000000, 0xFFFFFFFF):08x}{self.rng.randrange(16):x}0"

    def _server_lookup(self, t: datetime) -> list[Rec]:
        """A server asks the resolver ns1 directly."""
        rng = self.rng
        client = rng.choice(topo.SERVER_LAN_HOSTS)
        return [Rec(t, topo.RESOLVER, m.bind_query(
            self.named_pid, self._handle(), client, rng.randrange(1024, 65000),
            rng.choice(_NAMES), rng.choice(_QTYPES), topo.RESOLVER_IP))]  # fmt: skip

    def _client_lookup(self, t: datetime) -> list[Rec]:
        """A client asks dnsmasq on dhcp1. Most answers come from its cache; the rest are
        forwarded to ns1, which logs the question as coming from dhcp1. About one in
        twelve names does not exist."""
        rng = self.rng
        # dnsmasq numbers queries in the order they arrive: about ten a second at most here.
        serial = self.serial + int((t - self.start).total_seconds() * 10)
        client, cport = rng.choice(self.clients), rng.randrange(1024, 65000)
        missing = rng.random() < 0.08
        name = rng.choice(_MISSING if missing else _NAMES)
        qtype = "A" if missing else rng.choice(_QTYPES)
        pid = self.dnsmasq_pid
        out = [Rec(t, topo.DHCP_SERVER, m.dnsmasq_query(pid, serial, client, cport, qtype, name))]
        answer = "NXDOMAIN" if missing else self._answer(qtype)
        if not missing and rng.random() < 0.55:
            out.append(
                Rec(
                    t + sec(0.001),
                    topo.DHCP_SERVER,
                    m.dnsmasq_reply(pid, serial, client, cport, name, answer, "cached"),
                )
            )
            return out  # fmt: skip
        later = t + sec(rng.uniform(0.002, 0.004))
        reply = later + sec(rng.uniform(0.005, 0.09))
        out += [
            Rec(t + sec(0.001), topo.DHCP_SERVER,
                m.dnsmasq_forwarded(pid, serial, client, cport, name, topo.RESOLVER_IP)),
            Rec(later, topo.RESOLVER, m.bind_query(
                self.named_pid, self._handle(), topo.DHCP1_IP, rng.randrange(1024, 65000),
                name, qtype, topo.RESOLVER_IP)),
            Rec(reply, topo.DHCP_SERVER,
                m.dnsmasq_reply(pid, serial, client, cport, name, answer)),
        ]  # fmt: skip
        return out

    def _answer(self, qtype: str) -> str:
        rng = self.rng
        if qtype == "A":
            return _internet_ip(rng)
        if qtype == "AAAA":
            return rng.choice((f"2001:db8::{rng.randrange(1, 0xFFFF):x}", "NODATA-IPv6"))
        return "<HTTPS>" if qtype == "HTTPS" else "<MX>"

    def _broken_domain(self, t: datetime) -> list[Rec]:
        """A server asks for a name whose own DNS servers are broken: one SERVFAIL."""
        rng = self.rng
        client, cport, handle = (
            rng.choice(topo.SERVER_LAN_HOSTS),
            rng.randrange(1024, 65000),
            self._handle(),
        )  # noqa: E501
        return [
            Rec(t, topo.RESOLVER, m.bind_query(
                self.named_pid, handle, client, cport, _BROKEN, "A", topo.RESOLVER_IP)),
            Rec(t + sec(rng.uniform(1.5, 3)), topo.RESOLVER, m.bind_query_failed(
                self.named_pid, handle, client, cport, _BROKEN, "A", "SERVFAIL")),
        ]  # fmt: skip
