"""Background noise: what the network logs on a normal day with nothing wrong.

Some of it is deliberately close to an incident without being one, so detection rules
are tested against look-alikes:
  - a single port going down and up (someone unplugging a laptop) is not a link flap,
  - an administrator shutting a port on purpose is not a fault,
  - one mistyped password, or a couple of stray login attempts, is not a brute force.
"""

from __future__ import annotations

import random
from datetime import datetime

from generator import messages as m
from generator import topology as topo
from generator.records import Rec, sec

_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_MAC_VENDORS = ("3c:22:fb", "f4:5c:89", "a4:83:e7", "00:1a:2b", "d8:bb:c1", "70:85:c2")
_HOSTNAME_KINDS = ("LAPTOP", "DESKTOP", "android", "iPhone", "printer", "cam")
_SUDO_COMMANDS = (
    "/usr/bin/systemctl status nginx",
    "/usr/bin/journalctl -u nginx -n 50",
    "/usr/bin/apt update",
    "/usr/bin/tail -n 100 /var/log/syslog",
    "/usr/bin/systemctl restart app.service",
)
_STRAY_USERS = ("admin", "test", "oracle", "ubuntu", "pi", "guest")

# (event kind, relative frequency). Line volume is roughly 45% DHCP, 35% server, 20% Cisco.
_EVENTS = (
    ("dhcp_new", 14),
    ("dhcp_renew", 22),
    ("ssh_session", 20),
    ("sudo", 8),
    ("cron", 10),
    ("stray_login", 2),
    ("port_bounce", 5),
    ("device_login", 5),
    ("admin_shutdown", 1),
)


def random_mac(rng: random.Random) -> str:
    tail = ":".join(f"{rng.randrange(256):02x}" for _ in range(3))
    return f"{rng.choice(_MAC_VENDORS)}:{tail}"


def random_hostname(rng: random.Random) -> str:
    return f"{rng.choice(_HOSTNAME_KINDS)}-{rng.randrange(0x1000, 0xFFFF):04X}"


class Noise:
    def __init__(
        self,
        rng: random.Random,
        start: datetime,
        end: datetime,
        reserved_ports: frozenset[tuple[str, str]] = frozenset(),
    ) -> None:
        self.rng = rng
        self.start = start
        self.end = end
        self.reserved_ports = reserved_ports
        self._port_used: dict[tuple[str, str], list[datetime]] = {}
        self.clients = [
            (random_mac(rng), f"10.20.0.{topo.DHCP_POOL_FIRST + i}", random_hostname(rng))
            for i in range(topo.DHCP_KNOWN_CLIENTS)
        ]
        self._ssh_sources = topo.MGMT_IPS + tuple(c[1] for c in self.clients[:12])

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

    # --- DHCP ---------------------------------------------------------------------------

    def _dhcp_new(self, t: datetime) -> list[Rec]:
        mac, ip, hostname = self.rng.choice(self.clients)
        host, nic = topo.DHCP_SERVER, topo.DHCP_IF
        offered = t + sec(self.rng.uniform(0.9, 1.1))  # dhcpd pings the address first
        return [
            Rec(t, host, m.dhcp_discover(mac, nic)),
            Rec(offered, host, m.dhcp_offer(ip, mac, nic)),
            Rec(offered + sec(0.02), host, m.dhcp_request(ip, mac, nic, topo.DHCP_SERVER_ID)),
            Rec(offered + sec(0.03), host, m.dhcp_ack(ip, mac, hostname, nic)),
        ]

    def _dhcp_renew(self, t: datetime) -> list[Rec]:
        mac, ip, hostname = self.rng.choice(self.clients)
        host, nic = topo.DHCP_SERVER, topo.DHCP_IF
        return [
            Rec(t, host, m.dhcp_request(ip, mac, nic)),
            Rec(t + sec(0.01), host, m.dhcp_ack(ip, mac, hostname, nic)),
        ]

    # --- Server -------------------------------------------------------------------------

    def _ssh_session(self, t: datetime) -> list[Rec]:
        rng = self.rng
        user = rng.choice(tuple(topo.SERVER_USERS))
        uid = topo.SERVER_USERS[user]
        src = rng.choice(self._ssh_sources)
        pid = rng.randrange(1200, 32000)
        port = rng.randrange(32768, 61000)
        out: list[Rec] = []
        if rng.random() < 0.7:
            key = "".join(rng.choice(_KEY_ALPHABET) for _ in range(43))
            out.append(Rec(t, topo.SERVER, m.ssh_accepted(pid, "publickey", user, src, port, key)))
        else:
            if rng.random() < 0.15:  # a mistyped password, then the right one
                out.append(Rec(t, topo.SERVER, m.ssh_failed(pid, user, src, port, invalid=False)))
                t = t + sec(rng.uniform(4, 9))
            out.append(Rec(t, topo.SERVER, m.ssh_accepted(pid, "password", user, src, port)))
        out.append(Rec(t + sec(0.05), topo.SERVER, m.session_opened("sshd", pid, user, uid)))
        closed = t + sec(rng.uniform(10, 2400))
        out.append(Rec(closed, topo.SERVER, m.session_closed("sshd", pid, user)))
        return out

    def _sudo(self, t: datetime) -> list[Rec]:
        user = self.rng.choice(("alice", "bob", "deploy"))
        return [Rec(t, topo.SERVER, m.sudo(user, self.rng.choice(_SUDO_COMMANDS)))]

    def _cron(self, t: datetime) -> list[Rec]:
        fired = t.replace(second=1, microsecond=0)  # cron jobs start on the minute
        pid = self.rng.randrange(1200, 32000)
        return [
            Rec(fired, topo.SERVER, m.session_opened("CRON", pid, "root", 0)),
            Rec(fired + sec(self.rng.uniform(0.2, 6)), topo.SERVER, m.session_closed("CRON", pid, "root")),  # noqa: E501
        ]

    def _stray_login(self, t: datetime) -> list[Rec]:
        """One to three failed logins from a random outside address: background scanning."""
        rng = self.rng
        ip = f"198.51.100.{rng.randrange(10, 250)}"
        out: list[Rec] = []
        for _ in range(rng.randrange(1, 4)):
            user = rng.choice(_STRAY_USERS)
            pid = rng.randrange(1200, 32000)
            port = rng.randrange(32768, 61000)
            out.append(Rec(t, topo.SERVER, m.ssh_invalid_user(pid, user, ip, port)))
            out.append(Rec(t + sec(1.8), topo.SERVER, m.ssh_failed(pid, user, ip, port, invalid=True)))  # noqa: E501
            t = t + sec(rng.uniform(3, 20))
        return out

    # --- Cisco --------------------------------------------------------------------------

    def _free_port(self, t: datetime) -> tuple[str, str] | None:
        """Pick an access port not used within an hour of `t`, so noise never looks like a flap."""
        for _ in range(20):
            port = (self.rng.choice(topo.SWITCHES), self.rng.choice(topo.ACCESS_PORTS))
            if port in self.reserved_ports:
                continue
            used = self._port_used.setdefault(port, [])
            if all(abs((t - u).total_seconds()) > 3600 for u in used):
                used.append(t)
                return port
        return None

    def _port_bounce(self, t: datetime) -> list[Rec]:
        """A user unplugs a device and plugs it (or another one) back in."""
        port = self._free_port(t)
        if port is None:
            return []
        switch, interface = port
        rng = self.rng
        poe = rng.random() < 0.4
        up = t + sec(rng.uniform(3, 900))
        out = [
            Rec(t, switch, m.link(interface, "down")),
            Rec(t + sec(1.0), switch, m.lineproto(interface, "down")),
            Rec(up, switch, m.link(interface, "up")),
            Rec(up + sec(1.0), switch, m.lineproto(interface, "up")),
        ]
        if poe:
            out.insert(0, Rec(t - sec(0.1), switch, m.poe_removed(interface)))
            out.insert(3, Rec(up - sec(1.5), switch, m.poe_granted(interface)))
        return out

    def _device_login(self, t: datetime) -> list[Rec]:
        rng = self.rng
        device = rng.choice(topo.CISCO_HOSTS)
        user = rng.choice(topo.NETWORK_ADMINS)
        src = rng.choice(topo.MGMT_IPS)
        out = [Rec(t, device, m.login_success(user, src, t))]
        done = t + sec(rng.uniform(20, 300))
        if rng.random() < 0.35:
            out.append(Rec(done, device, m.config_i(user, src)))
        out.append(Rec(done + sec(rng.uniform(2, 30)), device, m.logout(user, src)))
        return out

    def _admin_shutdown(self, t: datetime) -> list[Rec]:
        """An administrator shuts an access port on purpose."""
        port = self._free_port(t)
        if port is None:
            return []
        switch, interface = port
        user = self.rng.choice(topo.NETWORK_ADMINS)
        src = self.rng.choice(topo.MGMT_IPS)
        return [
            Rec(t, switch, m.login_success(user, src, t)),
            Rec(t + sec(40), switch, m.link_admin_down(interface)),
            Rec(t + sec(41), switch, m.lineproto(interface, "down")),
            Rec(t + sec(47), switch, m.config_i(user, src)),
        ]
