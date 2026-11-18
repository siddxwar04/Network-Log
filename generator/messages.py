"""Message text for every log line the generator emits.

Cisco formats follow IOS 15.x system messages. Formats marked UNVERIFIED were written
from memory and should be checked against Cisco documentation before being relied on.
"""

from datetime import datetime

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def stamp(dt: datetime) -> str:
    """Classic syslog timestamp: `Mar  3 02:14:07` (day padded with a space, no year)."""
    return f"{MONTHS[dt.month - 1]} {dt.day:>2} {dt:%H:%M:%S}"


def stamp_ms(dt: datetime) -> str:
    return f"{stamp(dt)}.{dt.microsecond // 1000:03d}"


def cisco_clock(dt: datetime) -> str:
    """Time as Cisco prints it inside a message: `02:14:07 UTC Tue Mar 3 2026`."""
    return f"{dt:%H:%M:%S} UTC {WEEKDAYS[dt.weekday()]} {MONTHS[dt.month - 1]} {dt.day} {dt.year}"


def short_if(interface: str) -> str:
    """`GigabitEthernet0/7` -> `Gi0/7`, the form some messages use."""
    return interface.replace("GigabitEthernet", "Gi")


# --- Cisco IOS -------------------------------------------------------------------------


def link(interface: str, state: str) -> str:
    return f"%LINK-3-UPDOWN: Interface {interface}, changed state to {state}"


def lineproto(interface: str, state: str) -> str:
    return f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {interface}, changed state to {state}"


def link_admin_down(interface: str) -> str:
    return f"%LINK-5-CHANGED: Interface {interface}, changed state to administratively down"


def ospf_adj(neighbor: str, interface: str, frm: str, to: str, detail: str) -> str:
    return f"%OSPF-5-ADJCHG: Process 1, Nbr {neighbor} on {interface} from {frm} to {to}, {detail}"


def bgp_down(neighbor: str, reason: str) -> str:
    return f"%BGP-5-ADJCHANGE: neighbor {neighbor} Down {reason}"


def bgp_up(neighbor: str) -> str:
    return f"%BGP-5-ADJCHANGE: neighbor {neighbor} Up"


def bgp_hold_expired(neighbor: str) -> str:
    return f"%BGP-3-NOTIFICATION: sent to neighbor {neighbor} 4/0 (hold time expired) 0 bytes"


def config_i(user: str, source_ip: str) -> str:
    return f"%SYS-5-CONFIG_I: Configured from console by {user} on vty0 ({source_ip})"


def login_success(user: str, source_ip: str, at: datetime) -> str:
    return (
        f"%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: {user}] [Source: {source_ip}] "
        f"[localport: 22] at {cisco_clock(at)}"
    )


def logout(user: str, source_ip: str) -> str:
    # UNVERIFIED wording.
    return f"%SYS-6-LOGOUT: User {user} has exited tty session 2({source_ip})"


def reload_requested(user: str, source_ip: str) -> str:
    return (
        f"%SYS-5-RELOAD: Reload requested by {user} on vty0 ({source_ip}). "
        "Reload Reason: Reload Command."
    )


def restart() -> str:
    # On a real device this message spans several lines; collectors often store the
    # first line only or join them. Joined here.
    return (
        "%SYS-5-RESTART: System restarted -- Cisco IOS Software, C2960X Software "
        "(C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)"
    )


def clock_update(old: datetime, new: datetime, ntp_server: str) -> str:
    # UNVERIFIED wording.
    return (
        f"%SYS-6-CLOCKUPDATE: System clock has been updated from {cisco_clock(old)} "
        f"to {cisco_clock(new)}, configured from NTP by {ntp_server}."
    )


def poe_granted(interface: str) -> str:
    return f"%ILPOWER-5-POWER_GRANTED: Interface {short_if(interface)}: Power granted"


def poe_removed(interface: str) -> str:
    return f"%ILPOWER-5-IEEE_DISCONNECT: Interface {short_if(interface)}: PD removed"


# --- Linux sshd, sudo, cron -------------------------------------------------------------


def ssh_failed(pid: int, user: str, ip: str, port: int, *, invalid: bool) -> str:
    who = f"invalid user {user}" if invalid else user
    return f"sshd[{pid}]: Failed password for {who} from {ip} port {port} ssh2"


def ssh_invalid_user(pid: int, user: str, ip: str, port: int) -> str:
    return f"sshd[{pid}]: Invalid user {user} from {ip} port {port}"


def ssh_closed_preauth(pid: int, user: str, ip: str, port: int, *, invalid: bool) -> str:
    who = f"invalid user {user}" if invalid else f"authenticating user {user}"
    return f"sshd[{pid}]: Connection closed by {who} {ip} port {port} [preauth]"


def ssh_accepted(pid: int, method: str, user: str, ip: str, port: int, key: str = "") -> str:
    suffix = f": ED25519 SHA256:{key}" if key else ""
    return f"sshd[{pid}]: Accepted {method} for {user} from {ip} port {port} ssh2{suffix}"


def session_opened(app: str, pid: int, user: str, uid: int) -> str:
    return f"{app}[{pid}]: pam_unix({app.lower()}:session): session opened for user {user}(uid={uid}) by (uid=0)"  # noqa: E501


def session_closed(app: str, pid: int, user: str) -> str:
    return f"{app}[{pid}]: pam_unix({app.lower()}:session): session closed for user {user}"


def sudo(user: str, command: str) -> str:
    return f"sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}"


# --- ISC dhcpd --------------------------------------------------------------------------

_DHCPD = "dhcpd[811]"


def dhcp_discover(mac: str, interface: str) -> str:
    return f"{_DHCPD}: DHCPDISCOVER from {mac} via {interface}"


def dhcp_offer(ip: str, mac: str, interface: str) -> str:
    return f"{_DHCPD}: DHCPOFFER on {ip} to {mac} via {interface}"


def dhcp_request(ip: str, mac: str, interface: str, server_id: str = "") -> str:
    server = f" ({server_id})" if server_id else ""
    return f"{_DHCPD}: DHCPREQUEST for {ip}{server} from {mac} via {interface}"


def dhcp_ack(ip: str, mac: str, hostname: str, interface: str) -> str:
    return f"{_DHCPD}: DHCPACK on {ip} to {mac} ({hostname}) via {interface}"


def dhcp_no_free_leases(mac: str, interface: str, network: str) -> str:
    return f"{_DHCPD}: DHCPDISCOVER from {mac} via {interface}: network {network}: no free leases"
