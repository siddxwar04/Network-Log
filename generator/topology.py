"""The one simulated network every scenario uses. See generator/README.md for the diagram.

Inside addresses are private (10.0.0.0/8). Outside addresses use the ranges reserved
for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""

ROUTERS = ("R1", "R2", "R3", "R4")
SWITCHES = ("SW1", "SW2")
CISCO_HOSTS = ROUTERS + SWITCHES

# Each router's loopback is its OSPF router id and its iBGP peering address.
LOOPBACK = {"R1": "10.255.0.1", "R2": "10.255.0.2", "R3": "10.255.0.3", "R4": "10.255.0.4"}

# All four routers attach to one shared transit LAN (10.0.0.0/24) on this interface.
TRANSIT_IF = "GigabitEthernet0/1"

# eBGP neighbors: R1 peers with ISP-A, R2 with ISP-B, both on GigabitEthernet0/0.
ISP_NEIGHBOR = {"R1": "198.51.100.1", "R2": "203.0.113.1"}

# R1's interface to the server LAN (10.10.10.0/24). No routing protocol runs on it.
SERVER_LAN_IF = "GigabitEthernet0/2"

# Each access switch hangs off one distribution router.
SWITCH_UPLINK_IF = "GigabitEthernet0/1"
SWITCH_PARENT = {"SW1": ("R3", "GigabitEthernet0/3"), "SW2": ("R4", "GigabitEthernet0/3")}
ACCESS_PORTS = tuple(f"GigabitEthernet0/{n}" for n in range(2, 25))

SERVER = "srv1"
DHCP_SERVER = "dhcp1"
LINUX_HOSTS = (SERVER, DHCP_SERVER)

DHCP_IF = "eth1"
DHCP_SERVER_ID = "10.20.0.2"
DHCP_NETWORK = "10.20.0.0/24"
# The pool is 10.20.0.10 to 10.20.0.254: 245 addresses.
DHCP_KNOWN_CLIENTS = 180
DHCP_POOL_FIRST = 10
DHCP_POOL_LAST = 254

MGMT_IPS = tuple(f"10.10.10.{n}" for n in range(50, 56))
NETWORK_ADMINS = ("netops", "jdoe", "asingh")
SERVER_USERS = {"deploy": 1001, "alice": 1002, "bob": 1003, "backup": 1004, "monitor": 1005}

ATTACKER_IP = "192.0.2.77"
