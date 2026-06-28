#!/usr/bin/env python3
"""
M. Tyler Moffat: CSE 548 SDN DoS Mitigation Project
                 This script implements port security by enforcing one allowed IP
                 address per source MAC address. If one MAC address sends traffic
                 using a different source IP, the script installs an OpenFlow drop
                 rule on switch s1 for that source MAC.
"""

import re
import subprocess
import time
from datetime import datetime

SWITCH = "s1"
POLL_SECONDS = 1

# M. Tyler Moffat: Expected MAC-to-IP bindings for the required 4-host topology.
#                  These MAC addresses are stable because Mininet is started with --mac.
PORT_TABLE = {
    "00:00:00:00:00:01": "192.168.2.10",
    "00:00:00:00:00:02": "192.168.2.20",
    "00:00:00:00:00:03": "192.168.2.30",
    "00:00:00:00:00:04": "192.168.2.40",
}

blocked_macs = set()


def get_field(line, field_name):
    """M. Tyler Moffat: Extract a field such as dl_src or nw_src from one OVS flow line."""
    match = re.search(r"\b" + re.escape(field_name) + r"=([^, ]+)", line)
    return match.group(1).lower() if match else None


def dump_flows():
    """M. Tyler Moffat: Read current OpenFlow entries from switch s1."""
    result = subprocess.run(
        ["ovs-ofctl", "dump-flows", SWITCH],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return result.stdout.splitlines()


def install_drop_rule(src_mac):
    """M. Tyler Moffat: Install a high-priority OpenFlow rule that blocks the attacking MAC."""
    rule = f"priority=65535,dl_src={src_mac},actions=drop"
    result = subprocess.run(
        ["ovs-ofctl", "add-flow", SWITCH, rule],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if result.returncode == 0:
        print(f"[{timestamp}] BLOCKED {src_mac} using rule: {rule}", flush=True)
    else:
        print(f"[{timestamp}] ERROR installing rule for {src_mac}: {result.stderr}", flush=True)


def inspect_flow(line):
    """M. Tyler Moffat: Detect whether one source MAC is using more than one source IP."""
    src_mac = get_field(line, "dl_src")
    src_ip = get_field(line, "nw_src")

    if not src_mac or not src_ip:
        return

    expected_ip = PORT_TABLE.get(src_mac)

    if expected_ip is None:
        PORT_TABLE[src_mac] = src_ip
        print(f"[LEARN] {src_mac} -> {src_ip}", flush=True)
        return

    if src_ip != expected_ip:
        print(
            f"[ALERT] MAC {src_mac} expected {expected_ip}, but saw spoofed source IP {src_ip}",
            flush=True,
        )

        if src_mac not in blocked_macs:
            install_drop_rule(src_mac)
            blocked_macs.add(src_mac)


def main():
    print("M. Tyler Moffat: Port-security monitor started.")
    print("M. Tyler Moffat: Press Ctrl+C to stop.")
    print(f"M. Tyler Moffat: Initial port table: {PORT_TABLE}", flush=True)

    while True:
        for flow in dump_flows():
            inspect_flow(flow)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()