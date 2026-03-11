#!/usr/bin/env python3
"""Scapy-based packet generator for testing rudder steering and replication rules.

Generates UDP, TCP, or ICMP packets with configurable source/destination IP,
DSCP value, and output interface. Used to validate eBPF TC programs.
"""

import argparse
import sys
import time

from scapy.all import (
    Ether, IP, UDP, TCP, ICMP, Raw, sendp, conf,
)


def build_packet(args):
    """Build a packet based on command-line arguments."""
    ip = IP(src=args.src_ip, dst=args.dst_ip)

    # Set DSCP in the TOS byte (DSCP occupies upper 6 bits)
    ip.tos = (args.dscp & 0x3F) << 2

    if args.proto == "udp":
        transport = UDP(sport=12345, dport=5000)
    elif args.proto == "tcp":
        transport = TCP(sport=12345, dport=5000, flags="S")
    elif args.proto == "icmp":
        transport = ICMP()
    else:
        print(f"Unknown protocol: {args.proto}")
        sys.exit(1)

    payload = Raw(load=b"rudder-test-" + b"X" * 48)
    pkt = Ether() / ip / transport / payload
    return pkt


def main():
    parser = argparse.ArgumentParser(
        description="Generate test packets for rudder validation"
    )
    parser.add_argument("--mode", choices=["steer", "replicate"], required=True,
                        help="Test mode: steer or replicate")
    parser.add_argument("--src-ip", default="10.0.0.1",
                        help="Source IP address (default: 10.0.0.1)")
    parser.add_argument("--dst-ip", required=True,
                        help="Destination IP address")
    parser.add_argument("--dscp", type=int, default=0,
                        help="DSCP value 0-63 (default: 0)")
    parser.add_argument("--iface", required=True,
                        help="Outgoing interface name")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of packets to send (default: 10)")
    parser.add_argument("--interval", type=float, default=0.1,
                        help="Seconds between packets (default: 0.1)")
    parser.add_argument("--proto", choices=["tcp", "udp", "icmp"], default="udp",
                        help="Protocol: tcp, udp, or icmp (default: udp)")
    args = parser.parse_args()

    if args.dscp < 0 or args.dscp > 63:
        print("DSCP must be 0-63")
        sys.exit(1)

    # Suppress scapy verbosity
    conf.verb = 0

    pkt = build_packet(args)
    print(f"Sending {args.count} {args.proto.upper()} packets: "
          f"{args.src_ip} -> {args.dst_ip} "
          f"dscp={args.dscp} iface={args.iface} mode={args.mode}")

    for i in range(args.count):
        sendp(pkt, iface=args.iface)
        summary = (f"  [{i+1}/{args.count}] {args.proto.upper()} "
                   f"{args.src_ip} -> {args.dst_ip} "
                   f"dscp={args.dscp}")
        print(summary)
        if i < args.count - 1:
            time.sleep(args.interval)

    print(f"Sent {args.count} packets.")


if __name__ == "__main__":
    main()
