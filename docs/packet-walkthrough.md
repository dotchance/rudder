<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Packet Walkthrough

This page describes what happens to one packet after it enters a Rudder-managed
interface.

## Source Path

- Steer packet path: [ebpf/steer.c](../ebpf/steer.c)
- Replicate packet path: [ebpf/replicate.c](../ebpf/replicate.c)
- Rule map layout: [ebpf/maps.h](../ebpf/maps.h)
- Packet generator: [tests/gen_packets.py](../tests/gen_packets.py)

## Common Parsing

Both eBPF programs first parse Ethernet and IPv4 headers. Packets that are too
short, not IPv4, have an invalid IPv4 IHL, or are fragmented pass through
unchanged.

The programs then read fields used by policy matching:

- ingress ifindex from TC metadata
- source and destination IPv4 addresses
- DSCP from the IPv4 TOS byte
- IP protocol

## Steer Path

The steer program scans `steer_rules` in slot order. The first matching rule:

1. rewrites the IPv4 destination address,
2. updates IPv4 and transport checksums,
3. rewrites the Ethernet destination MAC,
4. increments the steer hit counter,
5. emits a trace event,
6. calls `bpf_redirect()` to send the packet to the selected egress interface.

## Replicate Path

The replicate program only handles multicast IPv4 destinations. The first
matching rule walks its configured targets:

1. for every target except the last, rewrite the current packet and clone it
   with `bpf_clone_redirect()`,
2. restore the original multicast destination before the next target,
3. for the last target, rewrite the original packet and redirect it with
   `bpf_redirect()`.

This avoids creating an extra clone for the final copy and keeps the rule's hit
counter tied to one matched original packet.

## Verifying Behavior

Use `tests/gen_packets.py` to send controlled packets and `tcpdump` on egress
interfaces to inspect rewritten destinations. Use `show stats` for counters and
`show maps` to confirm the map slots that the eBPF programs are reading.
