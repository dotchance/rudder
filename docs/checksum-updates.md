<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Checksum Updates

Rudder rewrites packet headers in the TC eBPF programs. Whenever an IP
destination changes, the affected checksums must change too, or receivers may
drop the packet.

## Source Path

- Steer checksum updates: [ebpf/steer.c](../ebpf/steer.c)
- Replicate checksum updates: [ebpf/replicate.c](../ebpf/replicate.c)
- Packet field layouts: [ebpf/maps.h](../ebpf/maps.h)

## IPv4 Header Checksum

The IPv4 header checksum covers the IPv4 header, including destination address.
After Rudder rewrites `iph->daddr`, it calls `bpf_l3_csum_replace()` with the old
destination and new destination. This applies a checksum delta instead of
recomputing the whole header checksum in eBPF code.

## TCP And UDP Pseudo-Header Checksums

TCP and UDP checksums include an IPv4 pseudo-header containing source and
destination IPs. If Rudder changes the destination IP, it must update those
transport checksums too.

The programs calculate the L4 checksum offset from the IPv4 IHL. This matters
because IPv4 options make the IP header longer than the common 20-byte case.

IPv4 UDP has a special case: checksum `0` means the UDP checksum is disabled.
Rudder preserves that behavior and does not create a checksum for such packets.

## Fragments

Rudder currently skips fragmented IPv4 packets. Rewriting fragments correctly
requires more packet state than the current teaching backend keeps. This is
represented in the Policy IR backend limits and is visible in
`sudo python3 rudder.py show internals`.
