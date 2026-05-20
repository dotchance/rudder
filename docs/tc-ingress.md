<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# TC Ingress

Rudder attaches eBPF classifiers to the Linux TC ingress hook. Ingress is the
point where a packet enters an interface before normal routing decisions have
finished. That makes it a useful teaching point for packet steering: the eBPF
program can inspect the packet, rewrite headers, and redirect it to a selected
egress interface.

## Source Path

- CLI load entry point: [rudder.py](../rudder.py)
- TC lifecycle manager: [engine/manager.py](../engine/manager.py)
- Steer classifier: [ebpf/steer.c](../ebpf/steer.c)
- Replicate classifier: [ebpf/replicate.c](../ebpf/replicate.c)

## Attachment Model

`PolicyManager._attach_interface()` creates or reuses the `clsact` qdisc on an
interface, then attaches two eBPF classifiers to ingress:

- `steer.c` with TC preference `49152`
- `replicate.c` with TC preference `49153`

Those preference values are intentionally fixed. They let Rudder delete only
its own filters during reload or stop instead of deleting the whole `clsact`
qdisc and disturbing other TC users.

## Why Both Programs Attach

Rudder currently has one eBPF program for steering and one for replication.
Both are attached to each Rudder-managed ingress interface so both policy types
can be updated by writing maps during reload. A packet that does not match a
program's rules returns `TC_ACT_OK` and continues through the stack.

## Interface Selection

The YAML field `match.interface` controls where TC hooks are needed:

- A concrete interface such as `eth0` attaches Rudder to that interface.
- `any` expands to all current non-loopback interfaces visible in the network
  namespace where Rudder runs.

Run `sudo python3 rudder.py show internals` to see the attached interface list
and the TC preferences Rudder is using.
