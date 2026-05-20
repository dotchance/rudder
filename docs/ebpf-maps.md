<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# eBPF Maps

Rudder uses eBPF maps as the contract between the Python control plane and the
in-kernel TC programs. YAML is parsed into the Policy IR, the manager serializes
that IR into fixed byte layouts, and the eBPF programs read those layouts while
processing packets.

## Source Path

- Shared C layouts: [ebpf/maps.h](../ebpf/maps.h)
- Python struct packing: [engine/manager.py](../engine/manager.py)
- Human-readable map dumps: [engine/observer.py](../engine/observer.py)
- Policy IR: [engine/policy.py](../engine/policy.py)

## Map Types

Rudder's current map set is:

- `steer_rules`: array of `struct steer_rule`
- `steer_hits`: per-rule steer hit counters
- `steer_events`: perf event array for steer trace events
- `replicate_rules`: array of `struct replicate_rule`
- `repl_hits`: per-rule replicate hit counters
- `repl_events`: perf event array for replicate trace events

The literal Linux API names still use `BPF`, such as `BPF_MAP_TYPE_ARRAY`, but
Rudder describes the technology and learning path as eBPF.

## Per-Attach Map Instances

Every `tc filter add ... obj ...` load creates a new set of map instances. If
Rudder attaches the same object to four interfaces, Linux creates four
`steer_rules` maps, four `steer_hits` maps, and so on.

That is why `PolicyManager._refresh_map_ids()` tracks every map id with a Rudder
map name, and why map writes update every matching map id. The pinned path under
`/sys/fs/bpf/rudder/` is only a representative map for inspection and trace
experiments.

## Slot Model

Rules are sorted by priority, then assigned dense per-type slots:

- steer rule slot `0..N-1` in `steer_rules`
- replicate rule slot `0..N-1` in `replicate_rules`

The eBPF programs stop scanning at the first invalid slot, so the manager
zero-fills unused slots after every load or reload. Run
`sudo python3 rudder.py show internals` to see the active rule-to-slot mapping.
