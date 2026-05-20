<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Rule Lifecycle

This page follows a rule from YAML to an eBPF map slot.

## Source Path

- Rule dataclasses: [engine/models.py](../engine/models.py)
- Policy IR: [engine/policy.py](../engine/policy.py)
- YAML loader: [engine/loader.py](../engine/loader.py)
- Map serialization: [engine/manager.py](../engine/manager.py)
- eBPF map layouts: [ebpf/maps.h](../ebpf/maps.h)

## 1. YAML

A rule begins as human-readable YAML with a name, priority, type, match section,
and action section. YAML is only one frontend. Future grammar work should parse
into the same Policy IR instead of bypassing it.

## 2. Validation

`engine/loader.py` rejects malformed structure, unknown fields, invalid MACs,
bad interface names, duplicate priorities, duplicate names, and unsupported
protocols. These checks protect the live TC/eBPF path and produce errors that
explain what Rudder needs from the user.

## 3. Policy IR

The loader returns a `Policy` object. The policy contains normalized `Rule`
objects, backend limits, and source file information. The daemon stores this as
the active intent.

## 4. Slot Assignment

Rules are sorted by priority. Then the loader assigns `rule_id` separately per
rule type:

- steer rules get steer slots starting at 0
- replicate rules get replicate slots starting at 0

That slot becomes the eBPF array key and the hit-counter key.

## 5. Serialization

`PolicyManager` turns Python fields into byte layouts matching `ebpf/maps.h`.
For example, interface names become ifindexes, IP networks become address plus
prefix length, and optional match fields become sentinel values.

## 6. Runtime Observation

Use these commands to inspect the lifecycle from different angles:

```bash
sudo python3 rudder.py show rules
sudo python3 rudder.py show maps
sudo python3 rudder.py show internals
```
