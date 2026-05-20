<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Reload Flow

Reload is Rudder's core semi-real-time workflow. A user edits YAML, asks Rudder
to reload, and the daemon updates live eBPF maps without stopping the process.

## Source Path

- CLI reload command: [rudder.py](../rudder.py)
- Daemon reload handler: [engine/daemon.py](../engine/daemon.py)
- YAML validation and Policy IR creation: [engine/loader.py](../engine/loader.py)
- Staged TC/eBPF update: [engine/manager.py](../engine/manager.py)

## Stages

1. The CLI sends a JSON reload request to the daemon socket under `/run/rudder`.
2. The daemon parses YAML into a new `Policy`.
3. Validation rejects malformed rules before TC or eBPF state is touched.
4. The manager resolves interfaces and next-hop MACs for the new policy.
5. Newly needed TC hooks are attached.
6. The manager refreshes eBPF map ids and writes the new policy into every map
   instance.
7. Interfaces no longer needed by the accepted policy are detached.
8. The daemon swaps its active Policy IR and Observer only after the manager
   succeeds.

## Failure Behavior

Reload is not perfectly atomic at the kernel level because TC filters and eBPF
maps are separate kernel objects. Rudder still stages the update to keep the
last good policy active wherever possible.

If a preflight step fails, Rudder restores the previous in-memory policy without
rewriting maps. If a map write fails after new hooks were attached, Rudder tries
to repopulate the old policy and detach newly attached interfaces. The CLI
reports whether that rollback succeeded.

Run `sudo python3 rudder.py show internals` before and after reload to see the
TC hooks, eBPF map ids, and active slots.
