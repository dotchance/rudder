<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Tracing

Rudder can emit trace events from the eBPF programs through perf event array
maps. This is useful for learning because it shows which rule matched and what
destination rewrite was selected.

## Source Path

- eBPF event layout: [ebpf/maps.h](../ebpf/maps.h)
- Steer event emission: [ebpf/steer.c](../ebpf/steer.c)
- Replicate event emission: [ebpf/replicate.c](../ebpf/replicate.c)
- Experimental userspace reader: [engine/perf_reader.py](../engine/perf_reader.py)
- CLI trace command: [rudder.py](../rudder.py)

## Current Status

`rudder trace` is experimental. It opens pinned perf event array maps directly,
sets up per-CPU perf events, and prints decoded `trace_event` records. The
command now labels itself experimental when it starts and resolves rule names
through the daemon when possible.

The current `PerfReader` is intentionally small and educational. It is not a
complete production implementation of the Linux perf mmap protocol. A complete
reader needs careful handling for metadata offsets, memory barriers, record
wraparound, lost samples, and kernel version differences.

## What Trace Events Mean

Trace events contain:

- timestamp from `bpf_ktime_get_ns()`
- rule slot id
- source IPv4 address
- original destination IPv4 address
- rewritten destination IPv4 address
- egress ifindex
- event type: steer, replicate clone, or replicate final

Use `sudo python3 rudder.py show internals` to see which rule name owns each
slot and which pinned perf event maps the trace command reads.

## Future Direction

The tracing path should eventually become either a fully correct perf reader or
a clearer ring-buffer based implementation if the eBPF program compatibility
goals allow it. Until then, treat trace output as a learning and debugging aid,
not as packet accounting or a lossless audit stream.
