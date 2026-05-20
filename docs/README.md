<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Rudder Learning Docs

These notes explain how Rudder's YAML policy, Python control plane, TC hooks,
and eBPF packet programs fit together. They are source-linked on purpose: the
goal is to make the code easier to read, not to replace it with separate theory.

- [TC Ingress](tc-ingress.md)
- [eBPF Maps](ebpf-maps.md)
- [Checksum Updates](checksum-updates.md)
- [Reload Flow](reload-flow.md)
- [Rule Lifecycle](rule-lifecycle.md)
- [Packet Walkthrough](packet-walkthrough.md)
- [Tracing](tracing.md)

For a live system view, run:

```bash
sudo python3 rudder.py show internals
```

That command shows TC filter priorities, attached interfaces, eBPF map ids,
pinned representative maps, runtime object paths, source rule files, and active
map slots.
