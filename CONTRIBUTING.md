<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Contributing

Thanks for improving rudder. This repository is focused on Linux eBPF TC packet steering and multicast-to-unicast replication, so changes should keep the CLI, rule format, eBPF programs, and deployment docs aligned.

## Development Checks

Run the lightweight checks before opening a pull request:

```bash
python -m pip install -r requirements.txt
python -m compileall rudder.py engine tests
python - <<'PY'
from engine.loader import load_rules
load_rules(["rules/example_steer.yaml", "rules/example_replicate.yaml"])
PY
```

On a Linux host with clang and libbpf headers, also compile the eBPF programs:

```bash
clang -O2 -g -target bpf \
  -I/usr/include \
  -I/usr/include/x86_64-linux-gnu \
  -c ebpf/steer.c -o /tmp/rudder_steer.o

clang -O2 -g -target bpf \
  -I/usr/include \
  -I/usr/include/x86_64-linux-gnu \
  -c ebpf/replicate.c -o /tmp/rudder_replicate.o
```

Runtime testing requires root privileges, a Linux kernel with eBPF TC support, and interfaces that match the loaded rule files.

## Pull Requests

- Keep behavior, documentation, and examples in sync.
- Include the kernel, distro, and interface topology used for runtime validation when a change affects packet handling.
- Avoid committing generated BPF object files, packet captures, secrets, host-specific configs, or local virtual environments.
- Use private security reporting for vulnerabilities instead of public pull requests or issues.
