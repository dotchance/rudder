<!--
Copyright 2025-2026 .chance (dotchance)
Licensed under the Apache License, Version 2.0. See LICENSE file.
-->

# Deploy

This directory contains optional lab deployment scaffolding for running Rudder
inside Kubernetes, specifically K3s-style environments that use Multus to attach
multiple network interfaces to one pod.

These files are not the core Rudder runtime. The core project is the Python
control plane, YAML policy model, TC attachment flow, and eBPF packet programs.
The deployment files are here for a narrower purpose: to help people build a
repeatable multi-interface lab where they can experiment with eBPF TC packet
steering and multicast-to-unicast replication without manually installing every
userspace dependency on a host.

## Files

- `Dockerfile` builds an Ubuntu-based lab image with Python, clang/LLVM,
  `bpftool`, `tc`, `tcpdump`, Rudder's runtime Python dependencies, and the
  optional dev/test dependency used by `tests/gen_packets.py`.
- `pod.yaml` shows a privileged K3s/Multus pod with multiple attached
  interfaces and the host mounts needed for eBPF map pinning and kernel headers.

## Intended Use

Use these files when you want to test Rudder in a containerized network lab that
has multiple pod interfaces, for example:

- one ingress interface receiving packets to match,
- one or more egress interfaces used by steer or replicate rules,
- a shared `/sys/fs/bpf` mount so pinned eBPF maps can be inspected,
- enough host access for TC and eBPF program loading.

This setup is useful for demonstrations, workshops, and local cluster labs. It
is not meant to imply that Rudder must run in Kubernetes, and it is not a
hardened production deployment.

## Security Model

The sample pod is privileged because loading eBPF programs, attaching TC
filters, and accessing host eBPF state require elevated Linux capabilities. That
is acceptable for a controlled lab but too broad for many production
environments.

Before adapting this manifest outside a lab, narrow the security context and
host mounts to the minimum capabilities your environment supports. Treat the
container image, rule files, mounted host paths, and cluster access as privileged
inputs.

## Build And Run

```bash
docker build -t rudder:latest -f deploy/Dockerfile .
kubectl apply -f deploy/pod.yaml
kubectl exec -it rudder -- bash
```

Inside the pod, inspect interfaces and run Rudder the same way you would on a
host:

```bash
ip link
python3 rudder.py load rules/example_steer.yaml
python3 rudder.py show interfaces
python3 rudder.py stop
```

The Multus `NetworkAttachmentDefinition` resources referenced by `pod.yaml`
must already exist in the cluster. The example names are `rudder-net1`,
`rudder-net2`, and `rudder-net3`.
