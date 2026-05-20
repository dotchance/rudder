# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# The image is meant for labs and K3s/Multus experiments. It includes the
# userspace tools needed to compile eBPF programs, attach them with TC, inspect
# eBPF maps, and capture packets while learning.
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    libbpf-dev \
    linux-tools-generic \
    clang llvm \
    iproute2 tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /rudder
COPY requirements.txt .

# The base image is a general Ubuntu environment, so this install intentionally
# uses the system Python. Rudder is not packaged as a Python wheel yet.
RUN pip3 install --break-system-packages -r requirements.txt

COPY . .

# Start with a shell so operators can inspect interfaces, edit rules, and run
# `python3 rudder.py load ...` interactively inside a privileged lab pod.
CMD ["/bin/bash"]
