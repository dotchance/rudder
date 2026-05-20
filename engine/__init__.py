# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""Rudder's Python control plane.

The modules in this package keep the teaching boundary clear:

* `loader` turns YAML into validated Python policy objects.
* `manager` compiles and attaches eBPF programs, then writes policy data into
  eBPF maps.
* `daemon` keeps those attachments alive and accepts reload/show/stop commands.
* `observer` reads maps back into human-friendly CLI output.
"""
