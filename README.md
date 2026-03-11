# Rudder

[https://github.com/dotchance/rudder](https://github.com/dotchance/rudder)

Rudder is a CLI tool for eBPF-based packet steering and multicast replication on Linux. It attaches eBPF programs to the TC (Traffic Control) ingress hook, letting you define YAML rules that match packets by interface, DSCP value, source/destination IP prefix, and protocol — then rewrite headers and redirect traffic across interfaces at wire speed in the kernel.

Two policy types are supported:

- **Steer** — Match ingress packets by DSCP, IP prefix, and protocol. Rewrite the destination IP and MAC, then redirect to a chosen egress interface. Useful for policy-based routing, traffic engineering, and DSCP-driven path selection.
- **Replicate** — Match multicast packets and fan them out as unicast copies to multiple egress interfaces, each with its own rewritten destination IP and MAC. Useful for multicast-to-unicast conversion across multiple downstream paths.

## How It Works

```
                   YAML rules
                       |
                       v
               +---------------+
               | Python engine |  Compiles eBPF C with clang
               | (engine/)     |  Attaches programs via `tc`
               +-------+-------+  Populates BPF maps via `bpftool`
                       |
            +----------+----------+
            |                     |
     ebpf/steer.c          ebpf/replicate.c
            |                     |
            v                     v
     TC ingress hook       TC ingress hook
     (per interface)       (per interface)
            |                     |
            v                     v
    Match + rewrite IP     Match multicast dst
    + redirect to egress   + clone to N unicast
                             destinations
```

When you run `rudder load`, the engine:

1. Parses and validates YAML rule files
2. Compiles `ebpf/steer.c` and `ebpf/replicate.c` with clang to BPF object files
3. Attaches both programs to TC ingress on each referenced interface via `tc filter add`
4. Pins BPF maps to `/sys/fs/bpf/rudder/` for userspace access
5. Serializes rules into the BPF array maps using `bpftool`
6. Forks a background daemon that holds state and serves CLI queries

The eBPF programs run in-kernel. On each ingress packet they iterate the rule array, match fields, rewrite the IP and Ethernet headers, fix checksums, and call `bpf_redirect()` (steer) or `bpf_clone_redirect()` (replicate).

## Requirements

- Linux kernel 5.15 or later (required for bounded loops in BPF)
- Root privileges (eBPF and TC attachment require CAP_SYS_ADMIN)
- x86_64 architecture

### System Dependencies

Install on Ubuntu/Debian:

```bash
sudo apt-get install -y \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-generic \
    clang \
    llvm \
    iproute2 \
    tcpdump
```

`linux-tools-generic` provides `bpftool`, which rudder uses to pin and populate BPF maps. `tcpdump` is optional but invaluable for verifying redirected packets on egress interfaces.

### Python Dependencies

```bash
pip3 install -r requirements.txt
```

This installs `click` (CLI framework), `PyYAML` (rule parsing), `pyroute2` (ARP neighbor table lookup), and `scapy` (test packet generation).

## Building the eBPF Programs

The Python engine compiles the eBPF programs automatically during `rudder load`, but you can also compile them manually to check for errors:

```bash
# Compile the steer program
clang -O2 -g -target bpf \
    -I/usr/include \
    -I/usr/include/x86_64-linux-gnu \
    -c ebpf/steer.c -o /tmp/rudder_steer.o

# Compile the replicate program
clang -O2 -g -target bpf \
    -I/usr/include \
    -I/usr/include/x86_64-linux-gnu \
    -c ebpf/replicate.c -o /tmp/rudder_replicate.o
```

Both commands should complete with zero warnings. If you see verifier-related errors when the program is loaded by `tc`, check that your kernel is 5.15 or later — earlier kernels may not support the bounded loop iteration pattern used to walk the rule array.

You can inspect the compiled objects with `llvm-objdump`:

```bash
llvm-objdump -d /tmp/rudder_steer.o        # Disassemble BPF instructions
llvm-objdump -h /tmp/rudder_steer.o        # Show sections (should include classifier and .maps)
```

## Rule File Format

Rules are defined in YAML files under a top-level `rules` key. Multiple files can be loaded simultaneously — all rules are merged, sorted by priority, and validated as a single set.

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique human-readable label |
| `priority` | yes | Integer evaluation order (lower = first). Must be unique across all files. |
| `type` | yes | `steer` or `replicate` |
| `match.interface` | yes | Ingress interface name (e.g. `eth0`) or `any` |
| `match.src_ip` | no | Source IP or CIDR prefix (e.g. `10.1.0.0/16`). Omit to match any. |
| `match.dst_ip` | no | Destination IP or CIDR prefix. Omit to match any. |
| `match.dscp` | no | DSCP value 0-63 (the 6-bit field, not the full TOS byte). Omit to match any. |
| `match.ip_proto` | no | `tcp`, `udp`, or `any` (default: `any`) |
| `action.dst_ip` | steer | Rewrite destination IP to this exact address |
| `action.via` | steer | Egress interface name |
| `action.next_hop_mac` | no | Static next-hop MAC (`aa:bb:cc:dd:ee:ff`). If omitted, resolved from ARP table. |
| `action.targets` | replicate | List of 1-12 replication targets, each with `dst_ip`, `via`, and optional `next_hop_mac` |

### Steer Rule Example

Route all EF-marked traffic (DSCP 46) destined for `10.0.0.0/8` arriving on `eth0` to `192.168.100.1` via `eth2`:

```yaml
rules:
  - name: ef-to-path-a
    priority: 10
    type: steer
    match:
      interface: eth0
      dscp: 46
      dst_ip: 10.0.0.0/8
    action:
      dst_ip: 192.168.100.1
      via: eth2
```

### Replicate Rule Example

Take any multicast packet to `239.1.1.1` on any interface, and deliver unicast copies to three destinations:

```yaml
rules:
  - name: mcast-replicate-stream
    priority: 20
    type: replicate
    match:
      interface: any
      dst_ip: 239.1.1.1
    action:
      targets:
        - dst_ip: 10.10.1.1
          via: eth1
        - dst_ip: 10.10.2.1
          via: eth2
        - dst_ip: 10.10.3.1
          via: eth3
```

### Multiple Files

You can split rules across files and load them together. Priorities and names must be unique across all files:

```bash
sudo python3 rudder.py load rules/steering.yaml rules/replication.yaml rules/overrides.yaml
```

## Usage

All commands require root.

### Load Rules

Parse rule files, compile eBPF programs, attach TC hooks, populate maps, and start the background daemon:

```bash
sudo python3 rudder.py load rules/example_steer.yaml
```

```
Loading rules from: rules/example_steer.yaml
  [ok] ef-to-path-a         priority=10   type=steer     interface=eth0
Attaching TC hooks:
  [ok] eth0  ingress
  [ok] eth2  ingress
Rudder running. 1 rule active (1 steer, 0 replicate). Daemon PID: 4821
```

Load both steer and replicate rules at once:

```bash
sudo python3 rudder.py load rules/example_steer.yaml rules/example_replicate.yaml
```

### Show Rules

Display the active rule table:

```bash
sudo python3 rudder.py show rules
```

```
PRI   NAME                  TYPE        INTERFACE   MATCH                         ACTION
10    ef-to-path-a          steer       eth0        dscp=46 dst=10.0.0.0/8        via=eth2 -> 192.168.100.1
20    mcast-replicate-stream replicate  any         dst=239.1.1.1                 3 targets: eth1 eth2 eth3
```

### Show Stats

Display per-rule packet hit counters:

```bash
sudo python3 rudder.py show stats
```

```
NAME                  TYPE        PRI    HITS
ef-to-path-a          steer       10       14,382
mcast-replicate-stream replicate  20          891
```

### Show Maps

Dump the raw BPF map contents with all fields decoded:

```bash
sudo python3 rudder.py show maps
```

```
=== steer_rules ===
  slot=0 name=ef-to-path-a ingress=eth0 src=0.0.0.0/0 dst=10.0.0.0/8 dscp=46 proto=0 -> new_dst=192.168.100.1 egress=eth2 mac=aa:bb:cc:dd:ee:ff
=== replicate_rules ===
  slot=0 name=mcast-replicate-stream ingress=0 dst=239.1.1.1/32 targets=3:
    -> 10.10.1.1 via eth1 mac=00:00:00:00:00:00
    -> 10.10.2.1 via eth2 mac=00:00:00:00:00:00
    -> 10.10.3.1 via eth3 mac=00:00:00:00:00:00
```

### Show Interfaces

See which interfaces have rudder TC hooks attached:

```bash
sudo python3 rudder.py show interfaces
```

```
INTERFACE   IFINDEX   HOOK
eth0        2         yes (rudder)
eth1        3         yes (rudder)
eth2        4         yes (rudder)
eth3        5         no
```

### Live Trace

Stream real-time trace events for every matched packet. Each line shows the matched rule, event type, source/destination IPs, and egress interface:

```bash
sudo python3 rudder.py trace
```

```
Streaming trace events (Ctrl-C to stop)...
[12:04:33.441] rule_id=0    type=steer               src=10.1.1.5        orig_dst=10.2.2.1       new_dst=192.168.100.1   egress=eth2
[12:04:33.449] rule_id=0    type=replicate_clone      src=10.1.1.9        orig_dst=239.1.1.1      new_dst=10.10.1.1       egress=eth1
[12:04:33.449] rule_id=0    type=replicate_clone      src=10.1.1.9        orig_dst=239.1.1.1      new_dst=10.10.2.1       egress=eth2
[12:04:33.449] rule_id=0    type=replicate_final      src=10.1.1.9        orig_dst=239.1.1.1      new_dst=10.10.3.1       egress=eth3
```

Press Ctrl-C to stop.

### Reload Rules

Update rules without detaching TC hooks. The engine re-populates the BPF maps in place and reports what changed:

```bash
sudo python3 rudder.py reload rules/updated_rules.yaml
```

```
Reloaded. Changes applied:
  MODIFIED  ef-to-path-a         action.via: eth2 -> eth3
  ADDED     be-to-path-b         priority=30
  REMOVED   old-rule             priority=50
```

### Stop

Detach all TC hooks, remove pinned BPF maps, and stop the daemon:

```bash
sudo python3 rudder.py stop
```

```
Rudder stopped.
```

You can verify cleanup with:

```bash
tc filter show dev eth0 ingress          # Should show no rudder filters
ls /sys/fs/bpf/rudder/ 2>/dev/null       # Directory should not exist
```

## Testing with Generated Traffic

The included packet generator uses Scapy to send crafted packets for validating rules.

### Test Steer Rules

Send 5 UDP packets with DSCP 46 to `10.0.0.1` on `eth0`, which should trigger the `ef-to-path-a` steer rule:

```bash
sudo python3 tests/gen_packets.py \
    --mode steer \
    --src-ip 10.1.1.5 \
    --dst-ip 10.0.0.1 \
    --dscp 46 \
    --iface eth0 \
    --count 5 \
    --proto udp
```

Then verify:

```bash
# Check hit counters incremented
sudo python3 rudder.py show stats

# Watch for rewritten packets on the egress interface
sudo tcpdump -i eth2 -n dst host 192.168.100.1
```

### Test Replicate Rules

Send 10 UDP packets to multicast group `239.1.1.1`:

```bash
sudo python3 tests/gen_packets.py \
    --mode replicate \
    --src-ip 10.1.1.9 \
    --dst-ip 239.1.1.1 \
    --iface eth0 \
    --count 10
```

Verify unicast copies appear on each target interface:

```bash
sudo tcpdump -i eth1 -n dst host 10.10.1.1 &
sudo tcpdump -i eth2 -n dst host 10.10.2.1 &
sudo tcpdump -i eth3 -n dst host 10.10.3.1 &
```

### Packet Generator Options

```
--mode        steer | replicate                    (required)
--src-ip      Source IP address                     (default: 10.0.0.1)
--dst-ip      Destination IP address                (required)
--dscp        DSCP value 0-63                       (default: 0)
--iface       Outgoing interface                    (required)
--count       Number of packets                     (default: 10)
--interval    Seconds between packets               (default: 0.1)
--proto       tcp | udp | icmp                      (default: udp)
```

## End-to-End Walkthrough

A full test cycle on a machine with `eth0`, `eth1`, `eth2`, and `eth3`:

```bash
# 1. Install dependencies
sudo apt-get install -y libbpf-dev linux-headers-$(uname -r) \
    linux-tools-generic clang llvm iproute2 tcpdump
pip3 install -r requirements.txt

# 2. Load steering and replication rules
sudo python3 rudder.py load rules/example_steer.yaml rules/example_replicate.yaml

# 3. Confirm TC hooks are attached
tc filter show dev eth0 ingress

# 4. Confirm BPF maps are pinned
ls /sys/fs/bpf/rudder/

# 5. Inspect map contents
sudo python3 rudder.py show maps

# 6. Start a trace in one terminal
sudo python3 rudder.py trace

# 7. In another terminal, send test traffic
sudo python3 tests/gen_packets.py --mode steer --dst-ip 10.0.0.1 --dscp 46 --iface eth0 --count 5

# 8. Check hit counters
sudo python3 rudder.py show stats

# 9. Watch for redirected packets
sudo tcpdump -i eth2 -n dst host 192.168.100.1

# 10. Clean up
sudo python3 rudder.py stop
```

## Kubernetes Deployment

A Dockerfile and K3s pod manifest are provided in `deploy/` for running rudder inside a container with Multus multi-interface support.

### Build and Deploy

```bash
docker build -t rudder:latest -f deploy/Dockerfile .
kubectl apply -f deploy/pod.yaml
kubectl exec -it rudder -- bash
```

The pod runs in privileged mode and mounts `/sys/fs/bpf`, `/lib/modules`, and `/usr/src` from the host. Multus `NetworkAttachmentDefinition` resources (`rudder-net1`, `rudder-net2`, `rudder-net3` in the manifest) must be created separately to match your cluster's network topology.

## Project Structure

```
rudder/
├── rudder.py                  # CLI entry point (click)
├── engine/
│   ├── __init__.py
│   ├── models.py              # Dataclasses: MatchSet, SteerAction, ReplicateAction, Rule
│   ├── loader.py              # YAML parsing, validation, priority sorting
│   ├── manager.py             # Compile, TC attach, map pinning, map population
│   ├── observer.py            # Stats, map dump, trace event formatting
│   ├── perf_reader.py         # ctypes-based perf event ring buffer reader
│   └── daemon.py              # Background daemon with Unix socket IPC
├── ebpf/
│   ├── maps.h                 # Shared struct definitions and constants
│   ├── steer.c                # TC classifier: DSCP/IP steering with redirect
│   └── replicate.c            # TC classifier: multicast-to-unicast replication
├── rules/
│   ├── example_steer.yaml     # Example DSCP steering rule
│   └── example_replicate.yaml # Example multicast replication rule
├── tests/
│   └── gen_packets.py         # Scapy packet generator for validation
├── deploy/
│   ├── Dockerfile             # Ubuntu 22.04 container with all dependencies
│   └── pod.yaml               # K3s pod manifest with Multus annotations
└── requirements.txt           # Python dependencies
```

## Limits

- Maximum 64 rules total (compile-time constant `MAX_RULES` in `ebpf/maps.h`)
- Maximum 12 replication targets per replicate rule (`MAX_TARGETS`)
- IPv4 only
- No stateful connection tracking
- No VLAN or QinQ support

## License

[MIT License](LICENSE)
