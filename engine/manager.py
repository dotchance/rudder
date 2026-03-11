import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
from ipaddress import IPv4Address
from pathlib import Path

from engine.models import MAX_RULES, MAX_TARGETS, Rule, SteerAction, ReplicateAction


BPF_PIN_DIR = "/sys/fs/bpf/rudder"
STEER_OBJ = "/tmp/rudder_steer.o"
REPLICATE_OBJ = "/tmp/rudder_replicate.o"

# Struct format for steer_rule matching C layout:
#   valid(u32) rule_id(u32) ingress_ifindex(u32)
#   src_ip(4s) src_prefix_len(u32) dst_ip(4s) dst_prefix_len(u32)
#   dscp(u8) ip_proto(u8) pad(2x)
#   new_dst_ip(4s) egress_ifindex(u32) dst_mac(6s) action_pad(2x)
STEER_RULE_FMT = "=III4sI4sIBB2x4sI6s2x"

# Struct format for replicate_target:
#   dst_ip(4s) egress_ifindex(u32) dst_mac(6s) pad(2x)
REPLICATE_TARGET_FMT = "=4sI6s2x"

# Struct format for replicate_rule header (before targets array):
#   valid(u32) rule_id(u32) ingress_ifindex(u32)
#   dst_ip(4s) dst_prefix_len(u32) pad(4x) target_count(u32)
REPLICATE_RULE_HDR_FMT = "=III4sI4xI"


def _check_kernel_version():
    """Verify kernel is 5.15+ for bounded loop support."""
    release = platform.release()
    parts = release.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except (IndexError, ValueError):
        print(f"WARNING: Could not parse kernel version from '{release}', proceeding anyway")
        return
    if (major, minor) < (5, 15):
        print(f"Kernel {major}.{minor} detected. Rudder requires kernel 5.15 or later.")
        sys.exit(1)


def _mac_to_bytes(mac_str: str | None) -> bytes:
    """Convert 'aa:bb:cc:dd:ee:ff' to 6 bytes, or return zeros."""
    if not mac_str:
        return b"\x00" * 6
    parts = mac_str.split(":")
    return bytes(int(p, 16) for p in parts)


def _ip_to_bytes(ip) -> bytes:
    """Convert IPv4Address to 4 bytes in network order."""
    return socket.inet_aton(str(ip))


def _run(cmd: list[str], check=True, capture=True) -> subprocess.CompletedProcess:
    """Run a subprocess command, printing it for transparency."""
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
    )
    if check and result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else "(no output)"
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{stderr}")
    return result


def _bpftool_json(args: list[str]) -> list | dict:
    """Run bpftool with --json and parse output."""
    result = subprocess.run(
        ["bpftool"] + args + ["--json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"bpftool failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


class PolicyManager:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._attached_interfaces: list[str] = []
        self._ifindex_cache: dict[str, int] = {}

    def load(self):
        """Full load sequence: check kernel, resolve interfaces, compile, attach, pin, populate."""
        _check_kernel_version()
        self._resolve_interfaces()
        self._resolve_macs()
        self._compile()
        try:
            self._attach_tc_hooks()
        except Exception:
            self._detach_all()
            raise
        try:
            self._pin_maps()
        except Exception:
            self._detach_all()
            raise
        self._populate_maps()

    def unload(self):
        """Detach TC hooks and remove pinned maps."""
        self._detach_all()
        # Remove pinned map files
        pin_dir = Path(BPF_PIN_DIR)
        if pin_dir.exists():
            shutil.rmtree(pin_dir, ignore_errors=True)
        self._attached_interfaces.clear()

    def update_maps(self, rules: list[Rule]):
        """Re-populate BPF maps without TC re-attachment."""
        self.rules = rules
        self._resolve_interfaces()
        self._resolve_macs()
        self._populate_maps()

    def get_interfaces(self) -> dict[str, int]:
        """Return all non-loopback interfaces with ifindex."""
        result = {}
        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo":
                continue
            try:
                result[name] = socket.if_nametoindex(name)
            except OSError:
                pass
        return result

    def get_attached_interfaces(self) -> list[str]:
        return list(self._attached_interfaces)

    def _resolve_interfaces(self):
        """Resolve all interface names referenced in rules to ifindex."""
        needed = set()
        for r in self.rules:
            if r.match.interface != "any":
                needed.add(r.match.interface)
            if isinstance(r.action, SteerAction):
                needed.add(r.action.via)
            elif isinstance(r.action, ReplicateAction):
                for t in r.action.targets:
                    needed.add(t.via)

        for name in needed:
            try:
                self._ifindex_cache[name] = socket.if_nametoindex(name)
            except OSError:
                raise RuntimeError(f"Interface not found: {name}")

    def _resolve_macs(self):
        """Resolve next_hop_mac via ARP for any rules that don't have it set."""
        try:
            from pyroute2 import IPRoute
        except ImportError:
            print("WARNING: pyroute2 not available, skipping ARP resolution")
            return

        ipr = IPRoute()
        try:
            neighbours = ipr.get_neighbours()
        finally:
            ipr.close()

        # Build lookup: (ifindex, ip) -> mac
        arp_table: dict[tuple[int, str], str] = {}
        for neigh in neighbours:
            attrs = dict(neigh.get("attrs", neigh.get("attrs", [])))
            dst = attrs.get("NDA_DST")
            lladdr = attrs.get("NDA_LLADDR")
            ifidx = neigh.get("ifindex")
            if dst and lladdr and ifidx:
                arp_table[(ifidx, dst)] = lladdr

        for r in self.rules:
            if isinstance(r.action, SteerAction) and not r.action.next_hop_mac:
                via_idx = self._ifindex_cache.get(r.action.via, 0)
                mac = arp_table.get((via_idx, str(r.action.dst_ip)))
                if mac:
                    r.action.next_hop_mac = mac
                else:
                    print(f"WARNING: No ARP entry for {r.action.dst_ip} on {r.action.via}. "
                          f"Using zero MAC — forwarding will be incorrect until ARP resolves.")
            elif isinstance(r.action, ReplicateAction):
                for t in r.action.targets:
                    if not t.next_hop_mac:
                        via_idx = self._ifindex_cache.get(t.via, 0)
                        mac = arp_table.get((via_idx, str(t.dst_ip)))
                        if mac:
                            t.next_hop_mac = mac
                        else:
                            print(f"WARNING: No ARP entry for {t.dst_ip} on {t.via}. "
                                  f"Using zero MAC.")

    def _compile(self):
        """Compile eBPF programs with clang."""
        ebpf_dir = Path(__file__).resolve().parent.parent / "ebpf"
        for src, obj in [("steer.c", STEER_OBJ), ("replicate.c", REPLICATE_OBJ)]:
            cmd = [
                "clang", "-O2", "-g", "-target", "bpf",
                "-I/usr/include",
                "-I/usr/include/x86_64-linux-gnu",
                "-c", str(ebpf_dir / src),
                "-o", obj,
            ]
            try:
                _run(cmd)
            except RuntimeError as e:
                print(f"Compilation failed for {src}:")
                print(str(e))
                sys.exit(1)

    def _get_unique_interfaces(self) -> list[str]:
        """Get all unique interfaces that need TC hooks."""
        ifaces = set()
        for r in self.rules:
            if r.match.interface == "any":
                # Attach to all non-loopback interfaces
                for name in os.listdir("/sys/class/net"):
                    if name != "lo":
                        ifaces.add(name)
            else:
                ifaces.add(r.match.interface)
        return sorted(ifaces)

    def _attach_tc_hooks(self):
        """Attach TC ingress hooks to all required interfaces."""
        interfaces = self._get_unique_interfaces()
        print("Attaching TC hooks:")

        for iface in interfaces:
            # Create clsact qdisc (idempotent)
            subprocess.run(
                ["tc", "qdisc", "add", "dev", iface, "clsact"],
                capture_output=True, text=True,
            )

            # Attach steer program
            cmd = ["tc", "filter", "add", "dev", iface, "ingress",
                   "bpf", "da", "obj", STEER_OBJ, "sec", "classifier"]
            result = _run(cmd, check=False)
            if result.returncode != 0:
                stderr = result.stderr.strip() if result.stderr else "(no output)"
                print(f"  FAILED attaching steer to {iface}: {stderr}")
                raise RuntimeError(f"TC attachment failed for {iface}")

            # Attach replicate program
            cmd = ["tc", "filter", "add", "dev", iface, "ingress",
                   "bpf", "da", "obj", REPLICATE_OBJ, "sec", "classifier"]
            result = _run(cmd, check=False)
            if result.returncode != 0:
                stderr = result.stderr.strip() if result.stderr else "(no output)"
                print(f"  FAILED attaching replicate to {iface}: {stderr}")
                raise RuntimeError(f"TC attachment failed for {iface}")

            self._attached_interfaces.append(iface)
            print(f"  [ok] {iface}  ingress")

    def _detach_all(self):
        """Detach TC hooks from all attached interfaces."""
        for iface in self._attached_interfaces:
            subprocess.run(
                ["tc", "qdisc", "del", "dev", iface, "clsact"],
                capture_output=True, text=True,
            )
            print(f"  Detached {iface}")
        self._attached_interfaces.clear()

    def _pin_maps(self):
        """Pin BPF maps to /sys/fs/bpf/rudder/ for userspace access."""
        os.makedirs(BPF_PIN_DIR, exist_ok=True)

        # Map names expected from each program
        steer_maps = ["steer_rules", "steer_hit_counters", "steer_trace_events"]
        replicate_maps = ["replicate_rules", "replicate_hit_counters", "replicate_trace_events"]

        all_maps = _bpftool_json(["map", "show"])

        for map_name in steer_maps + replicate_maps:
            map_id = None
            for m in all_maps:
                if m.get("name") == map_name:
                    map_id = m["id"]
                    break
            if map_id is None:
                raise RuntimeError(f"Could not find BPF map '{map_name}' after TC load")
            pin_path = f"{BPF_PIN_DIR}/{map_name}"
            if not os.path.exists(pin_path):
                _run(["bpftool", "map", "pin", "id", str(map_id), pin_path])

    def _populate_maps(self):
        """Write rule data into pinned BPF maps."""
        steer_rules = [r for r in self.rules if r.type == "steer"]
        replicate_rules = [r for r in self.rules if r.type == "replicate"]

        # Populate steer rules
        for r in steer_rules:
            self._write_steer_rule(r)

        # Zero-fill unused steer slots
        for i in range(len(steer_rules), MAX_RULES):
            self._zero_steer_slot(i)

        # Populate replicate rules
        for r in replicate_rules:
            self._write_replicate_rule(r)

        # Zero-fill unused replicate slots
        for i in range(len(replicate_rules), MAX_RULES):
            self._zero_replicate_slot(i)

        # Zero-fill all hit counter slots
        for i in range(MAX_RULES):
            self._zero_counter("steer_hit_counters", i)
            self._zero_counter("replicate_hit_counters", i)

    def _write_steer_rule(self, rule: Rule):
        """Serialize and write a steer rule to the pinned map."""
        action = rule.action
        assert isinstance(action, SteerAction)

        match = rule.match
        ingress_idx = 0
        if match.interface != "any":
            ingress_idx = self._ifindex_cache[match.interface]

        src_ip = b"\x00\x00\x00\x00"
        src_prefix = 0
        if match.src_ip is not None:
            src_ip = match.src_ip.network_address.packed
            src_prefix = match.src_ip.prefixlen

        dst_ip = b"\x00\x00\x00\x00"
        dst_prefix = 0
        if match.dst_ip is not None:
            dst_ip = match.dst_ip.network_address.packed
            dst_prefix = match.dst_ip.prefixlen

        dscp = 0xFF if match.dscp is None else match.dscp
        ip_proto = 0
        if match.ip_proto == "tcp":
            ip_proto = 6
        elif match.ip_proto == "udp":
            ip_proto = 17

        new_dst_ip = _ip_to_bytes(action.dst_ip)
        egress_idx = self._ifindex_cache[action.via]
        dst_mac = _mac_to_bytes(action.next_hop_mac)

        value = struct.pack(
            STEER_RULE_FMT,
            1,               # valid
            rule.rule_id,
            ingress_idx,
            src_ip,
            src_prefix,
            dst_ip,
            dst_prefix,
            dscp,
            ip_proto,
            # 2x pad implicit
            new_dst_ip,
            egress_idx,
            dst_mac,
            # 2x action_pad implicit
        )

        self._bpftool_map_update("steer_rules", rule.rule_id, value)

    def _write_replicate_rule(self, rule: Rule):
        """Serialize and write a replicate rule to the pinned map."""
        action = rule.action
        assert isinstance(action, ReplicateAction)

        match = rule.match
        ingress_idx = 0
        if match.interface != "any":
            ingress_idx = self._ifindex_cache[match.interface]

        dst_ip = b"\x00\x00\x00\x00"
        dst_prefix = 0
        if match.dst_ip is not None:
            dst_ip = match.dst_ip.network_address.packed
            dst_prefix = match.dst_ip.prefixlen

        # Pack header
        hdr = struct.pack(
            REPLICATE_RULE_HDR_FMT,
            1,               # valid
            rule.rule_id,
            ingress_idx,
            dst_ip,
            dst_prefix,
            # 4x pad implicit
            len(action.targets),
        )

        # Pack targets
        targets_data = b""
        for t in action.targets:
            targets_data += struct.pack(
                REPLICATE_TARGET_FMT,
                _ip_to_bytes(t.dst_ip),
                self._ifindex_cache[t.via],
                _mac_to_bytes(t.next_hop_mac),
            )

        # Pad remaining target slots with zeros
        target_size = struct.calcsize(REPLICATE_TARGET_FMT)
        for _ in range(len(action.targets), MAX_TARGETS):
            targets_data += b"\x00" * target_size

        value = hdr + targets_data
        self._bpftool_map_update("replicate_rules", rule.rule_id, value)

    def _zero_steer_slot(self, slot: int):
        """Write an all-zeros entry to a steer_rules slot."""
        size = struct.calcsize(STEER_RULE_FMT)
        self._bpftool_map_update("steer_rules", slot, b"\x00" * size)

    def _zero_replicate_slot(self, slot: int):
        """Write an all-zeros entry to a replicate_rules slot."""
        hdr_size = struct.calcsize(REPLICATE_RULE_HDR_FMT)
        target_size = struct.calcsize(REPLICATE_TARGET_FMT)
        total = hdr_size + target_size * MAX_TARGETS
        self._bpftool_map_update("replicate_rules", slot, b"\x00" * total)

    def _zero_counter(self, map_name: str, slot: int):
        """Zero a hit counter slot."""
        self._bpftool_map_update(map_name, slot, b"\x00" * 8)

    def _bpftool_map_update(self, map_name: str, key_int: int, value_bytes: bytes):
        """Write a value to a pinned BPF map using bpftool."""
        pin_path = f"{BPF_PIN_DIR}/{map_name}"
        key_hex = " ".join(f"0x{b:02x}" for b in key_int.to_bytes(4, "little"))
        val_hex = " ".join(f"0x{b:02x}" for b in value_bytes)
        cmd = ["bpftool", "map", "update", "pinned", pin_path,
               "key", *key_hex.split(), "value", *val_hex.split()]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"bpftool map update failed for {map_name}[{key_int}]: "
                f"{result.stderr.strip()}"
            )
