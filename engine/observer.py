import json
import socket
import struct
import subprocess
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path

from engine.models import MAX_RULES, Rule
from engine.manager import BPF_PIN_DIR, STEER_RULE_FMT, REPLICATE_RULE_HDR_FMT, REPLICATE_TARGET_FMT
from engine.perf_reader import PerfReader, TRACE_EVENT_SIZE


EVENT_TYPE_NAMES = {0: "steer", 1: "replicate_clone", 2: "replicate_final"}


def _bpftool_dump(map_name: str) -> list:
    """Dump a pinned BPF map as JSON."""
    pin_path = f"{BPF_PIN_DIR}/{map_name}"
    result = subprocess.run(
        ["bpftool", "map", "dump", "pinned", pin_path, "--json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"bpftool dump failed for {map_name}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def _ifindex_to_name(ifindex: int) -> str:
    """Convert ifindex to interface name, or return the index as string."""
    try:
        return socket.if_indextoname(ifindex)
    except OSError:
        return str(ifindex)


def _ip_from_bytes(raw: bytes) -> str:
    """Convert 4 bytes in network order to dotted decimal."""
    return str(IPv4Address(raw))


def _ip_from_int(val: int) -> str:
    """Convert a 32-bit integer (as stored in network order) to dotted IP."""
    return str(IPv4Address(val.to_bytes(4, "big")))


def _mac_from_bytes(raw: bytes) -> str:
    """Convert 6 bytes to colon-hex MAC string."""
    return ":".join(f"{b:02x}" for b in raw)


class Observer:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self._rule_name_map: dict[tuple[str, int], str] = {}
        for r in rules:
            self._rule_name_map[(r.type, r.rule_id)] = r.name

    def dump_stats(self) -> list[dict]:
        """Read hit counters for all active rules."""
        results = []

        for map_name, rtype in [("steer_hit_counters", "steer"),
                                 ("replicate_hit_counters", "replicate")]:
            try:
                entries = _bpftool_dump(map_name)
            except RuntimeError:
                continue

            for entry in entries:
                key_bytes = bytes(entry.get("key", []))
                val_bytes = bytes(entry.get("value", []))
                if len(key_bytes) < 4 or len(val_bytes) < 8:
                    continue
                slot = int.from_bytes(key_bytes, "little")
                hits = int.from_bytes(val_bytes, "little")
                if hits == 0:
                    continue

                name = self._rule_name_map.get((rtype, slot), f"unknown-{slot}")
                rule = next((r for r in self.rules
                            if r.type == rtype and r.rule_id == slot), None)
                priority = rule.priority if rule else -1

                results.append({
                    "name": name,
                    "priority": priority,
                    "type": rtype,
                    "hits": hits,
                })

        results.sort(key=lambda x: x["priority"])
        return results

    def dump_maps(self) -> dict:
        """Dump all active rules from BPF maps in human-readable form."""
        result = {"steer": [], "replicate": []}

        # Dump steer rules
        try:
            entries = _bpftool_dump("steer_rules")
        except RuntimeError:
            entries = []

        for entry in entries:
            val_bytes = bytes(entry.get("value", []))
            expected_size = struct.calcsize(STEER_RULE_FMT)
            if len(val_bytes) < expected_size:
                continue

            fields = struct.unpack(STEER_RULE_FMT, val_bytes[:expected_size])
            valid = fields[0]
            if not valid:
                continue

            rule_id = fields[1]
            name = self._rule_name_map.get(("steer", rule_id), f"steer-{rule_id}")

            result["steer"].append({
                "slot": rule_id,
                "name": name,
                "valid": valid,
                "rule_id": rule_id,
                "ingress_ifindex": _ifindex_to_name(fields[2]),
                "src_ip": _ip_from_bytes(fields[3]),
                "src_prefix_len": fields[4],
                "dst_ip": _ip_from_bytes(fields[5]),
                "dst_prefix_len": fields[6],
                "dscp": fields[7],
                "ip_proto": fields[8],
                "new_dst_ip": _ip_from_bytes(fields[9]),
                "egress_ifindex": _ifindex_to_name(fields[10]),
                "dst_mac": _mac_from_bytes(fields[11]),
            })

        # Dump replicate rules
        try:
            entries = _bpftool_dump("replicate_rules")
        except RuntimeError:
            entries = []

        hdr_size = struct.calcsize(REPLICATE_RULE_HDR_FMT)
        target_size = struct.calcsize(REPLICATE_TARGET_FMT)

        for entry in entries:
            val_bytes = bytes(entry.get("value", []))
            if len(val_bytes) < hdr_size:
                continue

            hdr = struct.unpack(REPLICATE_RULE_HDR_FMT, val_bytes[:hdr_size])
            valid = hdr[0]
            if not valid:
                continue

            rule_id = hdr[1]
            name = self._rule_name_map.get(("replicate", rule_id), f"replicate-{rule_id}")
            target_count = hdr[5]

            targets = []
            for t in range(min(target_count, 12)):
                offset = hdr_size + t * target_size
                if offset + target_size > len(val_bytes):
                    break
                tf = struct.unpack(REPLICATE_TARGET_FMT,
                                   val_bytes[offset:offset + target_size])
                targets.append({
                    "dst_ip": _ip_from_bytes(tf[0]),
                    "egress_ifindex": _ifindex_to_name(tf[1]),
                    "dst_mac": _mac_from_bytes(tf[2]),
                })

            result["replicate"].append({
                "slot": rule_id,
                "name": name,
                "valid": valid,
                "rule_id": rule_id,
                "ingress_ifindex": _ifindex_to_name(hdr[2]),
                "dst_ip": _ip_from_bytes(hdr[3]),
                "dst_prefix_len": hdr[4],
                "target_count": target_count,
                "targets": targets,
            })

        return result

    def poll_trace(self, callback, timeout_ms: int = 100):
        """Poll perf buffers for trace events and invoke callback with formatted strings."""
        for map_name in ["steer_trace_events", "replicate_trace_events"]:
            pin_path = f"{BPF_PIN_DIR}/{map_name}"
            if not Path(pin_path).exists():
                continue

            reader = PerfReader(pin_path)
            try:
                reader.open()

                def _handle_event(parsed):
                    ts_ns, rule_id, src_ip, orig_dst, new_dst, egress_idx, etype = parsed
                    ts = datetime.fromtimestamp(ts_ns / 1e9)
                    ts_str = ts.strftime("%H:%M:%S.%f")[:-3]

                    etype_name = EVENT_TYPE_NAMES.get(etype, f"unknown({etype})")
                    rtype = "steer" if "steer" in map_name else "replicate"
                    rname = self._rule_name_map.get((rtype, rule_id), f"rule-{rule_id}")
                    egress_name = _ifindex_to_name(egress_idx)

                    line = (
                        f"[{ts_str}] rule={rname:<20s} type={etype_name:<20s} "
                        f"src={_ip_from_int(src_ip):<15s} "
                        f"orig_dst={_ip_from_int(orig_dst):<15s} "
                        f"new_dst={_ip_from_int(new_dst):<15s} "
                        f"egress={egress_name}"
                    )
                    callback(line)

                reader.poll(_handle_event, timeout_ms)
            finally:
                reader.close()
