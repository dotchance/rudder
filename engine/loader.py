# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""YAML policy loader and validator.

The loader is intentionally strict at the edge of the system. It turns loosely
typed YAML into the Policy IR before anything reaches TC or eBPF map
serialization. Keeping validation here makes later config syntaxes easier:
future parsers should produce the same normalized `Policy` object.
"""

import re

import yaml
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from engine.models import (
    MAX_TARGETS, MatchSet, SteerAction,
    ReplicationTarget, ReplicateAction, Rule,
)
from engine.policy import BackendLimits, Policy


MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


class RuleValidationError(Exception):
    """Raised when a rule file contains invalid or conflicting definitions."""
    pass


def _fail(location: str, problem: str, hint: str | None = None):
    """Raise a validation error with a short explanation and optional hint."""
    message = f"{location}: {problem}"
    if hint:
        message += f"\nHint: {hint}"
    raise RuleValidationError(message)


def _reject_unknown_keys(raw: dict, allowed: set[str], location: str):
    """Reject misspelled or unsupported fields early.

    This is deliberately strict. A typo in YAML should not silently disappear
    before the policy is serialized into eBPF maps.
    """
    unknown = sorted(set(raw) - allowed)
    if unknown:
        fields = ", ".join(unknown)
        _fail(
            location,
            f"unknown field(s): {fields}",
            "Check the field spelling or add parser support before using a new policy field.",
        )


def _require_mapping(raw, location: str, hint: str) -> dict:
    """Return `raw` as a dict or explain why the section is malformed."""
    if not isinstance(raw, dict):
        _fail(location, "must be a mapping", hint)
    return raw


def _require_plain_int(raw: dict, key: str, location: str, hint: str) -> int:
    """Read an integer while rejecting booleans, which YAML treats specially."""
    if key not in raw:
        _fail(location, f"missing '{key}' field", hint)
    value = raw[key]
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(location, f"{key} must be an integer", hint)
    return value


def _require_non_empty_string(raw: dict, key: str, location: str, hint: str) -> str:
    """Read a required string and reject empty or whitespace-only values."""
    if key not in raw:
        _fail(location, f"missing '{key}' field", hint)
    value = raw[key]
    if not isinstance(value, str) or not value.strip():
        _fail(location, f"{key} must be a non-empty string", hint)
    if value != value.strip() or any(ord(ch) < 32 for ch in value):
        _fail(location, f"{key} must not contain leading, trailing, or control whitespace", hint)
    return value


def _parse_rule_name(raw: dict, file: str, index: int) -> str:
    """Parse the user-facing rule name."""
    location = f"{file}: rules[{index}]"
    name = _require_non_empty_string(
        raw,
        "name",
        location,
        "Rudder uses rule names in reload diffs, stats, and map dumps.",
    )
    if len(name) > 128:
        _fail(location, "name must be 128 characters or fewer")
    return name


def _parse_interface_name(value, location: str, allow_any: bool) -> str:
    """Validate a Linux interface name or the special match value `any`."""
    if not isinstance(value, str) or not value.strip():
        _fail(
            location,
            "must be a non-empty string",
            "Rudder resolves interface names to ifindexes before writing eBPF maps.",
        )
    if value == "any" and allow_any:
        return value
    if value == "any":
        _fail(
            location,
            "'any' is only valid for match.interface",
            "Actions need one concrete egress interface so bpf_redirect() has a target.",
        )
    if value != value.strip() or any(ch.isspace() for ch in value):
        _fail(location, "must not contain whitespace")
    if "\x00" in value or "/" in value:
        _fail(location, "must not contain NUL bytes or '/'")
    if len(value.encode("utf-8")) > 15:
        _fail(
            location,
            "must be 15 bytes or fewer",
            "Linux interface names are limited by IFNAMSIZ; Rudder validates this before TC setup.",
        )
    return value


def _parse_mac(value, location: str) -> str | None:
    """Validate and normalize an optional Ethernet destination MAC."""
    if value is None:
        return None
    if not isinstance(value, str) or not MAC_RE.match(value):
        _fail(
            location,
            "must be a MAC address like aa:bb:cc:dd:ee:ff",
            "Rudder writes these six bytes into the eBPF action; malformed MACs would corrupt rewrites.",
        )
    return value.lower()


def _parse_ipv4_network(value, location: str) -> IPv4Network:
    """Parse an IPv4 network or host value used by rule matching."""
    if not isinstance(value, str):
        _fail(
            location,
            "must be an IPv4 address or CIDR string",
            "The current eBPF map layout stores IPv4 addresses as four-byte fields.",
        )
    try:
        return IPv4Network(value, strict=False)
    except ValueError as e:
        _fail(
            location,
            str(e),
            "Rudder currently supports IPv4 policy fields; IPv6 needs a future map layout.",
        )


def _parse_ipv4_address(value, location: str) -> IPv4Address:
    """Parse an exact IPv4 address used for packet rewrite destinations."""
    if not isinstance(value, str):
        _fail(
            location,
            "must be an exact IPv4 address string",
            "Actions rewrite a packet destination to one concrete IPv4 address.",
        )
    try:
        return IPv4Address(value)
    except ValueError as e:
        _fail(location, f"must be an exact IPv4 address, not CIDR: {e}")


def _parse_match(raw: dict, file: str, name: str) -> MatchSet:
    """Parse the `match` section for a rule.

    Missing IP/DSCP/protocol fields mean "match any" and are represented as
    `None` or `"any"` until the manager converts them to eBPF map sentinels.
    """
    location = f"{file}: rule '{name}': match"
    raw = _require_mapping(
        raw,
        location,
        "Use match: with indented fields such as interface, dst_ip, dscp, and ip_proto.",
    )
    _reject_unknown_keys(raw, {"interface", "src_ip", "dst_ip", "dscp", "ip_proto"}, location)

    if "interface" not in raw:
        _fail(
            location,
            "interface is required",
            "Rudder needs to know which TC ingress hook should receive the rule; use 'any' to attach broadly.",
        )
    iface = _parse_interface_name(raw["interface"], f"{location}.interface", allow_any=True)

    src_ip = None
    if "src_ip" in raw:
        src_ip = _parse_ipv4_network(raw["src_ip"], f"{location}.src_ip")

    dst_ip = None
    if "dst_ip" in raw:
        dst_ip = _parse_ipv4_network(raw["dst_ip"], f"{location}.dst_ip")

    dscp = None
    if "dscp" in raw:
        dscp = raw["dscp"]
        if not isinstance(dscp, int) or isinstance(dscp, bool) or dscp < 0 or dscp > 63:
            _fail(
                f"{location}.dscp",
                "must be an integer 0-63",
                "DSCP is the six-bit differentiated services field, not the full IPv4 TOS byte.",
            )

    ip_proto = raw.get("ip_proto", "any")
    if not isinstance(ip_proto, str) or ip_proto not in ("any", "tcp", "udp"):
        _fail(
            f"{location}.ip_proto",
            "must be 'any', 'tcp', or 'udp'",
            "The current eBPF programs only parse TCP and UDP transport headers.",
        )

    return MatchSet(
        interface=iface,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dscp=dscp,
        ip_proto=ip_proto,
    )


def _parse_steer_action(raw: dict, file: str, name: str) -> SteerAction:
    """Parse a steer action into an exact destination and egress interface."""
    location = f"{file}: rule '{name}': action"
    raw = _require_mapping(
        raw,
        location,
        "A steer action needs dst_ip, via, and optional next_hop_mac fields.",
    )
    _reject_unknown_keys(raw, {"dst_ip", "via", "next_hop_mac"}, location)

    if "dst_ip" not in raw:
        _fail(
            location,
            "dst_ip is required for steer rules",
            "Steer rewrites the packet destination to one exact IPv4 address.",
        )
    dst_ip = _parse_ipv4_address(raw["dst_ip"], f"{location}.dst_ip")

    if "via" not in raw:
        _fail(location, "via is required for steer rules")
    via = _parse_interface_name(raw["via"], f"{location}.via", allow_any=False)

    return SteerAction(
        dst_ip=dst_ip,
        via=via,
        next_hop_mac=_parse_mac(raw.get("next_hop_mac"), f"{location}.next_hop_mac"),
    )


def _parse_replicate_action(raw: dict, file: str, name: str) -> ReplicateAction:
    """Parse replicate targets and enforce the eBPF map target limit."""
    location = f"{file}: rule '{name}': action"
    raw = _require_mapping(
        raw,
        location,
        "A replicate action needs targets: with one or more destination entries.",
    )
    _reject_unknown_keys(raw, {"targets"}, location)

    if "targets" not in raw:
        _fail(
            location,
            "targets is required for replicate rules",
            "Replicate needs at least one unicast output to clone packets toward.",
        )
    targets_raw = raw["targets"]
    if not isinstance(targets_raw, list) or len(targets_raw) < 1:
        _fail(
            f"{location}.targets",
            "must be a list with at least 1 entry",
            "Each target becomes one rewritten packet copy in the eBPF replicate program.",
        )
    if len(targets_raw) > MAX_TARGETS:
        _fail(
            f"{location}.targets",
            f"exceeds maximum of {MAX_TARGETS}",
            "The current eBPF map value has a fixed-size target array.",
        )

    targets = []
    seen_targets: set[tuple[str, str]] = set()
    for i, t in enumerate(targets_raw):
        target_location = f"{location}.targets[{i}]"
        t = _require_mapping(
            t,
            target_location,
            "Each target must be a mapping with dst_ip, via, and optional next_hop_mac.",
        )
        _reject_unknown_keys(t, {"dst_ip", "via", "next_hop_mac"}, target_location)
        if "dst_ip" not in t:
            _fail(
                target_location,
                "dst_ip is required",
                "Each clone needs one exact destination IPv4 address.",
            )
        dst_ip = _parse_ipv4_address(t["dst_ip"], f"{target_location}.dst_ip")
        if "via" not in t:
            _fail(target_location, "via is required")
        via = _parse_interface_name(t["via"], f"{target_location}.via", allow_any=False)
        target_key = (str(dst_ip), via)
        if target_key in seen_targets:
            _fail(
                target_location,
                f"duplicates target {dst_ip} via {via}",
                "Duplicate replicate targets waste map slots and produce duplicate packet copies.",
            )
        seen_targets.add(target_key)
        targets.append(ReplicationTarget(
            dst_ip=dst_ip,
            via=via,
            next_hop_mac=_parse_mac(t.get("next_hop_mac"), f"{target_location}.next_hop_mac"),
        ))

    return ReplicateAction(targets=targets)


def load_policy(paths: list[str], limits: BackendLimits | None = None) -> Policy:
    """Load YAML files into a validated Policy IR.

    Rules are sorted by priority and assigned per-type slot ids after every
    file has been parsed, because duplicate names/priorities are policy-wide
    errors rather than per-file errors.
    """
    limits = limits or BackendLimits()
    all_raw = []
    source_files = []

    for path in paths:
        p = Path(path)
        if not p.exists():
            raise RuleValidationError(f"Rule file not found: {path}")
        source_files.append(str(p))
        with open(p, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if not isinstance(doc, dict):
            _fail(
                str(p),
                "rule file must be a YAML mapping with a top-level 'rules' key",
                "Use rules: followed by a list of rule mappings.",
            )
        _reject_unknown_keys(doc, {"rules"}, str(p))
        if "rules" not in doc:
            _fail(str(p), "missing top-level 'rules' key")
        if not isinstance(doc["rules"], list):
            _fail(
                f"{p}: rules",
                "must be a list",
                "Use '- name: ...' entries under the rules key.",
            )
        for index, r in enumerate(doc["rules"]):
            all_raw.append((r, str(p), index))

    if not all_raw:
        _fail(
            "policy",
            "must contain at least one rule",
            "Initial load needs at least one ingress attachment so TC/eBPF maps can be created.",
        )

    # Validate individual rules and build Rule objects. `rule_id` is assigned
    # after sorting so slot numbers match priority order within each eBPF map.
    rules = []
    for raw, file, index in all_raw:
        raw = _require_mapping(
            raw,
            f"{file}: rules[{index}]",
            "Each rule must be a mapping with name, priority, type, match, and action.",
        )
        _reject_unknown_keys(raw, {"name", "priority", "type", "match", "action"},
                             f"{file}: rules[{index}]")

        name = _parse_rule_name(raw, file, index)
        rule_location = f"{file}: rule '{name}'"

        priority = _require_plain_int(
            raw,
            "priority",
            rule_location,
            "Priority controls rule order; lower numbers are evaluated first.",
        )
        if priority < 0:
            _fail(rule_location, "priority must be 0 or greater")

        rtype = _require_non_empty_string(
            raw,
            "type",
            rule_location,
            "Use 'steer' or 'replicate' so Rudder knows which eBPF map receives the rule.",
        )
        if rtype not in limits.supported_rule_types:
            supported = "', '".join(limits.supported_rule_types)
            _fail(
                rule_location,
                f"type must be '{supported}'",
                "The current backend has one eBPF program/map layout per supported rule type.",
            )

        if "match" not in raw:
            _fail(rule_location, "missing 'match' section")
        match = _parse_match(raw["match"], file, name)

        if "action" not in raw:
            _fail(rule_location, "missing 'action' section")

        if rtype == "steer":
            action = _parse_steer_action(raw["action"], file, name)
        else:
            action = _parse_replicate_action(raw["action"], file, name)

        rules.append(Rule(
            name=name,
            priority=priority,
            rule_id=-1,  # assigned below
            type=rtype,
            match=match,
            action=action,
            source_file=file,
        ))

    if len(rules) > limits.max_rules:
        _fail(
            "policy",
            f"total rule count ({len(rules)}) exceeds maximum of {limits.max_rules}",
            "The current teaching backend keeps one bounded rule loop size across policy types.",
        )

    # Check for duplicate priorities
    prio_map: dict[int, Rule] = {}
    for r in rules:
        if r.priority in prio_map:
            other = prio_map[r.priority]
            _fail(
                "policy",
                f"Duplicate priority {r.priority}: "
                f"'{r.name}' ({r.source_file}) and "
                f"'{other.name}' ({other.source_file})",
                "Priorities must be unique so reload diffs and eBPF slot assignment stay predictable.",
            )
        prio_map[r.priority] = r

    # Check for duplicate names
    name_map: dict[str, Rule] = {}
    for r in rules:
        if r.name in name_map:
            other = name_map[r.name]
            _fail(
                "policy",
                f"Duplicate rule name '{r.name}': "
                f"({r.source_file}) and ({other.source_file})",
                "Rule names are used for CLI output, stats, and reload change reports.",
            )
        name_map[r.name] = r

    # Sort by priority ascending
    rules.sort(key=lambda r: r.priority)

    # Assign per-type rule_id as slot index within that type's eBPF map
    steer_idx = 0
    replicate_idx = 0
    for r in rules:
        if r.type == "steer":
            r.rule_id = steer_idx
            steer_idx += 1
        else:
            r.rule_id = replicate_idx
            replicate_idx += 1

    return Policy(rules=rules, source_files=tuple(source_files), limits=limits)


def load_rules(paths: list[str]) -> list[Rule]:
    """Compatibility wrapper returning the rules from `load_policy()`."""
    return load_policy(paths).rules
