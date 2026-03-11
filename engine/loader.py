import yaml
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from engine.models import (
    MAX_RULES, MAX_TARGETS, MatchSet, SteerAction,
    ReplicationTarget, ReplicateAction, Rule,
)


class RuleValidationError(Exception):
    """Raised when a rule file contains invalid or conflicting definitions."""
    pass


def _parse_match(raw: dict, file: str, name: str) -> MatchSet:
    if "interface" not in raw:
        raise RuleValidationError(
            f"{file}: rule '{name}': match.interface is required"
        )
    iface = raw["interface"]
    if not isinstance(iface, str) or not iface:
        raise RuleValidationError(
            f"{file}: rule '{name}': match.interface must be a non-empty string"
        )

    src_ip = None
    if "src_ip" in raw:
        try:
            src_ip = IPv4Network(raw["src_ip"], strict=False)
        except ValueError as e:
            raise RuleValidationError(
                f"{file}: rule '{name}': match.src_ip: {e}"
            )

    dst_ip = None
    if "dst_ip" in raw:
        try:
            dst_ip = IPv4Network(raw["dst_ip"], strict=False)
        except ValueError as e:
            raise RuleValidationError(
                f"{file}: rule '{name}': match.dst_ip: {e}"
            )

    dscp = None
    if "dscp" in raw:
        dscp = raw["dscp"]
        if not isinstance(dscp, int) or dscp < 0 or dscp > 63:
            raise RuleValidationError(
                f"{file}: rule '{name}': match.dscp must be an integer 0-63"
            )

    ip_proto = raw.get("ip_proto", "any")
    if ip_proto not in ("any", "tcp", "udp"):
        raise RuleValidationError(
            f"{file}: rule '{name}': match.ip_proto must be 'any', 'tcp', or 'udp'"
        )

    return MatchSet(
        interface=str(iface),
        src_ip=src_ip,
        dst_ip=dst_ip,
        dscp=dscp,
        ip_proto=ip_proto,
    )


def _parse_steer_action(raw: dict, file: str, name: str) -> SteerAction:
    if "dst_ip" not in raw:
        raise RuleValidationError(
            f"{file}: rule '{name}': action.dst_ip is required for steer rules"
        )
    try:
        dst_ip = IPv4Address(raw["dst_ip"])
    except ValueError as e:
        raise RuleValidationError(
            f"{file}: rule '{name}': action.dst_ip must be an exact IP, not CIDR: {e}"
        )

    if "via" not in raw:
        raise RuleValidationError(
            f"{file}: rule '{name}': action.via is required for steer rules"
        )

    return SteerAction(
        dst_ip=dst_ip,
        via=raw["via"],
        next_hop_mac=raw.get("next_hop_mac"),
    )


def _parse_replicate_action(raw: dict, file: str, name: str) -> ReplicateAction:
    if "targets" not in raw:
        raise RuleValidationError(
            f"{file}: rule '{name}': action.targets is required for replicate rules"
        )
    targets_raw = raw["targets"]
    if not isinstance(targets_raw, list) or len(targets_raw) < 1:
        raise RuleValidationError(
            f"{file}: rule '{name}': action.targets must have at least 1 entry"
        )
    if len(targets_raw) > MAX_TARGETS:
        raise RuleValidationError(
            f"{file}: rule '{name}': action.targets exceeds maximum of {MAX_TARGETS}"
        )

    targets = []
    for i, t in enumerate(targets_raw):
        if "dst_ip" not in t:
            raise RuleValidationError(
                f"{file}: rule '{name}': action.targets[{i}].dst_ip is required"
            )
        try:
            dst_ip = IPv4Address(t["dst_ip"])
        except ValueError as e:
            raise RuleValidationError(
                f"{file}: rule '{name}': action.targets[{i}].dst_ip: {e}"
            )
        if "via" not in t:
            raise RuleValidationError(
                f"{file}: rule '{name}': action.targets[{i}].via is required"
            )
        targets.append(ReplicationTarget(
            dst_ip=dst_ip,
            via=t["via"],
            next_hop_mac=t.get("next_hop_mac"),
        ))

    return ReplicateAction(targets=targets)


def load_rules(paths: list[str]) -> list[Rule]:
    """Load, validate, and sort rules from one or more YAML files.

    Returns a list of Rule objects sorted by priority with rule_id
    assigned per-type as the slot index within that type's BPF map.
    """
    all_raw = []

    for path in paths:
        p = Path(path)
        if not p.exists():
            raise RuleValidationError(f"Rule file not found: {path}")
        with open(p) as f:
            doc = yaml.safe_load(f)
        if not doc or "rules" not in doc:
            raise RuleValidationError(f"{path}: missing top-level 'rules' key")
        for r in doc["rules"]:
            all_raw.append((r, str(p)))

    # Validate individual rules and build Rule objects (rule_id assigned later)
    rules = []
    for raw, file in all_raw:
        if "name" not in raw:
            raise RuleValidationError(f"{file}: rule missing 'name' field")
        name = raw["name"]

        if "priority" not in raw:
            raise RuleValidationError(f"{file}: rule '{name}': missing 'priority' field")
        priority = raw["priority"]
        if not isinstance(priority, int):
            raise RuleValidationError(
                f"{file}: rule '{name}': priority must be an integer"
            )

        if "type" not in raw:
            raise RuleValidationError(f"{file}: rule '{name}': missing 'type' field")
        rtype = raw["type"]
        if rtype not in ("steer", "replicate"):
            raise RuleValidationError(
                f"{file}: rule '{name}': type must be 'steer' or 'replicate'"
            )

        if "match" not in raw:
            raise RuleValidationError(f"{file}: rule '{name}': missing 'match' section")
        match = _parse_match(raw["match"], file, name)

        if "action" not in raw:
            raise RuleValidationError(f"{file}: rule '{name}': missing 'action' section")

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

    if len(rules) > MAX_RULES:
        raise RuleValidationError(
            f"Total rule count ({len(rules)}) exceeds MAX_RULES ({MAX_RULES})"
        )

    # Check for duplicate priorities
    prio_map: dict[int, Rule] = {}
    for r in rules:
        if r.priority in prio_map:
            other = prio_map[r.priority]
            raise RuleValidationError(
                f"Duplicate priority {r.priority}: "
                f"'{r.name}' ({r.source_file}) and "
                f"'{other.name}' ({other.source_file})"
            )
        prio_map[r.priority] = r

    # Check for duplicate names
    name_map: dict[str, Rule] = {}
    for r in rules:
        if r.name in name_map:
            other = name_map[r.name]
            raise RuleValidationError(
                f"Duplicate rule name '{r.name}': "
                f"({r.source_file}) and ({other.source_file})"
            )
        name_map[r.name] = r

    # Sort by priority ascending
    rules.sort(key=lambda r: r.priority)

    # Assign per-type rule_id as slot index within that type's BPF map
    steer_idx = 0
    replicate_idx = 0
    for r in rules:
        if r.type == "steer":
            r.rule_id = steer_idx
            steer_idx += 1
        else:
            r.rule_id = replicate_idx
            replicate_idx += 1

    return rules
