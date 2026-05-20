# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""Policy intermediate representation for Rudder.

Rudder accepts YAML today, but YAML should not be the shape that the rest of
the control plane thinks in. This module is the first IR layer: parsers produce
a `Policy`, and the daemon/manager consume that policy without caring whether
it came from YAML or a future grammar.

The current IR intentionally wraps the existing `Rule` dataclasses instead of
replacing them. That keeps the P0 change small while creating the boundary that
future BNF-style configuration can compile into.
"""

from dataclasses import dataclass, field
from typing import Iterable

from engine.models import (
    MAX_RULES,
    MAX_TARGETS,
    MatchSet,
    ReplicateAction,
    ReplicationTarget,
    Rule,
    SteerAction,
)


@dataclass(frozen=True)
class BackendLimits:
    """Capabilities and fixed sizes of the current TC/eBPF backend.

    Validation uses this object to explain why a rule is rejected. For example,
    `max_targets_per_rule` is not a YAML preference; it comes from the fixed
    targets array in the eBPF map value layout.
    """

    max_rules: int = MAX_RULES
    max_targets_per_rule: int = MAX_TARGETS
    supported_rule_types: tuple[str, ...] = ("steer", "replicate")
    supported_ip_protocols: tuple[str, ...] = ("any", "tcp", "udp")
    supports_ipv4: bool = True
    supports_ipv6: bool = False
    supports_vlan: bool = False
    skips_ipv4_fragments: bool = True


@dataclass(frozen=True)
class RuleCounts:
    """Small summary used by the CLI and tests."""

    total: int
    steer: int
    replicate: int


@dataclass
class Policy:
    """Validated, normalized policy ready for TC/eBPF realization."""

    rules: list[Rule]
    source_files: tuple[str, ...]
    limits: BackendLimits = field(default_factory=BackendLimits)

    @classmethod
    def from_rules(
        cls,
        rules: Iterable[Rule],
        source_files: Iterable[str] = (),
        limits: BackendLimits | None = None,
    ) -> "Policy":
        """Build a Policy from already-normalized rules.

        This is useful for compatibility paths that still call `load_rules()`
        and for tests that want to construct a policy without YAML.
        """
        return cls(
            rules=list(rules),
            source_files=tuple(source_files),
            limits=limits or BackendLimits(),
        )

    @property
    def counts(self) -> RuleCounts:
        """Return rule counts by backend program type."""
        steer = sum(1 for r in self.rules if r.type == "steer")
        replicate = sum(1 for r in self.rules if r.type == "replicate")
        return RuleCounts(total=len(self.rules), steer=steer, replicate=replicate)

    def diff(self, previous: "Policy | None") -> list[str]:
        """Return human-readable changes from `previous` to this policy.

        The daemon uses this before touching live TC/eBPF state so the reload
        response can describe the policy intent that was accepted.
        """
        if previous is None:
            return [
                f"  ADDED     {r.name:<20s} priority={r.priority}"
                for r in self.rules
            ]

        old_by_name = {r.name: r for r in previous.rules}
        new_by_name = {r.name: r for r in self.rules}

        changes: list[str] = []
        for rule in self.rules:
            old_rule = old_by_name.get(rule.name)
            if old_rule is None:
                changes.append(f"  ADDED     {rule.name:<20s} priority={rule.priority}")
            elif _rule_fingerprint(rule) != _rule_fingerprint(old_rule):
                changes.append(f"  MODIFIED  {rule.name:<20s}")

        for rule in previous.rules:
            if rule.name not in new_by_name:
                changes.append(f"  REMOVED   {rule.name:<20s} priority={rule.priority}")

        return changes


def _rule_fingerprint(rule: Rule) -> tuple:
    """Convert a rule into immutable values for reload diffing."""
    return (
        rule.priority,
        rule.type,
        _match_fingerprint(rule.match),
        _action_fingerprint(rule.action),
    )


def _match_fingerprint(match: MatchSet) -> tuple:
    """Convert match fields into stable string/int values."""
    return (
        match.interface,
        str(match.src_ip) if match.src_ip is not None else None,
        str(match.dst_ip) if match.dst_ip is not None else None,
        match.dscp,
        match.ip_proto,
    )


def _action_fingerprint(action: SteerAction | ReplicateAction) -> tuple:
    """Convert action fields into stable values without relying on object ids."""
    if isinstance(action, SteerAction):
        return (
            "steer",
            str(action.dst_ip),
            action.via,
            action.next_hop_mac,
        )

    targets = tuple(_target_fingerprint(t) for t in action.targets)
    return ("replicate", targets)


def _target_fingerprint(target: ReplicationTarget) -> tuple:
    """Convert one replicate target into stable values."""
    return (
        str(target.dst_ip),
        target.via,
        target.next_hop_mac,
    )
