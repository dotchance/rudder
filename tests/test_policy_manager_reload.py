# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""Tests for staged reload behavior without touching real TC/eBPF state."""

import os
import tempfile
import textwrap
import unittest

from engine.loader import load_policy
from engine.manager import POLICY_WRITE_MAPS, PolicyManager


class FakePolicyManager(PolicyManager):
    """PolicyManager test double that records reload order in memory."""

    def __init__(
        self,
        policy,
        fail_once_for_rule: str | None = None,
        fail_resolve_for_rule: str | None = None,
    ):
        super().__init__(policy)
        self.fail_once_for_rule = fail_once_for_rule
        self.fail_resolve_for_rule = fail_resolve_for_rule
        self.failed_once = False
        self.events: list[tuple] = []

    def _resolve_interfaces(self):
        """Avoid host interface lookups during unit tests."""
        if self.fail_resolve_for_rule in [rule.name for rule in self.rules]:
            raise RuntimeError("simulated interface resolution failure")

        self._ifindex_cache = {}
        next_index = 1
        for rule in self.rules:
            names = []
            if rule.match.interface != "any":
                names.append(rule.match.interface)
            action = rule.action
            if hasattr(action, "via"):
                names.append(action.via)
            else:
                names.extend(target.via for target in action.targets)

            for name in names:
                if name not in self._ifindex_cache:
                    self._ifindex_cache[name] = next_index
                    next_index += 1

    def _resolve_macs(self):
        """Do not inspect the host neighbor table in unit tests."""

    def _attach_interface(self, iface: str):
        self.events.append(("attach", iface))
        if iface not in self._attached_interfaces:
            self._attached_interfaces.append(iface)

    def _detach_interface(self, iface: str):
        self.events.append(("detach", iface))

    def _refresh_map_ids(self):
        self._map_ids_by_name = {
            name: [idx]
            for idx, name in enumerate(POLICY_WRITE_MAPS, start=1)
        }

    def _populate_maps(self):
        names = [rule.name for rule in self.rules]
        self.events.append(("populate", tuple(names)))
        if (
            self.fail_once_for_rule in names
            and not self.failed_once
        ):
            self.failed_once = True
            raise RuntimeError("simulated map write failure")


class PolicyManagerReloadTests(unittest.TestCase):
    """Checks for the P0 reload transaction shape."""

    def write_yaml(self, body: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent(body).lstrip())
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def policy(self, name: str, ingress: str, via: str, dst_ip: str = "192.0.2.1"):
        return load_policy([self.write_yaml(f"""
            rules:
              - name: {name}
                priority: 10
                type: steer
                match:
                  interface: {ingress}
                action:
                  dst_ip: {dst_ip}
                  via: {via}
            """)])

    def test_successful_reload_attaches_before_detaching(self):
        old_policy = self.policy("old-path", "eth0", "eth2")
        new_policy = self.policy("new-path", "eth1", "eth2")
        manager = FakePolicyManager(old_policy)
        manager._attached_interfaces = ["eth0"]

        summary = manager.update_policy(new_policy)

        self.assertEqual(summary["attached"], ["eth1"])
        self.assertEqual(summary["detached"], ["eth0"])
        self.assertEqual(manager.policy, new_policy)
        self.assertEqual(manager._attached_interfaces, ["eth1"])
        self.assertEqual(
            manager.events[:3],
            [
                ("attach", "eth1"),
                ("populate", ("new-path",)),
                ("detach", "eth0"),
            ],
        )

    def test_failed_map_write_restores_previous_policy(self):
        old_policy = self.policy("old-path", "eth0", "eth2")
        new_policy = self.policy("bad-path", "eth1", "eth2")
        manager = FakePolicyManager(old_policy, fail_once_for_rule="bad-path")
        manager._attached_interfaces = ["eth0"]

        with self.assertRaisesRegex(RuntimeError, "previous policy restored"):
            manager.update_policy(new_policy)

        self.assertEqual(manager.policy, old_policy)
        self.assertEqual([rule.name for rule in manager.rules], ["old-path"])
        self.assertEqual(manager._attached_interfaces, ["eth0"])
        self.assertIn(("populate", ("bad-path",)), manager.events)
        self.assertIn(("populate", ("old-path",)), manager.events)
        self.assertIn(("detach", "eth1"), manager.events)

    def test_failed_preflight_restore_does_not_rewrite_maps(self):
        old_policy = self.policy("old-path", "eth0", "eth2")
        new_policy = self.policy("bad-preflight", "eth1", "eth2")
        manager = FakePolicyManager(old_policy, fail_resolve_for_rule="bad-preflight")
        manager._attached_interfaces = ["eth0"]

        with self.assertRaisesRegex(RuntimeError, "previous policy restored"):
            manager.update_policy(new_policy)

        self.assertEqual(manager.policy, old_policy)
        self.assertEqual(manager._attached_interfaces, ["eth0"])
        self.assertEqual(manager.events, [])

    def test_internals_describe_runtime_maps_and_policy_slots(self):
        policy = self.policy("visible-path", "eth0", "eth2")
        manager = FakePolicyManager(policy)
        manager._attached_interfaces = ["eth0"]

        internals = manager.get_internals()

        self.assertEqual(internals["tc"]["attached_interfaces"], ["eth0"])
        self.assertEqual(
            [f["pref"] for f in internals["tc"]["filters"]],
            ["49152", "49153"],
        )

        maps_by_name = {m["name"]: m for m in internals["maps"]}
        self.assertEqual(maps_by_name["steer_rules"]["ids"], [1])
        self.assertTrue(maps_by_name["steer_rules"]["written_on_reload"])
        self.assertFalse(maps_by_name["steer_events"]["written_on_reload"])

        self.assertEqual(internals["policy"]["counts"]["total"], 1)
        self.assertEqual(internals["policy"]["limits"]["max_rules"], 64)
        self.assertEqual(internals["policy"]["slots"], [{
            "name": "visible-path",
            "type": "steer",
            "priority": 10,
            "source_file": policy.rules[0].source_file,
            "match_interface": "eth0",
            "map": "steer_rules",
            "slot": 0,
        }])


if __name__ == "__main__":
    unittest.main()
