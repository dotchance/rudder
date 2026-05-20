# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""Tests for YAML-to-Policy validation.

These tests stay at the loader boundary because that is where malformed human
configuration must be stopped before Rudder touches TC or eBPF maps.
"""

import os
import tempfile
import textwrap
import unittest

from engine.loader import RuleValidationError, load_policy


class PolicyLoaderTests(unittest.TestCase):
    """Focused checks for the P0 Policy IR loader."""

    def write_yaml(self, body: str) -> str:
        """Write a temporary YAML rule file and clean it up after the test."""
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent(body).lstrip())
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def assert_invalid(self, body: str, expected: str):
        """Load YAML and assert that validation rejects it with useful text."""
        path = self.write_yaml(body)
        with self.assertRaises(RuleValidationError) as ctx:
            load_policy([path])
        self.assertIn(expected, str(ctx.exception))

    def test_examples_load_into_policy_ir(self):
        policy = load_policy([
            "rules/example_steer.yaml",
            "rules/example_replicate.yaml",
        ])

        self.assertEqual(policy.counts.total, 2)
        self.assertEqual(policy.counts.steer, 1)
        self.assertEqual(policy.counts.replicate, 1)
        self.assertEqual([r.priority for r in policy.rules], [10, 20])
        self.assertEqual(policy.rules[0].rule_id, 0)
        self.assertEqual(policy.rules[1].rule_id, 0)

    def test_rules_must_be_a_list(self):
        self.assert_invalid(
            """
            rules: wrong
            """,
            "rules: must be a list",
        )

    def test_rule_must_be_a_mapping(self):
        self.assert_invalid(
            """
            rules:
              - just-a-string
            """,
            "rules[0]: must be a mapping",
        )

    def test_bool_priority_is_rejected(self):
        self.assert_invalid(
            """
            rules:
              - name: bad-priority
                priority: true
                type: steer
                match:
                  interface: eth0
                action:
                  dst_ip: 192.0.2.1
                  via: eth1
            """,
            "priority must be an integer",
        )

    def test_nested_sections_must_be_mappings(self):
        self.assert_invalid(
            """
            rules:
              - name: bad-match
                priority: 1
                type: steer
                match:
                  - interface
                action:
                  dst_ip: 192.0.2.1
                  via: eth1
            """,
            "match: must be a mapping",
        )

    def test_malformed_mac_is_rejected(self):
        self.assert_invalid(
            """
            rules:
              - name: bad-mac
                priority: 1
                type: steer
                match:
                  interface: eth0
                action:
                  dst_ip: 192.0.2.1
                  via: eth1
                  next_hop_mac: not-a-mac
            """,
            "must be a MAC address like aa:bb:cc:dd:ee:ff",
        )

    def test_replicate_target_must_be_mapping(self):
        self.assert_invalid(
            """
            rules:
              - name: bad-target
                priority: 1
                type: replicate
                match:
                  interface: eth0
                  dst_ip: 239.1.1.1
                action:
                  targets:
                    - wrong
            """,
            "targets[0]: must be a mapping",
        )

    def test_duplicate_replicate_target_is_rejected(self):
        self.assert_invalid(
            """
            rules:
              - name: duplicate-target
                priority: 1
                type: replicate
                match:
                  interface: eth0
                  dst_ip: 239.1.1.1
                action:
                  targets:
                    - dst_ip: 10.0.0.1
                      via: eth1
                    - dst_ip: 10.0.0.1
                      via: eth1
            """,
            "duplicates target 10.0.0.1 via eth1",
        )

    def test_policy_diff_reports_modified_rules(self):
        original = load_policy([self.write_yaml("""
            rules:
              - name: steer-one
                priority: 10
                type: steer
                match:
                  interface: eth0
                action:
                  dst_ip: 192.0.2.1
                  via: eth1
            """)])
        changed = load_policy([self.write_yaml("""
            rules:
              - name: steer-one
                priority: 10
                type: steer
                match:
                  interface: eth0
                action:
                  dst_ip: 192.0.2.2
                  via: eth1
            """)])

        self.assertEqual(changed.diff(original), ["  MODIFIED  steer-one           "])


if __name__ == "__main__":
    unittest.main()
