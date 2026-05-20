#!/usr/bin/env python3
# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""Rudder CLI for loading, reloading, observing, and stopping eBPF TC policy.

The CLI is deliberately thin: it validates root access, turns terminal commands
into control-plane calls, and leaves policy parsing/TC/eBPF details to the
engine package. That keeps the command surface easy to read for people learning
how userspace drives eBPF packet programs.
"""

import os
import sys

import click

from engine.loader import load_policy, RuleValidationError
from engine.manager import PolicyManager
from engine.daemon import start_daemon, send_command
from engine.manager import BPF_PIN_DIR, REPLICATE_EVENTS_MAP, STEER_EVENTS_MAP
from engine.runtime import SOCK_PATH


RULE_NAME_WIDTH = 26


@click.group()
def cli():
    """Rudder: eBPF TC packet steering and multicast replication."""
    # Loading and controlling TC/eBPF state requires root-equivalent privileges.
    # Enforce that at the CLI boundary so every subcommand behaves consistently.
    if os.geteuid() != 0:
        click.echo("rudder requires root privileges. Use sudo.")
        sys.exit(1)


def _print_kv(label: str, value) -> None:
    """Print an indented key/value line for structured show commands."""
    click.echo(f"  {label:<22s} {value}")


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
def load(files):
    """Load YAML rules, attach eBPF programs, and start the background daemon."""
    # The daemon owns cleanup. A socket means another rudder instance should be
    # stopped first instead of layering more TC hooks onto the same interfaces.
    if os.path.exists(SOCK_PATH):
        click.echo("Rudder is already running. Use 'sudo rudder stop' first.")
        sys.exit(1)

    file_list = list(files)
    click.echo(f"Loading rules from: {', '.join(file_list)}")

    try:
        policy = load_policy(file_list)
    except RuleValidationError as e:
        click.echo(f"Validation error: {e}")
        sys.exit(1)

    # Print loaded rules
    for r in policy.rules:
        click.echo(f"  [ok] {r.name:<20s} priority={r.priority:<4d} "
                    f"type={r.type:<10s} interface={r.match.interface}")

    # PolicyManager does the privileged work: compile eBPF, attach TC filters,
    # pin representative maps, and populate every loaded map instance.
    manager = PolicyManager(policy)
    try:
        manager.load()
    except Exception as e:
        click.echo(f"Load failed: {e}")
        sys.exit(1)

    # The process that loaded TC/eBPF state forks into a daemon so it can keep
    # ownership of interface attachments and accept semi-real-time reloads.
    pid = start_daemon(policy, manager)

    counts = policy.counts
    total = counts.total
    click.echo(f"Rudder running. {total} rule{'s' if total != 1 else ''} active "
               f"({counts.steer} steer, {counts.replicate} replicate). Daemon PID: {pid}")


@cli.command()
def stop():
    """Stop the rudder daemon and detach all TC hooks."""
    resp = send_command("stop")
    if not resp.get("ok"):
        click.echo(resp.get("error", "Unknown error"))
        sys.exit(1)
    click.echo("Rudder stopped.")


@cli.group()
def show():
    """Show rules, stats, maps, interfaces, or internals."""
    # Click requires a function body for command groups.
    pass


@show.command("rules")
def show_rules():
    """Display loaded rules."""
    resp = send_command("show_rules")
    if not resp.get("ok"):
        click.echo(resp.get("error", "Unknown error"))
        sys.exit(1)

    rules = resp["data"]
    if not rules:
        click.echo("No rules loaded.")
        return

    click.echo(f"{'PRI':<6s}{'NAME':<{RULE_NAME_WIDTH}s}{'TYPE':<12s}{'INTERFACE':<12s}"
               f"{'MATCH':<30s}{'ACTION'}")
    for r in rules:
        click.echo(f"{r['priority']:<6d}{r['name']:<{RULE_NAME_WIDTH}s}{r['type']:<12s}"
                   f"{r['interface']:<12s}{r['match']:<30s}{r['action']}")


@show.command("stats")
def show_stats():
    """Display hit counters for all rules."""
    resp = send_command("show_stats")
    if not resp.get("ok"):
        click.echo(resp.get("error", "Unknown error"))
        sys.exit(1)

    stats = resp["data"]
    if not stats:
        click.echo("No hits recorded.")
        return

    click.echo(f"{'NAME':<{RULE_NAME_WIDTH}s}{'TYPE':<12s}{'PRI':<7s}{'HITS':>12s}")
    for s in stats:
        click.echo(f"{s['name']:<{RULE_NAME_WIDTH}s}{s['type']:<12s}"
                   f"{s['priority']:<7d}{s['hits']:>12,d}")


@show.command("maps")
def show_maps():
    """Dump eBPF map contents in human-readable form."""
    resp = send_command("show_maps")
    if not resp.get("ok"):
        click.echo(resp.get("error", "Unknown error"))
        sys.exit(1)

    data = resp["data"]

    if data.get("steer"):
        click.echo("=== steer_rules ===")
        for entry in data["steer"]:
            click.echo(f"  slot={entry['slot']} name={entry['name']} "
                       f"ingress={entry['ingress_ifindex']} "
                       f"src={entry['src_ip']}/{entry['src_prefix_len']} "
                       f"dst={entry['dst_ip']}/{entry['dst_prefix_len']} "
                       f"dscp={entry['dscp']} proto={entry['ip_proto']} "
                       f"-> new_dst={entry['new_dst_ip']} "
                       f"egress={entry['egress_ifindex']} "
                       f"mac={entry['dst_mac']}")

    if data.get("replicate"):
        click.echo("=== replicate_rules ===")
        for entry in data["replicate"]:
            click.echo(f"  slot={entry['slot']} name={entry['name']} "
                       f"ingress={entry['ingress_ifindex']} "
                       f"dst={entry['dst_ip']}/{entry['dst_prefix_len']} "
                       f"targets={entry['target_count']}:")
            for t in entry.get("targets", []):
                click.echo(f"    -> {t['dst_ip']} via {t['egress_ifindex']} "
                           f"mac={t['dst_mac']}")


@show.command("interfaces")
def show_interfaces():
    """Show all network interfaces and their hook status."""
    resp = send_command("show_interfaces")
    if not resp.get("ok"):
        click.echo(resp.get("error", "Unknown error"))
        sys.exit(1)

    ifaces = resp["data"]
    click.echo(f"{'INTERFACE':<12s}{'IFINDEX':<10s}{'HOOK'}")
    for i in ifaces:
        hook = "yes (rudder)" if i["attached"] else "no"
        click.echo(f"{i['name']:<12s}{i['ifindex']:<10d}{hook}")


@show.command("internals")
def show_internals():
    """Show Rudder's runtime TC/eBPF internals."""
    resp = send_command("show_internals")
    if not resp.get("ok"):
        click.echo(resp.get("error", "Unknown error"))
        sys.exit(1)

    data = resp["data"]

    click.echo("=== runtime ===")
    runtime = data["runtime"]
    _print_kv("runtime_dir", runtime["runtime_dir"])
    _print_kv("socket_path", runtime["socket_path"])
    _print_kv("bpf_pin_dir", runtime["bpf_pin_dir"])
    for name, path in runtime["objects"].items():
        _print_kv(f"{name}_object", path)

    click.echo("\n=== tc filters ===")
    attached = data["tc"]["attached_interfaces"]
    _print_kv("attached_interfaces", ", ".join(attached) if attached else "(none)")
    for filt in data["tc"]["filters"]:
        click.echo(
            f"  {filt['program']:<10s} pref={filt['pref']:<6s} "
            f"section={filt['section']:<10s} object={filt['object']}"
        )

    click.echo("\n=== eBPF maps ===")
    for m in data["maps"]:
        ids = ", ".join(str(i) for i in m["ids"]) if m["ids"] else "(none)"
        pinned = "yes" if m["pinned"] else "no"
        writes = "yes" if m["written_on_reload"] else "no"
        click.echo(
            f"  {m['name']:<16s} ids={ids:<16s} pinned={pinned:<3s} "
            f"reload_write={writes:<3s} path={m['pinned_path']}"
        )
        click.echo(f"    role: {m['role']}")

    click.echo("\n=== policy ===")
    policy = data["policy"]
    counts = policy["counts"]
    _print_kv("source_files", ", ".join(policy["source_files"]) or "(none)")
    _print_kv("rule_counts", f"total={counts['total']} steer={counts['steer']} "
                             f"replicate={counts['replicate']}")
    limits = policy["limits"]
    _print_kv("max_rules", limits["max_rules"])
    _print_kv("max_targets", limits["max_targets_per_rule"])
    _print_kv("protocols", ", ".join(limits["supported_ip_protocols"]))
    fragment_status = "skipped" if limits["skips_ipv4_fragments"] else "processed"
    _print_kv("ipv4_fragments", fragment_status)

    click.echo("\n=== policy slots ===")
    slots = policy["slots"]
    if not slots:
        click.echo("  (none)")
    for slot in slots:
        click.echo(
            f"  {slot['type']:<10s} map={slot['map']:<16s} slot={slot['slot']:<3d} "
            f"priority={slot['priority']:<5d} ingress={slot['match_interface']:<10s} "
            f"name={slot['name']}"
        )
        click.echo(f"    source: {slot['source_file']}")


def _trace_rule_type(event_type: int) -> str:
    """Map trace event type to the policy rule type that emitted it."""
    if event_type == 0:
        return "steer"
    if event_type in (1, 2):
        return "replicate"
    return "unknown"


def _trace_rule_names() -> dict[tuple[str, int], str]:
    """Fetch rule names from the daemon so trace output is readable."""
    resp = send_command("show_rules")
    if not resp.get("ok"):
        return {}

    names = {}
    for rule in resp.get("data", []):
        if "rule_id" in rule:
            names[(rule["type"], rule["rule_id"])] = rule["name"]
    return names


@cli.command()
def trace():
    """Stream experimental live trace events from eBPF perf event arrays."""
    from engine.perf_reader import PerfReader
    from engine.observer import EVENT_TYPE_NAMES, _ifindex_to_name, _ip_from_int
    from pathlib import Path

    steer_pin = f"{BPF_PIN_DIR}/{STEER_EVENTS_MAP}"
    repl_pin = f"{BPF_PIN_DIR}/{REPLICATE_EVENTS_MAP}"

    # Trace reads the pinned perf event arrays directly. That keeps the
    # eBPF/userspace relationship visible; rule names are fetched separately
    # from the daemon when available.
    readers = []
    for pin_path in [steer_pin, repl_pin]:
        if Path(pin_path).exists():
            reader = PerfReader(pin_path)
            try:
                reader.open()
                readers.append((pin_path, reader))
            except Exception as e:
                click.echo(f"WARNING: Could not open {pin_path}: {e}")

    if not readers:
        click.echo("No trace event maps found. Is rudder loaded?")
        sys.exit(1)

    rule_names = _trace_rule_names()
    click.echo("WARNING: rudder trace is experimental.")
    click.echo(
        "It demonstrates eBPF perf event output, but the userspace reader "
        "is not production-grade."
    )
    click.echo("Use 'sudo python3 rudder.py show internals' to inspect the maps trace reads.")
    click.echo("Streaming trace events (Ctrl-C to stop)...")

    def _handle_event(parsed):
        ts_ns, rule_id, src_ip, orig_dst, new_dst, egress_idx, etype = parsed
        from datetime import datetime
        ts = datetime.fromtimestamp(ts_ns / 1e9)
        ts_str = ts.strftime("%H:%M:%S.%f")[:-3]
        etype_name = EVENT_TYPE_NAMES.get(etype, f"unknown({etype})")
        rtype = _trace_rule_type(etype)
        rule_name = rule_names.get((rtype, rule_id), f"{rtype}-{rule_id}")
        egress_name = _ifindex_to_name(egress_idx)

        click.echo(
            f"[{ts_str}] rule={rule_name:<{RULE_NAME_WIDTH}s} slot={rule_id:<4d} "
            f"type={etype_name:<20s} "
            f"src={_ip_from_int(src_ip):<15s} "
            f"orig_dst={_ip_from_int(orig_dst):<15s} "
            f"new_dst={_ip_from_int(new_dst):<15s} "
            f"egress={egress_name}"
        )

    try:
        while True:
            for pin_path, reader in readers:
                reader.poll(_handle_event, timeout_ms=100)
    except KeyboardInterrupt:
        click.echo("\nTrace stopped.")
    finally:
        for _, reader in readers:
            reader.close()


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
def reload(files):
    """Reload YAML rules and update eBPF maps without restarting the daemon."""
    file_list = list(files)
    resp = send_command("reload", files=file_list)
    if not resp.get("ok"):
        click.echo(f"Reload failed: {resp.get('error', 'Unknown error')}")
        sys.exit(1)

    changes = resp["data"]
    if changes:
        click.echo("Reloaded. Changes applied:")
        for c in changes:
            click.echo(c)
    else:
        click.echo("Reloaded. No changes detected.")


if __name__ == "__main__":
    cli()
