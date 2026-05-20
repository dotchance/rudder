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

from engine.loader import load_rules, RuleValidationError
from engine.manager import PolicyManager
from engine.daemon import start_daemon, send_command
from engine.manager import BPF_PIN_DIR, REPLICATE_EVENTS_MAP, STEER_EVENTS_MAP
from engine.runtime import SOCK_PATH


@click.group()
def cli():
    """Rudder: eBPF TC packet steering and multicast replication."""
    # Loading and controlling TC/eBPF state requires root-equivalent privileges.
    # Enforce that at the CLI boundary so every subcommand behaves consistently.
    if os.geteuid() != 0:
        click.echo("rudder requires root privileges. Use sudo.")
        sys.exit(1)


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
        rules = load_rules(file_list)
    except RuleValidationError as e:
        click.echo(f"Validation error: {e}")
        sys.exit(1)

    # Print loaded rules
    for r in rules:
        click.echo(f"  [ok] {r.name:<20s} priority={r.priority:<4d} "
                    f"type={r.type:<10s} interface={r.match.interface}")

    # PolicyManager does the privileged work: compile eBPF, attach TC filters,
    # pin representative maps, and populate every loaded map instance.
    manager = PolicyManager(rules)
    try:
        manager.load()
    except Exception as e:
        click.echo(f"Load failed: {e}")
        sys.exit(1)

    # The process that loaded TC/eBPF state forks into a daemon so it can keep
    # ownership of interface attachments and accept semi-real-time reloads.
    pid = start_daemon(rules, manager)

    steer_count = sum(1 for r in rules if r.type == "steer")
    repl_count = sum(1 for r in rules if r.type == "replicate")
    total = len(rules)
    click.echo(f"Rudder running. {total} rule{'s' if total != 1 else ''} active "
               f"({steer_count} steer, {repl_count} replicate). Daemon PID: {pid}")


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
    """Show rules, stats, maps, or interfaces."""
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

    click.echo(f"{'PRI':<6s}{'NAME':<22s}{'TYPE':<12s}{'INTERFACE':<12s}"
               f"{'MATCH':<30s}{'ACTION'}")
    for r in rules:
        click.echo(f"{r['priority']:<6d}{r['name']:<22s}{r['type']:<12s}"
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

    click.echo(f"{'NAME':<22s}{'TYPE':<12s}{'PRI':<7s}{'HITS':>12s}")
    for s in stats:
        click.echo(f"{s['name']:<22s}{s['type']:<12s}"
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


@cli.command()
def trace():
    """Stream experimental live trace events from eBPF perf event arrays."""
    from engine.perf_reader import PerfReader
    from engine.observer import EVENT_TYPE_NAMES, _ifindex_to_name, _ip_from_int
    from pathlib import Path

    steer_pin = f"{BPF_PIN_DIR}/{STEER_EVENTS_MAP}"
    repl_pin = f"{BPF_PIN_DIR}/{REPLICATE_EVENTS_MAP}"

    # Trace currently reads the pinned perf event arrays directly. That makes
    # the eBPF/userspace relationship visible, but it also means this command
    # prints numeric rule IDs instead of resolving names through the daemon.
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

    click.echo("Streaming trace events (Ctrl-C to stop)...")

    def _handle_event(parsed):
        ts_ns, rule_id, src_ip, orig_dst, new_dst, egress_idx, etype = parsed
        from datetime import datetime
        ts = datetime.fromtimestamp(ts_ns / 1e9)
        ts_str = ts.strftime("%H:%M:%S.%f")[:-3]
        etype_name = EVENT_TYPE_NAMES.get(etype, f"unknown({etype})")
        egress_name = _ifindex_to_name(egress_idx)

        click.echo(
            f"[{ts_str}] rule_id={rule_id:<4d} type={etype_name:<20s} "
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
