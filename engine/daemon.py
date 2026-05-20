# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""Background daemon that owns Rudder's live TC/eBPF state.

Communicates via a Unix domain socket under /run/rudder using
newline-delimited JSON. Spawned via os.fork() + os.setsid() from
'rudder load'.

The daemon is intentionally simple: one request is handled at a time, which is
good enough for a teaching tool and avoids concurrent writes into eBPF maps
while a reload is in progress.
"""

import json
import os
import signal
import socket
import stat
import struct

from engine.loader import load_policy
from engine.manager import PolicyManager
from engine.observer import Observer
from engine.policy import Policy
from engine.runtime import SOCK_PATH, ensure_runtime_dir


PEER_CRED_FMT = "3i"  # pid, uid, gid from SO_PEERCRED on Linux.


class Daemon:
    """Small JSON-over-Unix-socket control server.

    `PolicyManager` remains the owner of TC attachments and eBPF maps. The
    daemon only routes commands and keeps enough rule state to format CLI
    responses.
    """

    def __init__(self, manager: PolicyManager, observer: Observer, policy: Policy):
        self.manager = manager
        self.observer = observer
        self.policy = policy
        self.rules = policy.rules
        self._running = False

    def run(self):
        """Listen for root-only JSON commands until `stop` or SIGTERM."""
        self._running = True
        ensure_runtime_dir()

        # Clean up a stale socket left by a previous daemon. If another file
        # exists at this path, fail instead of unlinking something unexpected.
        if os.path.exists(SOCK_PATH):
            mode = os.stat(SOCK_PATH).st_mode
            if not stat.S_ISSOCK(mode):
                raise RuntimeError(f"{SOCK_PATH} exists and is not a socket")
            os.unlink(SOCK_PATH)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o077)
        try:
            server.bind(SOCK_PATH)
        finally:
            os.umask(old_umask)
        os.chmod(SOCK_PATH, 0o600)
        server.listen(5)
        server.settimeout(1.0)

        # Handle SIGTERM for clean shutdown
        def _sigterm(signum, frame):
            # Signal handlers should do the smallest possible amount of work.
            # The main loop observes this flag and performs cleanup in `finally`.
            self._running = False
        signal.signal(signal.SIGTERM, _sigterm)

        try:
            while self._running:
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    self._handle_connection(conn)
                except Exception as e:
                    try:
                        resp = json.dumps({"ok": False, "error": str(e)}) + "\n"
                        conn.sendall(resp.encode())
                    except Exception:
                        # If the client disappeared, the daemon should keep
                        # running so future stop/show/reload commands still work.
                        pass
                finally:
                    conn.close()
        finally:
            server.close()
            if os.path.exists(SOCK_PATH):
                os.unlink(SOCK_PATH)
            # Clean unload on shutdown
            try:
                self.manager.unload()
            except Exception:
                # Shutdown cleanup is best effort. The daemon is already
                # exiting, and surfacing an exception here would hide the signal
                # or command that requested shutdown.
                pass

    def _handle_connection(self, conn: socket.socket):
        """Read one newline-delimited JSON request and write one response."""
        if not self._peer_is_root(conn):
            resp = {"ok": False, "error": "Rudder daemon only accepts root clients"}
            conn.sendall((json.dumps(resp) + "\n").encode())
            return

        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break

        # Rudder's protocol is intentionally one-line JSON. It is enough for
        # the small command set and keeps the daemon easy to exercise by hand.
        line = data.decode().strip()
        if not line:
            return

        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            resp = {"ok": False, "error": "Invalid JSON"}
            conn.sendall((json.dumps(resp) + "\n").encode())
            return

        cmd = req.get("cmd", "")
        resp = self._dispatch(cmd, req)
        conn.sendall((json.dumps(resp) + "\n").encode())

    def _peer_is_root(self, conn: socket.socket) -> bool:
        """Return True when the Unix socket peer is uid 0.

        The CLI enforces root before it connects, but checking peer credentials
        here keeps the daemon boundary explicit and protects the control plane
        if another local process tries to speak the JSON protocol directly.
        """
        try:
            raw = conn.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize(PEER_CRED_FMT),
            )
        except OSError:
            return False

        _pid, uid, _gid = struct.unpack(PEER_CRED_FMT, raw)
        return uid == 0

    def _dispatch(self, cmd: str, req: dict) -> dict:
        """Route a command to the appropriate handler."""
        if cmd == "stop":
            self._running = False
            return {"ok": True, "data": "Stopping rudder daemon"}

        elif cmd == "show_rules":
            rules_data = []
            for r in self.rules:
                rd = {
                    "name": r.name,
                    "priority": r.priority,
                    "rule_id": r.rule_id,
                    "type": r.type,
                    "interface": r.match.interface,
                    "match": self._format_match(r),
                    "action": self._format_action(r),
                }
                rules_data.append(rd)
            return {"ok": True, "data": rules_data}

        elif cmd == "show_stats":
            stats = self.observer.dump_stats()
            return {"ok": True, "data": stats}

        elif cmd == "show_maps":
            maps = self.observer.dump_maps()
            return {"ok": True, "data": maps}

        elif cmd == "show_interfaces":
            all_ifaces = self.manager.get_interfaces()
            attached = set(self.manager.get_attached_interfaces())
            iface_list = []
            for name, idx in all_ifaces.items():
                iface_list.append({
                    "name": name,
                    "ifindex": idx,
                    "attached": name in attached,
                })
            return {"ok": True, "data": iface_list}

        elif cmd == "show_internals":
            return {"ok": True, "data": self.manager.get_internals()}

        elif cmd == "reload":
            files = req.get("files", [])
            if not files:
                return {"ok": False, "error": "No rule files specified"}
            try:
                new_policy = load_policy(files)
                # Change reporting is intentionally human-oriented. The real
                # behavior is in PolicyManager.update_policy(), which stages TC
                # hook reconciliation and writes the accepted policy into eBPF
                # maps before the daemon swaps its active Policy IR.
                changes = new_policy.diff(self.policy)
                runtime_changes = self.manager.update_policy(new_policy)
                changes.extend(_format_runtime_changes(runtime_changes))
                self.policy = new_policy
                self.rules = new_policy.rules
                self.observer = Observer(new_policy.rules)
                return {"ok": True, "data": changes}
            except Exception as e:
                return {"ok": False, "error": str(e)}

        else:
            return {"ok": False, "error": f"Unknown command: {cmd}"}

    def _format_match(self, rule) -> str:
        parts = []
        m = rule.match
        if m.dscp is not None:
            parts.append(f"dscp={m.dscp}")
        if m.dst_ip is not None:
            parts.append(f"dst={m.dst_ip}")
        if m.src_ip is not None:
            parts.append(f"src={m.src_ip}")
        if m.ip_proto != "any":
            parts.append(f"proto={m.ip_proto}")
        return " ".join(parts) if parts else "any"

    def _format_action(self, rule) -> str:
        from engine.models import SteerAction, ReplicateAction
        a = rule.action
        if isinstance(a, SteerAction):
            return f"via={a.via} -> {a.dst_ip}"
        elif isinstance(a, ReplicateAction):
            ifaces = " ".join(t.via for t in a.targets)
            return f"{len(a.targets)} targets: {ifaces}"
        return ""


def _format_runtime_changes(runtime_changes: dict) -> list[str]:
    """Format TC/eBPF runtime changes for the reload response."""
    changes: list[str] = []
    for iface in runtime_changes.get("attached", []):
        changes.append(f"  ATTACHED  {iface:<20s} TC ingress")
    for iface in runtime_changes.get("detached", []):
        changes.append(f"  DETACHED  {iface:<20s} TC ingress")

    maps = runtime_changes.get("maps", {})
    if maps:
        map_summary = ", ".join(
            f"{name}={count}" for name, count in sorted(maps.items())
        )
        changes.append(f"  UPDATED   eBPF maps: {map_summary}")
    return changes


def start_daemon(policy, manager):
    """Fork a daemon process and return its pid to the CLI parent.

    The child inherits the loaded `PolicyManager`, which is useful here: the
    same process that attached TC filters becomes responsible for later reloads
    and cleanup.
    """
    ensure_runtime_dir()

    # Fork
    pid = os.fork()
    if pid > 0:
        # Parent: wait briefly for the socket to appear
        import time
        for _ in range(50):
            if os.path.exists(SOCK_PATH):
                return pid
            time.sleep(0.1)
        return pid

    # Child: become session leader
    os.setsid()

    # Redirect stdio to /dev/null
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    os.close(devnull)

    observer = Observer(policy.rules)
    daemon = Daemon(manager, observer, policy)
    daemon.run()
    os._exit(0)


def send_command(cmd: str, **kwargs) -> dict:
    """Send a one-shot command to the running daemon and decode its JSON reply."""
    if not os.path.exists(SOCK_PATH):
        return {"ok": False, "error": "Rudder is not running. Use 'sudo rudder load' first."}

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(SOCK_PATH)
        req = {"cmd": cmd}
        req.update(kwargs)
        sock.sendall((json.dumps(req) + "\n").encode())

        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break

        return json.loads(data.decode().strip())
    except ConnectionRefusedError:
        return {"ok": False, "error": "Rudder is not running. Use 'sudo rudder load' first."}
    finally:
        sock.close()
