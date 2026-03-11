"""Background daemon that holds PolicyManager state and serves CLI requests.

Communicates via a Unix domain socket at /tmp/rudder.sock using
newline-delimited JSON. Spawned via os.fork() + os.setsid() from
'rudder load'.
"""

import json
import os
import signal
import socket
import sys
import threading
from pathlib import Path

from engine.loader import load_rules
from engine.manager import PolicyManager
from engine.observer import Observer


SOCK_PATH = "/tmp/rudder.sock"


class Daemon:
    def __init__(self, manager: PolicyManager, observer: Observer, rules: list):
        self.manager = manager
        self.observer = observer
        self.rules = rules
        self._running = False

    def run(self):
        """Main daemon loop. Listens on Unix socket for JSON commands."""
        self._running = True

        # Clean up stale socket
        if os.path.exists(SOCK_PATH):
            os.unlink(SOCK_PATH)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(SOCK_PATH)
        server.listen(5)
        server.settimeout(1.0)

        # Handle SIGTERM for clean shutdown
        def _sigterm(signum, frame):
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
                pass

    def _handle_connection(self, conn: socket.socket):
        """Process a single client connection."""
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break

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

        elif cmd == "reload":
            files = req.get("files", [])
            if not files:
                return {"ok": False, "error": "No rule files specified"}
            try:
                new_rules = load_rules(files)
                old_names = {r.name for r in self.rules}
                new_names = {r.name for r in new_rules}

                changes = []
                for r in new_rules:
                    if r.name not in old_names:
                        changes.append(f"  ADDED     {r.name:<20s} priority={r.priority}")
                for r in self.rules:
                    if r.name not in new_names:
                        changes.append(f"  REMOVED   {r.name:<20s} priority={r.priority}")
                for r in new_rules:
                    if r.name in old_names:
                        old_r = next(o for o in self.rules if o.name == r.name)
                        if r.action != old_r.action or r.match != old_r.match:
                            changes.append(f"  MODIFIED  {r.name:<20s}")

                self.manager.update_maps(new_rules)
                self.rules = new_rules
                self.observer = Observer(new_rules)
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


def start_daemon(rules, manager):
    """Fork a daemon process. Parent returns after daemon signals readiness."""
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

    observer = Observer(rules)
    daemon = Daemon(manager, observer, rules)
    daemon.run()
    os._exit(0)


def send_command(cmd: str, **kwargs) -> dict:
    """Send a command to the running daemon and return the response."""
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
