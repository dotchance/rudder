# Copyright 2025-2026 .chance (dotchance)
# Licensed under the Apache License, Version 2.0. See LICENSE file.

"""Runtime paths for root-owned rudder state.

Rudder is intentionally a small teaching-oriented control plane, so these
paths stay explicit. The Unix socket and temporary eBPF object files are
runtime state, not user configuration, and should live in a root-owned runtime
directory rather than in a world-writable directory such as /tmp.
"""

import os
import stat
from pathlib import Path


RUNTIME_DIR = Path(os.environ.get("RUDDER_RUNTIME_DIR", "/run/rudder"))
SOCK_PATH = str(RUNTIME_DIR / "rudder.sock")
STEER_OBJ = str(RUNTIME_DIR / "rudder_steer.o")
REPLICATE_OBJ = str(RUNTIME_DIR / "rudder_replicate.o")


def ensure_runtime_dir() -> None:
    """Create the runtime directory and restrict it to the current uid.

    The CLI already requires root, but keeping the directory owner-only makes
    the daemon socket and compiled object paths harder to spoof accidentally.
    This function is cheap and deliberately called from both parent and daemon
    startup paths so the invariant is local to every privileged entry point.
    """
    if RUNTIME_DIR.exists() and not RUNTIME_DIR.is_dir():
        raise RuntimeError(f"{RUNTIME_DIR} exists but is not a directory")

    RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    st = RUNTIME_DIR.stat()
    if st.st_uid != os.geteuid():
        raise RuntimeError(
            f"{RUNTIME_DIR} must be owned by uid {os.geteuid()}, found uid {st.st_uid}"
        )

    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        os.chmod(RUNTIME_DIR, 0o700)
