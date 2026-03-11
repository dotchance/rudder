"""Ctypes-based perf event buffer reader for BPF perf event arrays.

Reads trace events from pinned BPF perf event array maps without
requiring BCC. Uses raw syscalls via ctypes to:
  1. Get an FD for the pinned perf event array (bpf(BPF_OBJ_GET))
  2. Open perf events per CPU
  3. Mmap ring buffers
  4. Poll with select() and deserialize events
"""

import ctypes
import ctypes.util
import mmap
import os
import select
import struct
from pathlib import Path


# BPF syscall command constants
BPF_OBJ_GET = 7
BPF_MAP_UPDATE_ELEM = 2

# Perf event constants
PERF_TYPE_SOFTWARE = 1
PERF_COUNT_SW_BPF_OUTPUT = 10
PERF_SAMPLE_RAW = 1024
PERF_FLAG_FD_CLOEXEC = 8

# Page size for mmap
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MMAP_PAGES = 8  # Number of data pages per ring buffer (must be power of 2)

# Syscall numbers (x86_64)
SYS_BPF = 321
SYS_PERF_EVENT_OPEN = 298

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


class PerfEventAttr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("size", ctypes.c_uint),
        ("config", ctypes.c_ulong),
        ("sample_period_or_freq", ctypes.c_ulong),
        ("sample_type", ctypes.c_ulong),
        ("read_format", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("wakeup_events_or_watermark", ctypes.c_uint),
        ("bp_type", ctypes.c_uint),
        ("bp_addr_or_config1", ctypes.c_ulong),
        ("bp_len_or_config2", ctypes.c_ulong),
        ("branch_sample_type", ctypes.c_ulong),
        ("sample_regs_user", ctypes.c_ulong),
        ("sample_stack_user", ctypes.c_uint),
        ("clockid", ctypes.c_int),
        ("sample_regs_intr", ctypes.c_ulong),
        ("aux_watermark", ctypes.c_uint),
        ("sample_max_stack", ctypes.c_ushort),
        ("reserved_2", ctypes.c_ushort),
    ]


class BpfAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_ulong),
        ("bpf_fd", ctypes.c_uint),
        ("file_flags", ctypes.c_uint),
    ]


class BpfAttrMapUpdate(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint),
        ("key", ctypes.c_ulong),
        ("value_or_next_key", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
    ]


def _sys_bpf(cmd, attr, size):
    return libc.syscall(SYS_BPF, cmd, ctypes.byref(attr), size)


def _bpf_obj_get(pin_path: str) -> int:
    """Get FD for a pinned BPF object."""
    path_bytes = pin_path.encode() + b"\x00"
    path_buf = ctypes.create_string_buffer(path_bytes)
    attr = BpfAttrObjGet()
    attr.pathname = ctypes.addressof(path_buf)
    attr.bpf_fd = 0
    attr.file_flags = 0
    fd = _sys_bpf(BPF_OBJ_GET, attr, ctypes.sizeof(attr))
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"BPF_OBJ_GET failed for {pin_path}: {os.strerror(errno)}")
    return fd


def _perf_event_open(cpu: int) -> int:
    """Open a perf event for BPF output on a specific CPU."""
    attr = PerfEventAttr()
    attr.type = PERF_TYPE_SOFTWARE
    attr.size = ctypes.sizeof(PerfEventAttr)
    attr.config = PERF_COUNT_SW_BPF_OUTPUT
    attr.sample_type = PERF_SAMPLE_RAW
    attr.wakeup_events_or_watermark = 1

    fd = libc.syscall(
        SYS_PERF_EVENT_OPEN,
        ctypes.byref(attr),
        -1,   # pid: all processes
        cpu,
        -1,   # group_fd
        PERF_FLAG_FD_CLOEXEC,
    )
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"perf_event_open failed for CPU {cpu}: {os.strerror(errno)}")
    return fd


def _bpf_map_update(map_fd: int, key_int: int, value_int: int):
    """Update a BPF map entry (used to set perf event FDs in the array)."""
    key = ctypes.c_uint(key_int)
    value = ctypes.c_uint(value_int)
    attr = BpfAttrMapUpdate()
    attr.map_fd = map_fd
    attr.key = ctypes.addressof(key)
    attr.value_or_next_key = ctypes.addressof(value)
    attr.flags = 0  # BPF_ANY
    ret = _sys_bpf(BPF_MAP_UPDATE_ELEM, attr, ctypes.sizeof(attr))
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"BPF_MAP_UPDATE_ELEM failed: {os.strerror(errno)}")


# struct trace_event layout: timestamp_ns(u64) rule_id(u32) src_ip(u32)
#   orig_dst_ip(u32) new_dst_ip(u32) egress_ifindex(u32) event_type(u8) pad(3x)
TRACE_EVENT_FMT = "=QIIIII B3x"
TRACE_EVENT_SIZE = struct.calcsize(TRACE_EVENT_FMT)


class PerfReader:
    """Read perf events from a pinned BPF perf event array map."""

    def __init__(self, pin_path: str):
        self._pin_path = pin_path
        self._map_fd = -1
        self._perf_fds: list[int] = []
        self._mmaps: list[mmap.mmap] = []
        self._num_cpus = os.cpu_count() or 1
        self._ring_size = (1 + MMAP_PAGES) * PAGE_SIZE
        self._opened = False

    def open(self):
        """Set up perf events and mmap ring buffers for all CPUs."""
        self._map_fd = _bpf_obj_get(self._pin_path)

        for cpu in range(self._num_cpus):
            try:
                pfd = _perf_event_open(cpu)
            except OSError:
                # CPU may be offline
                continue

            # Mmap the ring buffer: 1 metadata page + MMAP_PAGES data pages
            buf = mmap.mmap(
                pfd,
                self._ring_size,
                mmap.MAP_SHARED,
                mmap.PROT_READ | mmap.PROT_WRITE,
            )

            # Tell the BPF perf event array about this perf FD
            _bpf_map_update(self._map_fd, cpu, pfd)

            # Enable the perf event via ioctl
            import fcntl
            PERF_EVENT_IOC_ENABLE = 0x2400
            fcntl.ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0)

            self._perf_fds.append(pfd)
            self._mmaps.append(buf)

        self._opened = True

    def close(self):
        """Clean up FDs and mmaps."""
        for buf in self._mmaps:
            buf.close()
        for fd in self._perf_fds:
            os.close(fd)
        if self._map_fd >= 0:
            os.close(self._map_fd)
        self._mmaps.clear()
        self._perf_fds.clear()
        self._map_fd = -1
        self._opened = False

    def poll(self, callback, timeout_ms: int = 100):
        """Poll for events and invoke callback with parsed trace_event tuples.

        callback receives: (timestamp_ns, rule_id, src_ip, orig_dst_ip,
                           new_dst_ip, egress_ifindex, event_type)
        """
        if not self._opened:
            raise RuntimeError("PerfReader not opened")

        readable, _, _ = select.select(self._perf_fds, [], [], timeout_ms / 1000.0)

        for i, pfd in enumerate(self._perf_fds):
            if pfd not in readable:
                continue
            self._read_ring(i, callback)

    def _read_ring(self, idx: int, callback):
        """Read all available events from a CPU ring buffer."""
        buf = self._mmaps[idx]
        data_offset = PAGE_SIZE
        data_size = MMAP_PAGES * PAGE_SIZE

        # Read metadata page: data_head is at offset 0 (8 bytes),
        # data_tail at offset 8 (after we manually track it)
        buf.seek(0)
        metadata = buf.read(16)
        data_head = struct.unpack("Q", metadata[:8])[0]

        # We track tail ourselves via the metadata page offset 8*1
        data_tail_raw = struct.unpack("Q", metadata[8:16])[0]
        data_tail = data_tail_raw

        while data_tail < data_head:
            # Perf event header: type(u32) misc(u16) size(u16)
            offset = data_offset + (data_tail % data_size)
            buf.seek(offset)
            hdr_data = buf.read(8)
            if len(hdr_data) < 8:
                break
            event_type, misc, event_size = struct.unpack("IHH", hdr_data)

            if event_type == 9:  # PERF_RECORD_SAMPLE
                # Sample: size(u32) + raw data
                sample_hdr = buf.read(4)
                if len(sample_hdr) < 4:
                    break
                raw_size = struct.unpack("I", sample_hdr)[0]
                if raw_size >= TRACE_EVENT_SIZE:
                    raw_data = buf.read(TRACE_EVENT_SIZE)
                    if len(raw_data) == TRACE_EVENT_SIZE:
                        parsed = struct.unpack(TRACE_EVENT_FMT, raw_data)
                        callback(parsed)

            data_tail += event_size

        # Update data_tail in the metadata page
        buf.seek(8)
        buf.write(struct.pack("Q", data_tail))
