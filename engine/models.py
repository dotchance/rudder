from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from typing import Optional

MAX_RULES = 64
MAX_TARGETS = 12


@dataclass
class MatchSet:
    interface: str                        # interface name or "any"
    src_ip: Optional[IPv4Network] = None
    dst_ip: Optional[IPv4Network] = None
    dscp: Optional[int] = None            # 0-63
    ip_proto: str = "any"                 # "any", "tcp", "udp"


@dataclass
class SteerAction:
    dst_ip: IPv4Address
    via: str
    next_hop_mac: Optional[str] = None    # "aa:bb:cc:dd:ee:ff" format


@dataclass
class ReplicationTarget:
    dst_ip: IPv4Address
    via: str
    next_hop_mac: Optional[str] = None


@dataclass
class ReplicateAction:
    targets: list[ReplicationTarget] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    priority: int
    rule_id: int                          # Slot index assigned by loader: 0..N-1
    type: str                             # "steer" or "replicate"
    match: MatchSet
    action: SteerAction | ReplicateAction
    source_file: str                      # YAML file this rule came from
