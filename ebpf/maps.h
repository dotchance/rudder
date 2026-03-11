#ifndef RUDDER_MAPS_H
#define RUDDER_MAPS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_RULES    64
#define MAX_TARGETS  12

/* Steer rule entry. One slot per rule in the steer_rules array.
 * Python engine writes these in priority order starting at slot 0. */
struct steer_rule {
    __u32 valid;              /* 0 = empty slot, stop iteration. 1 = active rule. */
    __u32 rule_id;            /* Matches Python-assigned rule_id for counter indexing. */
    __u32 ingress_ifindex;    /* 0 = match any interface. */
    __u32 src_ip;             /* Network byte order. 0 = match any. */
    __u32 src_prefix_len;     /* 0-32. 0 with src_ip=0 means match any. */
    __u32 dst_ip;             /* Network byte order. 0 = match any. */
    __u32 dst_prefix_len;     /* 0-32. */
    __u8  dscp;               /* 0xFF = match any DSCP value. */
    __u8  ip_proto;           /* 0 = any, 6 = TCP, 17 = UDP. */
    __u8  pad[2];
    /* Action fields */
    __u32 new_dst_ip;         /* Rewritten destination IP. Network byte order. */
    __u32 egress_ifindex;     /* Resolved at load time by Python engine. */
    __u8  dst_mac[6];         /* Next hop MAC. Resolved via ARP or statically configured. */
    __u8  action_pad[2];
};

/* Replicate rule entry. One slot per rule in the replicate_rules array. */
struct replicate_target {
    __u32 dst_ip;             /* Rewritten unicast destination. Network byte order. */
    __u32 egress_ifindex;
    __u8  dst_mac[6];
    __u8  pad[2];
};

struct replicate_rule {
    __u32 valid;
    __u32 rule_id;
    __u32 ingress_ifindex;    /* 0 = any */
    __u32 dst_ip;             /* Multicast group to match. Network byte order. */
    __u32 dst_prefix_len;
    __u8  pad[4];
    __u32 target_count;
    struct replicate_target targets[MAX_TARGETS];
};

/* Trace event emitted to perf buffer on every rule match. */
struct trace_event {
    __u64 timestamp_ns;       /* bpf_ktime_get_ns() at match time. */
    __u32 rule_id;
    __u32 src_ip;
    __u32 orig_dst_ip;
    __u32 new_dst_ip;
    __u32 egress_ifindex;
    __u8  event_type;         /* 0=steer, 1=replicate_clone, 2=replicate_final */
    __u8  pad[3];
};

#endif /* RUDDER_MAPS_H */
