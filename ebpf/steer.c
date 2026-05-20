/*
 * Copyright 2025-2026 .chance (dotchance)
 * Licensed under the Apache License, Version 2.0. See LICENSE file.
 */

#include "maps.h"

#define IP_CHECK_OFFSET   10
#define IP_DADDR_OFFSET   16
#define TCP_CHECK_OFFSET  16
#define UDP_CHECK_OFFSET  6

/* Per-program maps.
 *
 * TC loads this object once per attached interface. Each load gets its own map
 * instances, so userspace discovers all maps named `steer_rules`/`steer_hits`
 * and writes the same policy into each one.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct steer_rule);
} steer_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, __u64);
} steer_hits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} steer_events SEC(".maps");

/* Compute a network mask from prefix length (in network byte order) */
static __always_inline __u32 prefix_mask(__u32 len)
{
    /* Prefixes are compared against IPv4 addresses stored in network byte
     * order. Building the mask in host order and converting once keeps the
     * rule-matching code readable. */
    if (len == 0)
        return 0;
    if (len >= 32)
        return 0xFFFFFFFF;
    /* Build host-order mask, then convert to network order.
     * Example: len=8 -> 0xFF000000 in host order -> network order. */
    return bpf_htonl(~((__u32)0) << (32 - len));
}

SEC("classifier")
int steer_main(struct __sk_buff *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Parse IP header.
     *
     * The first version of rudder assumed the common 20-byte IPv4 header.
     * For teaching and correctness, keep the parser explicit: IHL tells us
     * where L4 begins, and fragmented packets are skipped until rudder grows
     * fragment-aware rewrite logic.
     */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    if (iph->ihl < 5)
        return TC_ACT_OK;

    __u32 ip_header_len = iph->ihl * 4;
    if ((void *)iph + ip_header_len > data_end)
        return TC_ACT_OK;

    __u16 frag_off = bpf_ntohs(iph->frag_off);
    if (frag_off & (IP_MF | IP_OFFSET))
        return TC_ACT_OK;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u8 dscp = (iph->tos >> 2) & 0x3F;
    __u8 ip_proto = iph->protocol;
    __u32 ingress_ifindex = ctx->ingress_ifindex;
    __u32 l4_csum_offset = 0;
    int should_update_l4 = 0;

    if (ip_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + ip_header_len;
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;
        l4_csum_offset = ETH_HLEN + ip_header_len + TCP_CHECK_OFFSET;
        should_update_l4 = 1;
    } else if (ip_proto == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + ip_header_len;
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
        l4_csum_offset = ETH_HLEN + ip_header_len + UDP_CHECK_OFFSET;
        /* IPv4 UDP checksum 0 means "checksum disabled"; do not create one. */
        should_update_l4 = (udph->check != 0);
    }

    /* Iterate steer_rules in priority order. Userspace guarantees active
     * rules are densely packed, so the first invalid slot ends the scan. */
    for (int i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct steer_rule *rule = bpf_map_lookup_elem(&steer_rules, &key);
        if (!rule || !rule->valid)
            break;

        /* Match ingress interface */
        if (rule->ingress_ifindex != 0 &&
            rule->ingress_ifindex != ingress_ifindex)
            continue;

        /* Match destination IP with prefix */
        if (rule->dst_ip != 0) {
            __u32 mask = prefix_mask(rule->dst_prefix_len);
            if ((dst_ip & mask) != (rule->dst_ip & mask))
                continue;
        }

        /* Match source IP with prefix */
        if (rule->src_ip != 0) {
            __u32 mask = prefix_mask(rule->src_prefix_len);
            if ((src_ip & mask) != (rule->src_ip & mask))
                continue;
        }

        /* Match DSCP */
        if (rule->dscp != 0xFF && rule->dscp != dscp)
            continue;

        /* Match IP protocol */
        if (rule->ip_proto != 0 && rule->ip_proto != ip_proto)
            continue;

        /* First match wins. This mirrors policy routing tables and keeps the
         * mental model simple: lower YAML priority number means earlier slot. */
        __u32 old_dst_ip = dst_ip;
        __u32 new_dst_ip = rule->new_dst_ip;

        /* Rewrite destination IP in packet.
         * Offset of daddr within IP header: ETH_HLEN + offsetof(iphdr, daddr)
         * offsetof(iphdr, daddr) = 16 */
        if (bpf_skb_store_bytes(ctx, ETH_HLEN + IP_DADDR_OFFSET,
                                &new_dst_ip, 4, 0) < 0)
            return TC_ACT_SHOT;

        /* Re-validate pointers after skb modification */
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return TC_ACT_SHOT;
        iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_SHOT;

        /* Fix IP header checksum.
         * IP checksum offset: ETH_HLEN + offsetof(iphdr, check) = 14 + 10 = 24 */
        if (bpf_l3_csum_replace(ctx, ETH_HLEN + IP_CHECK_OFFSET,
                                old_dst_ip, new_dst_ip, 4) < 0)
            return TC_ACT_SHOT;

        if (should_update_l4) {
            /* The TCP/UDP pseudo-header includes source/destination IPs, so
             * changing daddr requires an L4 checksum delta as well. */
            if (bpf_l4_csum_replace(ctx, l4_csum_offset, old_dst_ip,
                                    new_dst_ip, 4 | BPF_F_PSEUDO_HDR) < 0)
                return TC_ACT_SHOT;
        }

        /* Rewrite destination MAC (first 6 bytes of Ethernet header) */
        if (bpf_skb_store_bytes(ctx, 0, rule->dst_mac, 6, 0) < 0)
            return TC_ACT_SHOT;

        /* Re-validate pointers after MAC rewrite */
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        /* Increment hit counter */
        __u32 ckey = rule->rule_id;
        __u64 *counter = bpf_map_lookup_elem(&steer_hits, &ckey);
        if (counter)
            __sync_fetch_and_add(counter, 1);

        /* Emit trace event */
        struct trace_event evt = {};
        evt.timestamp_ns = bpf_ktime_get_ns();
        evt.rule_id = rule->rule_id;
        evt.src_ip = src_ip;
        evt.orig_dst_ip = old_dst_ip;
        evt.new_dst_ip = new_dst_ip;
        evt.egress_ifindex = rule->egress_ifindex;
        evt.event_type = 0; /* steer */
        bpf_perf_event_output(ctx, &steer_events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));

        /* Hand the packet to the selected egress interface. TC_ACT_OK would
         * leave it on the ingress path; bpf_redirect() is the steering action. */
        return bpf_redirect(rule->egress_ifindex, 0);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
