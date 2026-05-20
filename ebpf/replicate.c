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
 * Like steer.c, every TC object load gets its own maps. The Python manager
 * keeps those per-interface map instances synchronized during load/reload.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct replicate_rule);
} replicate_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, __u64);
} repl_hits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} repl_events SEC(".maps");

/* Compute a network mask from prefix length (in network byte order) */
static __always_inline __u32 prefix_mask(__u32 len)
{
    /* See steer.c for the network-order reasoning. Keeping a local helper in
     * each program makes the examples self-contained for readers. */
    if (len == 0)
        return 0;
    if (len >= 32)
        return 0xFFFFFFFF;
    return bpf_htonl(~((__u32)0) << (32 - len));
}

SEC("classifier")
int repl_main(struct __sk_buff *ctx)
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
     * Replication rewrites destination IPs repeatedly on the same skb before
     * cloning. That is only straightforward for complete, non-fragmented IPv4
     * packets, so fragments are passed through unchanged for now.
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

    /* Only process multicast destinations (224.0.0.0/4) */
    if ((bpf_ntohl(iph->daddr) & 0xF0000000) != 0xE0000000)
        return TC_ACT_OK;

    __u32 src_ip = iph->saddr;
    __u32 orig_dst_ip = iph->daddr;
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
        should_update_l4 = (udph->check != 0);
    }

    /* Save original destination MAC for restoration between clones */
    __u8 orig_dst_mac[6];
    __builtin_memcpy(orig_dst_mac, eth->h_dest, 6);

    /* Iterate replicate_rules in priority order. The first matching rule owns
     * the packet and produces all configured unicast outputs. */
    for (int i = 0; i < MAX_RULES; i++) {
        __u32 key = i;
        struct replicate_rule *rule = bpf_map_lookup_elem(&replicate_rules, &key);
        if (!rule || !rule->valid)
            break;

        /* Match ingress interface */
        if (rule->ingress_ifindex != 0 &&
            rule->ingress_ifindex != ingress_ifindex)
            continue;

        /* Match destination IP with prefix */
        if (rule->dst_ip != 0) {
            __u32 mask = prefix_mask(rule->dst_prefix_len);
            if ((orig_dst_ip & mask) != (rule->dst_ip & mask))
                continue;
        }

        /* First match found: clone for every target except the last one, then
         * redirect the original skb to the final target. This avoids needing
         * an extra clone for the last copy. */
        __u32 tcount = rule->target_count;
        if (tcount == 0 || tcount > MAX_TARGETS)
            break;

        for (int t = 0; t < MAX_TARGETS; t++) {
            if (t >= (int)tcount)
                break;

            struct replicate_target *target = &rule->targets[t];
            __u32 new_dst_ip = target->dst_ip;
            int is_last = (t == (int)tcount - 1);

            /* Rewrite destination IP */
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

            /* Fix IP header checksum */
            if (bpf_l3_csum_replace(ctx, ETH_HLEN + IP_CHECK_OFFSET,
                                    orig_dst_ip, new_dst_ip, 4) < 0)
                return TC_ACT_SHOT;

            if (should_update_l4) {
                if (bpf_l4_csum_replace(ctx, l4_csum_offset, orig_dst_ip,
                                        new_dst_ip, 4 | BPF_F_PSEUDO_HDR) < 0)
                    return TC_ACT_SHOT;
            }

            /* Rewrite destination MAC */
            if (bpf_skb_store_bytes(ctx, 0, target->dst_mac, 6, 0) < 0)
                return TC_ACT_SHOT;

            /* Re-validate pointers after MAC rewrite */
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;

            /* Emit trace event */
            struct trace_event evt = {};
            evt.timestamp_ns = bpf_ktime_get_ns();
            evt.rule_id = rule->rule_id;
            evt.src_ip = src_ip;
            evt.orig_dst_ip = orig_dst_ip;
            evt.new_dst_ip = new_dst_ip;
            evt.egress_ifindex = target->egress_ifindex;

            if (is_last) {
                /* Last target: increment counter, redirect the original skb */
                __u32 ckey = rule->rule_id;
                __u64 *counter = bpf_map_lookup_elem(&repl_hits, &ckey);
                if (counter)
                    __sync_fetch_and_add(counter, 1);

                evt.event_type = 2; /* replicate_final */
                bpf_perf_event_output(ctx, &repl_events,
                                      BPF_F_CURRENT_CPU, &evt, sizeof(evt));

                return bpf_redirect(target->egress_ifindex, 0);
            }

            /* Not the last target: clone the current skb and redirect that
             * clone. The original skb is restored below so the next target
             * starts from the multicast packet again. */
            evt.event_type = 1; /* replicate_clone */
            bpf_perf_event_output(ctx, &repl_events,
                                  BPF_F_CURRENT_CPU, &evt, sizeof(evt));

            bpf_clone_redirect(ctx, target->egress_ifindex, 0);

            /* Restore original destination IP for next iteration.
             * The checksum fixup uses orig_dst_ip as old value,
             * so we restore the IP and let the next iteration re-apply. */
            if (bpf_skb_store_bytes(ctx, ETH_HLEN + IP_DADDR_OFFSET,
                                    &orig_dst_ip, 4, 0) < 0)
                return TC_ACT_SHOT;

            /* Re-validate after restore */
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return TC_ACT_SHOT;
            iph = (void *)(eth + 1);
            if ((void *)(iph + 1) > data_end)
                return TC_ACT_SHOT;

            /* Restore IP checksum back to original */
            if (bpf_l3_csum_replace(ctx, ETH_HLEN + IP_CHECK_OFFSET,
                                    new_dst_ip, orig_dst_ip, 4) < 0)
                return TC_ACT_SHOT;

            if (should_update_l4) {
                if (bpf_l4_csum_replace(ctx, l4_csum_offset, new_dst_ip,
                                        orig_dst_ip, 4 | BPF_F_PSEUDO_HDR) < 0)
                    return TC_ACT_SHOT;
            }

            /* Restore original destination MAC */
            if (bpf_skb_store_bytes(ctx, 0, orig_dst_mac, 6, 0) < 0)
                return TC_ACT_SHOT;

            /* Re-validate after MAC restore */
            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
        }

        /* Should not reach here (last target returns above),
         * but satisfy the compiler */
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

/* The kernel eBPF loader reads this ELF section during program load. The
 * string controls access to helpers that the kernel marks as GPL-only; several
 * packet rewrite/redirect helpers used above are gated by that check. */
char _license[] SEC("license") = "GPL";
