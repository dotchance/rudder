#include "maps.h"

/* Per-program maps with replicate-specific names for pinning */
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
} replicate_hit_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} replicate_trace_events SEC(".maps");

/* Compute a network mask from prefix length (in network byte order) */
static __always_inline __u32 prefix_mask(__u32 len)
{
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

    /* Parse IP header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    /* Only process multicast destinations (224.0.0.0/4) */
    if ((bpf_ntohl(iph->daddr) & 0xF0000000) != 0xE0000000)
        return TC_ACT_OK;

    __u32 src_ip = iph->saddr;
    __u32 orig_dst_ip = iph->daddr;
    __u8 ip_proto = iph->protocol;
    __u32 ingress_ifindex = ctx->ingress_ifindex;

    /* Save original destination MAC for restoration between clones */
    __u8 orig_dst_mac[6];
    __builtin_memcpy(orig_dst_mac, eth->h_dest, 6);

    /* Iterate replicate_rules array in priority order */
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

        /* First match found -- replicate to all targets */
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
            bpf_skb_store_bytes(ctx, ETH_HLEN + 16, &new_dst_ip, 4, 0);

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
            bpf_l3_csum_replace(ctx, ETH_HLEN + 10, orig_dst_ip, new_dst_ip, 4);

            /* Fix L4 checksum if TCP or UDP */
            if (ip_proto == IPPROTO_TCP) {
                bpf_l4_csum_replace(ctx, ETH_HLEN + 20 + 16, orig_dst_ip,
                                    new_dst_ip, 4 | BPF_F_PSEUDO_HDR);
            } else if (ip_proto == IPPROTO_UDP) {
                bpf_l4_csum_replace(ctx, ETH_HLEN + 20 + 6, orig_dst_ip,
                                    new_dst_ip, 4 | BPF_F_PSEUDO_HDR);
            }

            /* Rewrite destination MAC */
            bpf_skb_store_bytes(ctx, 0, target->dst_mac, 6, 0);

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
                __u64 *counter = bpf_map_lookup_elem(&replicate_hit_counters, &ckey);
                if (counter)
                    __sync_fetch_and_add(counter, 1);

                evt.event_type = 2; /* replicate_final */
                bpf_perf_event_output(ctx, &replicate_trace_events,
                                      BPF_F_CURRENT_CPU, &evt, sizeof(evt));

                return bpf_redirect(target->egress_ifindex, 0);
            }

            /* Not the last target: clone and redirect */
            evt.event_type = 1; /* replicate_clone */
            bpf_perf_event_output(ctx, &replicate_trace_events,
                                  BPF_F_CURRENT_CPU, &evt, sizeof(evt));

            bpf_clone_redirect(ctx, target->egress_ifindex, 0);

            /* Restore original destination IP for next iteration.
             * The checksum fixup uses orig_dst_ip as old value,
             * so we restore the IP and let the next iteration re-apply. */
            bpf_skb_store_bytes(ctx, ETH_HLEN + 16, &orig_dst_ip, 4, 0);

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
            bpf_l3_csum_replace(ctx, ETH_HLEN + 10, new_dst_ip, orig_dst_ip, 4);

            /* Restore L4 checksum */
            if (ip_proto == IPPROTO_TCP) {
                bpf_l4_csum_replace(ctx, ETH_HLEN + 20 + 16, new_dst_ip,
                                    orig_dst_ip, 4 | BPF_F_PSEUDO_HDR);
            } else if (ip_proto == IPPROTO_UDP) {
                bpf_l4_csum_replace(ctx, ETH_HLEN + 20 + 6, new_dst_ip,
                                    orig_dst_ip, 4 | BPF_F_PSEUDO_HDR);
            }

            /* Restore original destination MAC */
            bpf_skb_store_bytes(ctx, 0, orig_dst_mac, 6, 0);

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

char _license[] SEC("license") = "GPL";
