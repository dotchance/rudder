#include "maps.h"

/* Per-program maps with steer-specific names for pinning */
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
} steer_hit_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} steer_trace_events SEC(".maps");

/* Compute a network mask from prefix length (in network byte order) */
static __always_inline __u32 prefix_mask(__u32 len)
{
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

    /* Parse IP header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u8 dscp = (iph->tos >> 2) & 0x3F;
    __u8 ip_proto = iph->protocol;
    __u32 ingress_ifindex = ctx->ingress_ifindex;

    /* Iterate steer_rules array in priority order */
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

        /* First match found -- apply steer action */
        __u32 old_dst_ip = dst_ip;
        __u32 new_dst_ip = rule->new_dst_ip;

        /* Rewrite destination IP in packet.
         * Offset of daddr within IP header: ETH_HLEN + offsetof(iphdr, daddr)
         * offsetof(iphdr, daddr) = 16 */
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

        /* Fix IP header checksum.
         * IP checksum offset: ETH_HLEN + offsetof(iphdr, check) = 14 + 10 = 24 */
        bpf_l3_csum_replace(ctx, ETH_HLEN + 10, old_dst_ip, new_dst_ip, 4);

        /* Fix L4 checksum if TCP or UDP */
        if (ip_proto == IPPROTO_TCP) {
            /* TCP checksum offset: ETH_HLEN + ihl*4 + offsetof(tcphdr, check)
             * Minimum IHL=5 -> 14 + 20 + 16 = 50 */
            bpf_l4_csum_replace(ctx, ETH_HLEN + 20 + 16, old_dst_ip,
                                new_dst_ip, 4 | BPF_F_PSEUDO_HDR);
        } else if (ip_proto == IPPROTO_UDP) {
            /* UDP checksum offset: ETH_HLEN + ihl*4 + offsetof(udphdr, check)
             * 14 + 20 + 6 = 40 */
            bpf_l4_csum_replace(ctx, ETH_HLEN + 20 + 6, old_dst_ip,
                                new_dst_ip, 4 | BPF_F_PSEUDO_HDR);
        }

        /* Rewrite destination MAC (first 6 bytes of Ethernet header) */
        bpf_skb_store_bytes(ctx, 0, rule->dst_mac, 6, 0);

        /* Re-validate pointers after MAC rewrite */
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        /* Increment hit counter */
        __u32 ckey = rule->rule_id;
        __u64 *counter = bpf_map_lookup_elem(&steer_hit_counters, &ckey);
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
        bpf_perf_event_output(ctx, &steer_trace_events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));

        return bpf_redirect(rule->egress_ifindex, 0);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
