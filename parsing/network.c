#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include "../network_monitor.h"
#include "./utils.c"

int parse_ipv4(void *start, void *data_end, void **transport_start, struct stats_key *key)
{
    struct iphdr *l2_hdr = start;
    if (start + sizeof(*l2_hdr) > data_end)
    {
        return TC_ACT_SHOT;
    }

    *transport_start = start + sizeof(*l2_hdr);

    key->l3_proto = l2_hdr->protocol;
    key->src_addr.ipv4 = bpf_ntohl(l2_hdr->saddr);
    key->dst_addr.ipv4 = bpf_ntohl(l2_hdr->daddr);

    return 0;
}

int parse_ipv6(void *start, void *data_end, void **transport_start, struct stats_key *key)
{
    struct ipv6hdr *l2_hdr = start;
    if (start + sizeof(*l2_hdr) > data_end)
    {
        return TC_ACT_SHOT;
    }

    *transport_start = start + sizeof(*l2_hdr);

    key->l3_proto = l2_hdr->nexthdr;
    copy_char_array_16(key->src_addr.ipv6, l2_hdr->saddr.in6_u.u6_addr8);
    copy_char_array_16(key->dst_addr.ipv6, l2_hdr->daddr.in6_u.u6_addr8);

    return 0;
}

int parse_network_layer(void *start, void *data_end, void **transport_start, struct stats_key *key)
{
    int err;

    switch (key->l2_proto)
    {
    case ETH_P_IP:
        err = parse_ipv4(start, data_end, transport_start, key);
        break;
    case ETH_P_IPV6:
        err = parse_ipv6(start, data_end, transport_start, key);
        break;
    default:
        err = TC_ACT_OK;
        break;
    }

    return err;
}
