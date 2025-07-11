#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include "../network_monitor.h"

int parse_tcp(void *start, void *data_end, struct stats_key *key)
{
    struct tcphdr *hdr = start;
    if (start + sizeof(*hdr) > data_end)
    {
        return TC_ACT_SHOT;
    }

    key->src_port = bpf_ntohl(hdr->source);
    key->dst_port = bpf_ntohl(hdr->dest);

    return 0;
}

int parse_udp(void *start, void *data_end, struct stats_key *key)
{
    struct udphdr *hdr = start;
    if (start + sizeof(*hdr) > data_end)
    {
        return TC_ACT_SHOT;
    }

    key->src_port = bpf_ntohl(hdr->source);
    key->dst_port = bpf_ntohl(hdr->dest);

    return 0;
}

int parse_transport_layer(void *start, void *data_end, struct stats_key *key)
{
    if (start == 0) {
        return 0;
    }

    int err;

    switch (key->l2_proto)
    {
    case 6:
        err = parse_tcp(start, data_end, key);
        break;
    case 17:
        err = parse_udp(start, data_end, key);
        break;
    default:
        err = TC_ACT_OK;
        break;
    }

    return err;
}
