#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include "../network_monitor.h"

int parse_eth(void *start, void *data_end, void **network_start, struct stats_key *key)
{
    struct ethhdr *eth = start;
    if (start + sizeof(*eth) > data_end)
    {
        return TC_ACT_SHOT;
    }

    *network_start = start + sizeof(*eth);

    key->l2_proto = bpf_ntohs(eth->h_proto);

    return 0;
}
