#include <errno.h>	     /* Error codes */
#include <linux/bpf.h>	     /* Definition of struct __sk_buff, the parameter
			      * passed to our eBPF program
			      */
#include <linux/pkt_cls.h>   /* Definition of valid return codes for eBPF
			      * programs attached to the TC hook
			      * (e.g. TC_ACT_OK)
			      */
#include <linux/if_ether.h>  /* Definition of struct ethhdr */
#include <linux/ip.h>	     /* Definition of struct iphdr */
#include <linux/tcp.h>	     /* Definition of struct tcphdr */
#include <linux/udp.h>	     /* Definition of struct udphdr */
#include <bpf/bpf_endian.h>  /* Helpers to convert endiannes
			      * (e.g., bpf_ntohs())
			      */
#include <bpf/bpf_helpers.h> /* Other libbpf helpers (e.g., bpf_printk()) */
#include "network_monitor.h"

#include "parsing/datalink.c"
#include "parsing/network.c"

/* Define a hash map with key of type __u16 (the size of the ethertype), value
 * of type struct stats_value and a max size of 1024 elements
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct stats_key);
	__type(value, struct stats_value);
} l3protos_stats SEC(".maps");

/* The main program that will be executed every time the hook is triggered.
 * The SEC("tc") macro provides a hint to libbpf to where the program will be
 * attached.
 * Programs attached to the TC hook receive as input a struct __sk_buff, that
 * contains metadata of the handled packet
 * (https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.hL6103)
 */
SEC("tc")
int tc_prog(struct __sk_buff *ctx)
{
	/* Retrieve pointers to the begin and end of the packet buffer */
	void *data = (void *)(unsigned long)ctx->data;
	void *data_end = (void *)(unsigned long)ctx->data_end;

	/* Initialize the stats key struct */
	struct stats_key key = {0};

	/* Get the L2 protocol from the Ethernet header */
	void *network_start = 0;

	int err = parse_eth(data, data_end, &network_start, &key);
	if (err != 0) {
		return err;
	}

	// TODO: remove
	if (key.l2_proto != ETH_P_IP) {
		return TC_ACT_OK;
	}

	/* Get the L3 protocol from the correct L2 header */
	void *transport_start = 0;

	err = parse_network_layer(network_start, data_end, &transport_start, &key);
	if (err != 0) {
		return err;
	}

	/* Look for an existing entry in the hash map */
	struct stats_value *val;
	val = bpf_map_lookup_elem(&l3protos_stats, &key);

	/* The value might be NULL if there is no element for the given key
	 * (i.e., this is the first packet we process with this ethertype).
	 * The check on the validity of the pointer is MANDATORY even if we know
	 * that it cannot be NULL due to the program logic. Without the check
	 * the eBPF program would be rejected by the verifier at injection time,
	 * as in the case of packet boundary checks
	 */
	if (!val) {
		/* Preapare a new entry for the given ethertype */
		struct stats_value new_val;
		new_val.pkts = 0;
		new_val.bytes = 0;

		/* The eBPF program can be executed concurrently on different
		 * CPU cores, and another core might be creating/updating the
		 * same entry in parallel. To prevent overwriting its values we
		 * use the BPF_NOEXIST flag, that adds the entry only if it
		 * doesn't already exist
		 */
		int rc = bpf_map_update_elem(&l3protos_stats, &key, &new_val, BPF_NOEXIST);
		if (rc != 0 && rc != -EEXIST) {
			/* The update failed (rc != 0), and it's not beacuse the
			 * entry already existed (rc != -EEXIST). The map is
			 * probably full. We let the packet proceed without
			 * counting
			 */
			return TC_ACT_OK;
		}

		/* Retrieve a pointer to the newly inserted value */
		val = bpf_map_lookup_elem(&l3protos_stats, &key);
		if (!val) {
			/* This should never happen, however the check is
			 * MANDATORY for the verifier to guarantee the safety
			 * of the program
			 */
			return TC_ACT_OK;
		}
	}

	/* Since we are updating values concurrently on multiple cores we use
	 * the __sync_fetch_and_add() instruction that guarantees an atomic
	 * operation
	 */
	__sync_fetch_and_add(&val->pkts, 1);
	__sync_fetch_and_add(&val->bytes, (data_end - data));

	/* The bpf_trace_printk() helper can be used to print debug messages to
	 * the kernel trace pipe. The pipe is accessible reading the file
	 * /sys/kernel/debug/tracing/trace_pipe. The function bpf_printk() is a
	 * libbpf wrapper around the actual eBPF helper
	 */

	/* The TC_ACT_OK return code lets the packet proceed up in the network
	 * stack for ingress packets or out of a net device for egress ones
	 */
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";