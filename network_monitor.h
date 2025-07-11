#ifndef _NETWORK_MONITOR_H
#define _NETWORK_MONITOR_H

typedef union
{
	unsigned int ipv4;
	unsigned char ipv6[16];
} ip_address;

struct stats_key
{
	unsigned short l2_proto;
	unsigned char l3_proto;

	ip_address src_addr;
	ip_address dst_addr;

	unsigned short src_port;
	unsigned short dst_port;
};

struct stats_value
{
	unsigned long pkts;
	unsigned long bytes;
};

#endif
