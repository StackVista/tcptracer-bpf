#include <linux/types.h>

typedef unsigned int u32;
typedef unsigned long long u64;

// Key used as key in the connections hash map
struct Key {
	u32 src_ip;               // source ip
	u32 dst_ip;               // destination ip
    u32 protocol;             // protocol (TCP, UDP, ICMP, ...)
	unsigned short src_port;  // source port
	unsigned short dst_port;  // destination port
};

// Leaf used as leaf in the connections hash map
struct Leaf {
	u64 pkts;
	u64 bytes;
};
