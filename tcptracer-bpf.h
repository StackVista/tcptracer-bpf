#ifndef __TCPTRACER_BPF_H
#define __TCPTRACER_BPF_H

#include <linux/types.h>

#define GUESS_SADDR      0
#define GUESS_DADDR      1
#define GUESS_FAMILY     2
#define GUESS_SPORT      3
#define GUESS_DPORT      4
#define GUESS_NETNS      5
#define GUESS_DADDR_IPV6 6

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct proc_t {
    char comm[TASK_COMM_LEN];
};

struct conn_stats_t {
	__u64 send_bytes;
	__u64 recv_bytes;
};

struct conn_stats_ts_t {
	__u64 send_bytes;
	__u64 recv_bytes;
	__u64 timestamp;
};

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 pid;
};

struct ipv6_tuple_t {
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	__u64 saddr_h;
	__u64 saddr_l;
	__u64 daddr_h;
	__u64 daddr_l;
	__u16 sport;
	__u16 dport;
	__u32 netns;
	__u32 pid;
};
#endif

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
