#include <linux/kconfig.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/if_packet.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/bpf.h>
#include <linux/version.h>
#include "bpf_helpers.h"
#include "bcc_proto.h"
#include "tcptracer-bpf.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wenum-conversion"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#define bpf_debug(fmt, ...)                                        \
	({                                                             \
		char ____fmt[] = fmt;                                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})

// Extract an IPv4 given the address where it's stored
__u32 parse_ipv4(struct __sk_buff *skb, __u64 off) {
	__u32 w0 = load_byte(skb, off);
	__u32 w1 = load_byte(skb, off + 1);
	__u32 w2 = load_byte(skb, off + 2);
	__u32 w3 = load_byte(skb, off + 3);

    return w0 | (w1 << 8) | (w2 << 16) | (w3 << 24);
}

union ports {
		__u32 ports;
		__u16 port16[2];
};

// Map in which we store all the connections
struct bpf_map_def SEC("maps/connections") socket_stats = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct Key),
	.value_size = sizeof(struct Leaf),
	.max_entries = 512, // There is a default limit for non root users on this param
	.pinning = 0,
	.namespace = "",
};

// The socket filter we use to store packets data
SEC("socket_tracer")
int socket__tracer(struct __sk_buff *skb) {
    // Networks header offset and protocol
    // If the protocol is TCP or UPD, the memory is as follow
    // |  BEGIN
    // |  Ethernet header (struct ethhdr)
    // |  IP header (struct iphdr)
    // |  TCP/UDP header (struct tcphdr, udphdr)
    // |  ????
    // |  --- Continues

    __u32 nhoff, ip_proto;
    nhoff = skb->cb[0];
    // TODO check if ipv6

    struct Key key;
    // Extract protocol
	ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));
    key.protocol = ip_proto;

    // Parse IPs
    key.src_ip = parse_ipv4(skb, nhoff + offsetof(struct iphdr, saddr));
    key.dst_ip = parse_ipv4(skb, nhoff + offsetof(struct iphdr, daddr));

    // Parse ports
    union ports ps;
    ps.ports = load_word(skb, nhoff + sizeof(struct iphdr));
    key.src_port = ps.port16[0];
    key.dst_port = ps.port16[1];

    // Check if we already have this connection stored
    struct Leaf* val;
    val = bpf_map_lookup_elem(&socket_stats, &key);

    if (val != NULL) {
        // If we do just increment the number of packets and bytes received
        val->pkts += 1;
        val->bytes += skb->len;
    } else {
        // Otherwise create it
        struct Leaf leaf;
        leaf.pkts = 1;
        leaf.bytes = skb->len;
        bpf_map_update_elem(&socket_stats, &key, &leaf, BPF_ANY);
    }

    // We let the packet go through
    return -1;
}

char _license[] SEC("license") = "GPL";
