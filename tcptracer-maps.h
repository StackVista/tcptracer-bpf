#ifndef TCPTRACER_BPF_TCPTRACER_MAPS_H
#define TCPTRACER_BPF_TCPTRACER_MAPS_H

#include "tcptracer-bpf.h"

/* This is a key/value store with the keys being an ipv4_tuple_t for send & recv calls
 * and the values being the struct conn_stats_ts_t *.
 */
struct bpf_map_def SEC("maps/udp_stats_ipv4") udp_stats_ipv4 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv4_tuple_t),
        .value_size = sizeof(struct conn_stats_ts_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* This is a key/value store with the keys being an ipv4_tuple_t for send & recv calls
 * and the values being the struct conn_stats_ts_t *.
 */
struct bpf_map_def SEC("maps/udp_stats_ipv6") udp_stats_ipv6 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv6_tuple_t),
        .value_size = sizeof(struct conn_stats_ts_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* This is a key/value store with the keys being an ipv4_tuple_t for send & recv calls
 * and the values being the struct conn_stats_t *.
 */
struct bpf_map_def SEC("maps/tcp_stats_ipv4") tcp_stats_ipv4 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv4_tuple_t),
        .value_size = sizeof(struct conn_stats_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* This is a key/value store with the keys being an ipv6_tuple_t for send & recv calls
 * and the values being the struct conn_stats_t *.
 */
struct bpf_map_def SEC("maps/tcp_stats_ipv6") tcp_stats_ipv6 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv6_tuple_t),
        .value_size = sizeof(struct conn_stats_t),
        .max_entries = 32768,
        .pinning = 0,
        .namespace = "",
};

/* These maps are used to match the kprobe & kretprobe of connect for IPv4 */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/connectsock_ipv4") connectsock_ipv4 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(void *),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

/* These maps are used to match the kprobe & kretprobe of connect for IPv6 */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/connectsock_ipv6") connectsock_ipv6 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(void *),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

/* This map is used to match the kprobe & kretprobe of udp_recvmsg */
/* This is a key/value store with the keys being a pid
 * and the values being a struct sock *.
 */
struct bpf_map_def SEC("maps/udp_recv_sock") udp_recv_sock = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(void *),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

struct bpf_map_def SEC("maps/http_stats") http_stats = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ipv4_tuple_t),
        .value_size = sizeof(struct http_stats_t),
        .max_entries = 1024,
        .pinning = 0,
        .namespace = "",
};

#endif //TCPTRACER_BPF_TCPTRACER_MAPS_H
