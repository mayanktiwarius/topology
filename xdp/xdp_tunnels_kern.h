/* SPDX-License-Identifier: GPL-2.0 */

/* Used *ONLY* by BPF-prog running kernel side. */
#ifndef __XDP_TUNNEL_KERN_H
#define __XDP_TUNNEL_KERN_H

/* tunnel map, index by ifindex */
struct bpf_map_def SEC("maps") xdp_tunnel_if_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct tunnelrec),
	.max_entries = MAX_TUNNELS,
};

/* tunnel map, index by ipv6_src */
struct bpf_map_def SEC("maps") xdp_tunnel_ipv6_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct in6_addr),
	.value_size  = sizeof(struct tunnelrec),
	.max_entries = MAX_TUNNELS,
};

#ifndef __XDP_TXPORT_KERN_H
#define __XDP_TXPORT_KERN_H
struct bpf_map_def SEC("maps") tx_port = {
  .type = BPF_MAP_TYPE_DEVMAP_HASH,
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 128,
};
#endif

#endif /* __XDP_TUNNEL_KERN_H */
