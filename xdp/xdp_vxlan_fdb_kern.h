/* SPDX-License-Identifier: GPL-2.0 */

/* Used *ONLY* by BPF-prog running kernel side. */
#ifndef __XDP_VXLAN_FDB_KERN_H
#define __XDP_VXLAN_FDB_KERN_H

/* tunnel map, index by ipv6_src */
struct bpf_map_def SEC("maps") xdp_vxlan_fdb_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = ETH_ALEN,
	.value_size  = sizeof(struct vxlanfdbrec),
	.max_entries = MAX_VXLAN_FDBS,
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

#endif /* __XDP_VXLAN_FDB_KERN_H */
