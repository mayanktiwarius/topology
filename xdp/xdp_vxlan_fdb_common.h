/* SPDX-License-Identifier: GPL-2.0 */

/* Used by BPF-prog kernel side BPF-progs and userspace programs,
 * for sharing xdp_tunnel common struct and DEFINEs.
 */
#ifndef __XDP_VXLAN_FDB_COMMON_H
#define __XDP_VXLAN_FDB_COMMON_H

#include <linux/if_ether.h>

#define MAX_VXLAN_FDBS 100

/* This is the data record stored in the map */
struct vxlanfdbrec {
  unsigned char   ether_dest[ETH_ALEN];
  __u32           vni;
  __be32          ipv4_srcvtep;
  __be32          ipv4_vtep;
	struct in6_addr ipv6_vtep;
  __u16           ifindex;
  __u16           vlan;
};

#endif /* __XDP_VXLAN_FDB_COMMON_H */
