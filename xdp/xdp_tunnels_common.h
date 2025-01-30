/* SPDX-License-Identifier: GPL-2.0 */

/* Used by BPF-prog kernel side BPF-progs and userspace programs,
 * for sharing xdp_tunnel common struct and DEFINEs.
 */
#ifndef __XDP_TUNNEL_COMMON_H
#define __XDP_TUNNEL_COMMON_H

#include <linux/in6.h>

#define MAX_TUNNELS 24

/* This is the data record stored in the map */
struct tunnelrec {
	struct in6_addr ipv6_src;
	struct in6_addr ipv6_dst;
        __u64           cookie;
        __u16           session_id;
        __u16           vlan;  // 4095 for untagged
        __u16           phyid;  // underlying physical interface id
};

#endif /* __XDP_TUNNEL_COMMON_H */
