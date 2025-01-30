/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#include "xdp_stats_kern_user.h"
#include "xdp_stats_kern.h"

#include "xdp_tunnels_common.h"
#include "xdp_tunnels_kern.h"

#include "xdp_vxlan_fdb_common.h"
#include "xdp_vxlan_fdb_kern.h"


#define AF_INET   2
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)
#define IPPROTO_L2TP  115
#define VXLAN_UDP_PORT 4789

// from include/net/ip.h
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
  __u32 check = iph->check;
  check += __bpf_htons(0x0100);
  iph->check = (__u16)(check + (check >= 0xFFFF));
  return --iph->ttl;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
  __u32 sum;
  sum = (csum>>16) + (csum & 0xffff);
  sum += (sum>>16);
  return ~sum;
}

static __always_inline void ipv4_csum(void *data_start, int data_size,
    __u32 *csum)
{
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

struct vlan_hdr {
  __be16 h_vlan_tci;
  __be16 h_vlan_encap_proto;
} __attribute__((packed));

struct vxlan_hdr {
  __be32 vxlan_flags;
  __be32 vxlan_vni;
} __attribute__((packed));

// unmanaged l2tpv3 tunnel header
struct l2tpv3hdr {
  __u8  b1;
  __u8  b2;
  __u16   session_id;
  __u64   cookie;
}  __attribute__((packed));

// adjust the l2tpv3 session_id before passing on
static __u32 xdp_set_sid_action(struct xdp_md *ctx, struct ipv6hdr *ip6h, __u32 action)
{
  struct l2tpv3hdr *l2tpv3h;
  void *data_end = (void *)(long)ctx->data_end;
  struct tunnelrec *rec;

  if (ip6h + 1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_DROP);
  }
  rec = bpf_map_lookup_elem(&xdp_tunnel_ipv6_map, &(ip6h->saddr));
  if (!rec) {
    bpf_printk("bpf_map_lookup_elem failed for ipv6 (via ifindex %d)\n", ctx->ingress_ifindex);
    return xdp_stats_record_action(ctx, XDP_PASS);
  } 
  l2tpv3h = (void *)(ip6h +1);
  if (l2tpv3h +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }
  //    bpf_printk("if=%d setting session_id to %d\n", ctx->ingress_ifindex, rec->session_id);
  l2tpv3h->session_id = bpf_htons(rec->session_id);
  return xdp_stats_record_action(ctx, action);
}

SEC("xdp_vxlan")  // VXLAN encap/decap

int vxlan_router_func(struct xdp_md *ctx) {

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  struct ethhdr *innereth = data;
  __u8  h_source[ETH_ALEN];

  struct vlan_hdr *vlh;
  struct vlan_hdr *innervlh;
  int vlan = 0;
  int phyid = 0;
  int vni = 0;

  struct iphdr *iph, *inneriph;
  struct ipv6hdr *ip6h, *innerip6h;

  struct udphdr *udph;
  struct vxlan_hdr *vxlanh;

  __u16 payload_l3_len;
  struct bpf_fib_lookup fib_params = {};
  __be16  h_proto;

  struct vxlanfdbrec *rec;

  struct l2tpv3hdr *l2tpv3h;
  int delta;
  int rc;
  __u32 csum;

  if (eth +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  h_proto = eth->h_proto;

  if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
    vlh = (void *)(eth +1);
    if (vlh + 1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    vlan = bpf_ntohs(vlh->h_vlan_tci) & 4095;
    // bpf_printk("rx vlan %d from ifindex=%d\n", vlan, ctx->ingress_ifindex);
    h_proto = vlh->h_vlan_encap_proto;
    eth = data;
    if (eth +1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
    ip6h = (void *)(vlh +1);
  } else {
    ip6h = (void *)(eth +1);
  }

  // check if we find a L2 match in FDB first
  rec = bpf_map_lookup_elem(&xdp_vxlan_fdb_map, eth->h_dest);


  if (rec) {
    // found destination mac in fdb. Now we have 2 options: 
    // local interface or vxlan tunnel
    if (rec->ifindex) {
     // bpf_printk("ship packet to ifindex %d\n", rec->ifindex);
      return xdp_stats_record_action(ctx, bpf_redirect_map(&tx_port, rec->ifindex, 0));
    } 
    // vxlan tunnel it is ...
    delta = (int)(0 - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr) - sizeof(struct vxlan_hdr));
    //bpf_printk("headroom required: delta is %d\n", delta);

    if (0 != bpf_xdp_adjust_head(ctx, delta)) {
      bpf_printk("call to bpf_xdp_adjust_head failed!\n");
      return xdp_stats_record_action(ctx, XDP_ABORTED);
    }

    // all range checks are now invalid and need to be redone 
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;   // points now to the new packet start
    if (eth +1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
    // need to fill in the new eth, ip, udp and vxlan header, plus calc the udp src port
    eth->h_proto = bpf_htons(ETH_P_IP);
    iph = (void *)(eth +1);

    if (iph +1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    __builtin_memset(iph, 0, sizeof(struct iphdr));
    iph->version  = 4;
    iph->ihl  = 5;  // 20 bytes
    iph->ttl      = 64;
    iph->tot_len  = bpf_htons((data_end - data) - sizeof(struct ethhdr));   
    iph->protocol = IPPROTO_UDP;
    // iph->saddr    = bpf_htonl(0x0a000115); // TODO remove me
    iph->saddr    = rec->ipv4_srcvtep;
    iph->daddr    = rec->ipv4_vtep;
    csum = 0;
    ipv4_csum(iph, sizeof(struct iphdr), &csum);
    iph->check = csum;

    udph = (void *)(iph +1);
    if (udph +1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
    udph->source = 0;   // TODO create hash from payload header
    udph->dest = bpf_htons(VXLAN_UDP_PORT);
    udph->check = 0;
    udph->len = bpf_htons(bpf_ntohs(iph->tot_len) - sizeof(struct iphdr));

    vxlanh = (void *)(udph +1);
    if (vxlanh +1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
    vxlanh->vxlan_vni = bpf_htonl(rec->vni << 8);
    vxlanh->vxlan_flags = bpf_htonl(0x08000000);

    /* populate the fib_params fields to prepare for the lookup */
    fib_params.family       = AF_INET;
    fib_params.tos          = iph->tos;
    fib_params.l4_protocol  = iph->protocol;
    fib_params.sport        = 0;
    fib_params.dport        = 0;
    fib_params.tot_len      = bpf_ntohs(iph->tot_len);
    fib_params.ipv4_src     = iph->saddr;
    fib_params.ipv4_dst     = iph->daddr;

    // do a lookup on the received v4 or v6 packet
    fib_params.ifindex = ctx->ingress_ifindex;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),  BPF_FIB_LOOKUP_DIRECT);
    __u32 ip_dst = iph->daddr;
//    bpf_printk("vxlan encap fib_lookup rc=%d daddr=0x%x ifindex=%d\n", rc, ip_dst, fib_params.ifindex);

    switch (rc) {
      case BPF_FIB_LKUP_RET_SUCCESS:
  //      bpf_printk("vxlan encap fib_lookup success ifindex=%d daddr=0x%x\n", fib_params.ifindex, iph->daddr);
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        return xdp_stats_record_action(ctx, bpf_redirect_map(&tx_port, fib_params.ifindex, 0));
        break;
    }
    bpf_printk("vxlan encap fib_lookup failed. rc=%d daddr=0x%x ifindex=%d\n", rc, ip_dst, fib_params.ifindex);
    return xdp_stats_record_action(ctx, XDP_TX);  // broken packet, but good for tcpdump
  }

  if (h_proto == bpf_htons(ETH_P_IPV6)) {
    if (ip6h + 1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    if (ip6h->nexthdr == IPPROTO_UDP) {
      udph = (void *)(ip6h +1);
    } else {
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
  } else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    iph = (void *)ip6h;
    if (iph + 1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    if (iph->protocol == IPPROTO_UDP) {
      udph = (void *)(iph +1);
    }
  } else {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  if (udph +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }
  if (udph->dest != bpf_htons(VXLAN_UDP_PORT)) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }
  vxlanh = (void *)(udph +1);
  if (vxlanh +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }
  vni = bpf_ntohs(vxlanh->vxlan_vni >> 8);  // TODO likely breaks for VNIs > 65535
  // bpf_printk("rx vxlan vni %d from ifindex=%d\n", vni, ctx->ingress_ifindex);

  innereth = (void *)(vxlanh +1);

  // innereth and inneriph are now either set to the native or encapped v4/v6 packet

  if (innereth +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  if (eth == innereth) {
    bpf_printk("native packet found here!! ifindex=%d\n", fib_params.ifindex);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

//  bpf_printk("vxlan packet ifindex=%d\n", fib_params.ifindex);
//  bpf_printk("bpf_map_lookup_elem for h_dest %x:%x:%x......\n", 
//     innereth->h_dest[0],
//      innereth->h_dest[1],
//      innereth->h_dest[2]
//      );

  // dealing with a vxlan encapsulated ethernet packet now.
  // lookup dst mac and verify vni.
  //
  rec = bpf_map_lookup_elem(&xdp_vxlan_fdb_map, innereth->h_dest);
  if (!rec) {
//    bpf_printk("no match found\n");
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  if (vni != rec->vni) {
    bpf_printk("vni mismatch %d != %d\n", vni, rec->vni);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

//  bpf_printk("NOT DOING v4 adjust_head by %d\n", (int)((void *)innereth - (void *)eth));
//  return xdp_stats_record_action(ctx, XDP_PASS);

  if (0 != bpf_xdp_adjust_head(ctx, (int)((void *)innereth - (void *)eth))) {
    bpf_printk("bpf_xdp_adjust_head failed!\n");
    return xdp_stats_record_action(ctx, XDP_ABORTED);
  }

  //bpf_printk("vxlan payload redirect to ifindex %d\n", rec->ifindex);
  return xdp_stats_record_action(ctx, bpf_redirect_map(&tx_port, rec->ifindex, 0));

} // vxlan_router_func()


SEC("xdp_l2tpv3")  // L2TPv3 encap and routing

int l2tpv3_router_func(struct xdp_md *ctx) {

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  struct ethhdr *innereth = data;
  __u8  h_source[ETH_ALEN];

  struct vlan_hdr *vlh;
  struct vlan_hdr *innervlh;
  int vlan = 0;
  int phyid = 0;

  struct iphdr *iph, *inneriph;
  struct ipv6hdr *ip6h, *innerip6h;

  __u16 payload_l3_len;
  struct bpf_fib_lookup fib_params = {};
  __be16  h_proto;

  struct tunnelrec *rec;

  struct l2tpv3hdr *l2tpv3h;
  int delta;
  int rc;

  if (eth +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  h_proto = eth->h_proto;

  if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
    vlh = (void *)(eth +1);
    if (vlh + 1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    vlan = bpf_ntohs(vlh->h_vlan_tci) & 4095;
    // bpf_printk("rx vlan %d from ifindex=%d\n", vlan, ctx->ingress_ifindex);
    h_proto = vlh->h_vlan_encap_proto;
    eth = data;
    if (eth +1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_PASS);
    }
    ip6h = (void *)(vlh +1);
  } else {
    ip6h = (void *)(eth +1);
  }

  if (h_proto == bpf_htons(ETH_P_IPV6)) {
    if (ip6h + 1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    if (ip6h->nexthdr == IPPROTO_L2TP) {

      l2tpv3h = (void *)(ip6h +1);
      if (l2tpv3h +1 > data_end) {
        return xdp_stats_record_action(ctx, XDP_PASS);
      }
      // TODO: add session_id and cookie check
      innereth = (void *)(l2tpv3h +1);
    }

  } else if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  // innereth and inneriph are now either set to the native or encapped v4/v6 packet

  if (innereth +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  if (innereth->h_proto == bpf_htons(ETH_P_IP)) {

    /* IPv4 packet */
    inneriph = (void *)(innereth  +1);
    if (inneriph + 1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    if (inneriph->ttl <= 1) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    payload_l3_len = bpf_ntohs(inneriph->tot_len);

    /* populate the fib_params fields to prepare for the lookup */
    fib_params.family       = AF_INET;
    fib_params.tos          = inneriph->tos;
    fib_params.l4_protocol  = inneriph->protocol;
    fib_params.sport        = 0;
    fib_params.dport        = 0;
    fib_params.tot_len      = payload_l3_len;
    fib_params.ipv4_src     = inneriph->saddr;
    fib_params.ipv4_dst     = inneriph->daddr;

  } else if (innereth->h_proto == bpf_htons(ETH_P_IPV6)) {

    /* IPv6 packet */
    struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
    struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

    innerip6h = (void *)(innereth +1);
    if (innerip6h + 1 > data_end) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }

    if (innerip6h->hop_limit <= 1) {
      return xdp_stats_record_action(ctx, XDP_DROP);
    }
    payload_l3_len = bpf_ntohs(innerip6h->payload_len);

    /* populate the fib_params fields to prepare for the lookup */
    fib_params.family       = AF_INET6;
    fib_params.flowinfo     = *(__be32 *) innerip6h & IPV6_FLOWINFO_MASK;
    fib_params.l4_protocol  = innerip6h->nexthdr;
    fib_params.sport        = 0;
    fib_params.dport        = 0;
    fib_params.tot_len      = payload_l3_len;
    *src                    = innerip6h->saddr;
    *dst                    = innerip6h->daddr;

  } else {
    // neither v4 nor v6 packet, pass it on to the kernel
    if (eth < innereth) {
      return xdp_set_sid_action(ctx, ip6h, XDP_PASS);
    }
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  // do a lookup on the received v4 or v6 packet
  fib_params.ifindex = ctx->ingress_ifindex;
  rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),  BPF_FIB_LOOKUP_DIRECT);
  // bpf_printk("inner fib_lookup rc=%d vlan=%d ifindex=%d\n", rc, vlan, fib_params.ifindex);

  switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
      if (fib_params.ifindex == 1) { // loopback interface, just pass it on
        return xdp_stats_record_action(ctx, XDP_PASS);
      }
      __builtin_memcpy(innereth->h_dest, fib_params.dmac, ETH_ALEN);
      __builtin_memcpy(innereth->h_source, fib_params.smac, ETH_ALEN);
      // bpf_printk("B vlan_proto=%d vlan_TCI=%d ifindex=%d\n", fib_params.h_vlan_proto, fib_params.h_vlan_TCI, fib_params.ifindex);
      if (innereth->h_proto == bpf_htons(ETH_P_IP)) {
         ip_decrease_ttl(inneriph);
      } else if (innereth->h_proto == bpf_htons(ETH_P_IPV6)) {
        innerip6h->hop_limit--;
      }

      // egress a tunnel?
      rec = bpf_map_lookup_elem(&xdp_tunnel_if_map, &(fib_params.ifindex));
      if (rec) {
        if (innereth == eth) {
          // encap!
          // need to make headroom for v6 and l2tpv3 headers
          delta = (int)(0 - sizeof(*eth) - sizeof(*ip6h) - sizeof(*l2tpv3h));
          if (rec->vlan) {
            delta -= sizeof(*vlh);
          }
          if (0 != bpf_xdp_adjust_head(ctx, delta)) {
            bpf_printk("call to bpf_xdp_adjust_head failed!\n");
            return xdp_stats_record_action(ctx, XDP_ABORTED);
          }

          // all range checks are now invalid and need to be redone 
          data = (void *)(long)ctx->data;
          data_end = (void *)(long)ctx->data_end;
          eth = data;   // points now to the new packet start
          if (eth +1 > data_end) {
            return xdp_stats_record_action(ctx, XDP_PASS);
          }

          if (rec->vlan) {
            vlh = (void *)(eth +1);
            if (vlh + 1 > data_end) {
              return xdp_stats_record_action(ctx, XDP_DROP);
            }
            eth->h_proto = bpf_htons(ETH_P_8021Q);
            vlh->h_vlan_tci = bpf_htons(rec->vlan);
            vlh->h_vlan_encap_proto = bpf_htons(ETH_P_IPV6);
            ip6h = (void *)(vlh +1);
          } else {
            eth->h_proto = bpf_htons(ETH_P_IPV6);
            ip6h = data + sizeof(*eth);
          }

          if (ip6h +1 > data_end) {
            return xdp_stats_record_action(ctx, XDP_DROP);
          }
          __builtin_memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
          ip6h->version     = 6;
          ip6h->priority    = 0;
          ip6h->payload_len = bpf_htons(payload_l3_len + sizeof(*eth) + sizeof(*l2tpv3h));
          ip6h->nexthdr     = IPPROTO_L2TP;
        }
      } else {
        // no egress tunnel
        if (eth < innereth) {
          // bpf_printk("decap l2tpv3 payload for this host from ifindex=%d vlan=%d\n", ctx->ingress_ifindex, vlan);
          if (vlan > 0) {

            // TODO this needs to be tested. Likely needs fixing

            h_proto = innereth->h_proto;
            __builtin_memcpy(h_source, innereth->h_source, ETH_ALEN);

            innereth = data + sizeof(*eth) + sizeof(*ip6h) + sizeof(*l2tpv3h);
            if (innereth +1 > data_end) {
              return xdp_stats_record_action(ctx, XDP_PASS);
            }

            innervlh = (void *)(innereth +1);
            if (innervlh +1 > data_end) {
              return xdp_stats_record_action(ctx, XDP_PASS);
            }

            innervlh->h_vlan_tci = vlh->h_vlan_tci;
            innervlh->h_vlan_encap_proto = h_proto;

            __builtin_memcpy(innereth->h_source, h_source, ETH_ALEN);
            innereth->h_proto = eth->h_proto; // use original vlan proto
          }

          if (0 != bpf_xdp_adjust_head(ctx, (int)(sizeof(*eth) + sizeof(*ip6h) + sizeof(*l2tpv3h)))) {
            bpf_printk("call to bpf_xdp_adjust_head failed!\n");
            return xdp_stats_record_action(ctx, XDP_ABORTED);
          }
          // bpf_printk("vlan pushed for host ifindex=%d vlan=%d\n", ctx->ingress_ifindex, vlan);
        }
        // now plain ipv4/ipv6 packet to send
        // bpf_printk("plain routed packet via ifindex %d\n", fib_params.ifindex);
        if (fib_params.ifindex == ctx->ingress_ifindex) {
          return xdp_stats_record_action(ctx, XDP_TX);
        } else {
          // no egress tunnel, just plain routing
          return xdp_stats_record_action(ctx, bpf_redirect_map(&tx_port, fib_params.ifindex, 0));
        }
      }
      break;

    case BPF_FIB_LKUP_RET_NOT_FWDED:
      // local packet. Deliver to the kernel, pop l2tp header if present
      if (eth < innereth) {
        return xdp_set_sid_action(ctx, ip6h, XDP_PASS);
      }
      return xdp_stats_record_action(ctx, XDP_PASS);
      break;

    default:
      // bpf_printk("l2tpv3 payload rc=%d. XDP_PASS\n",rc);
      return xdp_stats_record_action(ctx, XDP_PASS);
      break;
  }

  // lookup l2tpv3 tunnel v6 src/dst via tunnel_if_map
  rec = bpf_map_lookup_elem(&xdp_tunnel_if_map, &(fib_params.ifindex));
  if (!rec) {
    bpf_printk("bpf_map_lookup_elem failed for ifindex=%d (not a tunnel)\n", fib_params.ifindex);
    return xdp_stats_record_action(ctx, XDP_PASS);
  }

  if (ip6h +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_DROP);
  }

  struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;                                  
  struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;                                  

  // set ipv6 src/dst address based on successful tunnel lookup
  ip6h->saddr = rec->ipv6_src;
  ip6h->daddr = rec->ipv6_dst;
  ip6h->hop_limit   = 64;

  // do a v6 fib lookup for the new tunnel endpoint
  fib_params.family       = AF_INET6;
  fib_params.flowinfo     = *(__be32 *) ip6h & IPV6_FLOWINFO_MASK;
  fib_params.l4_protocol  = ip6h->nexthdr;                                                         
  fib_params.sport        = 0;
  fib_params.dport        = 0;
  fib_params.tot_len      = bpf_ntohs(ip6h->payload_len);
  *src                    = ip6h->saddr;
  *dst                    = ip6h->daddr;
  fib_params.ifindex      = ctx->ingress_ifindex;

  rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params),  BPF_FIB_LOOKUP_DIRECT);

  switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
      // bpf_printk("A vlan=%d rec->vlan=%d ifindex=%d\n", vlan, rec->vlan, fib_params.ifindex);

      if (vlan && (0 == rec->vlan)) {

        // pop ingress vlan header
        // bpf_printk("pop vlan %d to ifindex=%d\n", vlan, fib_params.ifindex);
        if (0 != bpf_xdp_adjust_head(ctx, sizeof(*vlh))) {
          bpf_printk("add vlh bpf_xdp_adjust_head failed!\n");
          return xdp_stats_record_action(ctx, XDP_ABORTED);
        }
        // all range checks are now invalid and need to be redone 
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;   // points now to the new packet start
        if (eth +1 > data_end) {
          return xdp_stats_record_action(ctx, XDP_PASS);
        }
        eth->h_proto = bpf_htons(ETH_P_IPV6);
        ip6h = (void *)(eth +1);

      } else if (rec->vlan) {

        if (0 == vlan) {
          // bpf_printk("push vlan %d to ifindex=%d resize by %d\n", rec->vlan, fib_params.ifindex, 0 - sizeof(*vlh));
          // need to make headroom for a vlan tag and fill in the the gaps
          if (0 != bpf_xdp_adjust_head(ctx, (int)(0 - sizeof(*vlh)))) {
            bpf_printk("add vlh bpf_xdp_adjust_head failed!\n");
            return xdp_stats_record_action(ctx, XDP_ABORTED);
          }
          // all range checks are now invalid and need to be redone 
          data = (void *)(long)ctx->data;
          data_end = (void *)(long)ctx->data_end;
          eth = data;   // points now to the new packet start
          if (eth +1 > data_end) {
            return xdp_stats_record_action(ctx, XDP_PASS);
          }
          vlh = (void *)(eth +1);
          if (vlh + 1 > data_end) {
            return xdp_stats_record_action(ctx, XDP_DROP);
          }
          eth->h_proto = bpf_htons(ETH_P_8021Q);
          vlh->h_vlan_encap_proto = bpf_htons(ETH_P_IPV6);
          vlh->h_vlan_tci = bpf_htons(rec->vlan);
          ip6h = (void *)(vlh +1);
        } else {
          // bpf_printk("swap vlan %d -> %d to ifindex=%d\n", vlan, rec->vlan, fib_params.ifindex);
          vlh = (void *)(eth +1);
          if (vlh + 1 > data_end) {
            return xdp_stats_record_action(ctx, XDP_DROP);
          }
          vlh->h_vlan_tci = bpf_htons(rec->vlan);
          ip6h = (void *)(vlh +1);
        }
      }

      if (eth +1 > data_end) {
        return xdp_stats_record_action(ctx, XDP_PASS);
      }
      __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
      __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

      if (ip6h + 1 > data_end) {
        return xdp_stats_record_action(ctx, XDP_DROP);
      }

      // fill in l2tpv3 header
      l2tpv3h = (void *)ip6h + sizeof(*ip6h);
      if (l2tpv3h +1  > data_end) {
        // bpf_printk("error with l2tpv3h, size=%d data_end=%p l2tpv3h=%p\n", sizeof(*l2tpv3h), data_end, &l2tpv3h);
        return xdp_stats_record_action(ctx, XDP_DROP);
      }
      l2tpv3h->session_id = 0xffff; // TODO: hard-coded for now !!
      l2tpv3h->cookie = rec->cookie;

      phyid = fib_params.ifindex;
      if (rec->phyid) {
        phyid = rec->phyid;
      }

      if (phyid == ctx->ingress_ifindex) {
        // TODO if this is a vlan interface, we need to send it to the underlying phy !!!!
        return xdp_stats_record_action(ctx, XDP_TX);
      } else {
        // bpf_printk("redirect ifindex %d -> %d vlan=%d\n", ctx->ingress_ifindex, fib_params.ifindex, rec->vlan);
        return xdp_stats_record_action(ctx, bpf_redirect_map(&tx_port, fib_params.ifindex, 0));
      }
      break;

    default:
      bpf_printk("v6 bpf_fib_lookup failed, rc=%d!\n", rc);
      return xdp_stats_record_action(ctx, XDP_PASS);
      break; 
  }
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx) {
  return xdp_stats_record_action(ctx, XDP_PASS);
}

SEC("xdp_tx")
int xdp_tx_func(struct xdp_md *ctx) {

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  __u8 h_tmp[ETH_ALEN];

  if (eth +1 > data_end) {
    return xdp_stats_record_action(ctx, XDP_PASS);
  }
  __builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
  __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  __builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
  return xdp_stats_record_action(ctx, XDP_TX);
}

SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx) {
  return xdp_stats_record_action(ctx, XDP_DROP);
}

char __license[] SEC("license") = "GPL";
