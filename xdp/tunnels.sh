#!/bin/bash

# this walks the l2tp session and tunnel lists and creates (in a quick and dirty way ...)
# ifindex,ipv6src, ipv6dst,ifname
# 8 fd01::100 fd00::1 l2tpeth0 0 4
# 9 fd02::100 fd00::1 l2tpeth1 100 6

tunnels=$(ip l2tp show tunnel | grep ^Tunnel | cut -d' ' -f2 | cut -d, -f1)
for t in $tunnels; do
  interface=$(ip l2tp show session | pr -5 -a -t -s | grep "tunnel $t" | awk '{print $13}')
  sessionid=$(ip l2tp show session | pr -5 -a -t -s | grep "tunnel $t" | awk '{print $2}')
  ip6src=$(ip l2tp show tunnel | pr -3 -a -t -s | grep "Tunnel $t" | cut -d' ' -f 7)
  ip6dst=$(ip l2tp show tunnel | pr -3 -a -t -s | grep "Tunnel $t" | cut -d' ' -f 9|cut -d $'\t' -f 1)
  ip6dst="${ip6dst// /}"
  ifindex=$(ip link show dev $interface|head -1 |cut -d: -f1)
  dstif=$(ip -6 route get $ip6dst | awk '{print $7}')
  phyif=$(cat /proc/net/vlan/$dstif 2>/dev/null | grep Device: | awk '{print $2}')
  if [ -z $phyif ]; then
    phyid=$(ip link show dev $dstif | head -1 | cut -d: -f1)
  else
    phyid=$(ip link show dev $phyif | head -1 | cut -d: -f1)
  fi
  phyid=${phyid:-0}
  vlan=$(cat /proc/net/vlan/$dstif 2>/dev/null | grep VID: | awk '{print $3}')
  vlan=${vlan:-0}
  echo "$ifindex $ip6src $ip6dst $interface $vlan $phyid $sessionid"
done
