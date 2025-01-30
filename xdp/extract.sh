#!/bin/bash
set -e
echo "extracting xdp tools from xdpbuild ..."
docker rm xdpbuild 2>/dev/null || true
docker create --rm --name xdpbuild xdpbuild
rm -f xdp_stats xdp_tunnels xdp_loader xdp_router.o
docker cp xdpbuild:/xdp_stats .
docker cp xdpbuild:/xdp_tunnels .
docker cp xdpbuild:/xdp_loader .
docker cp xdpbuild:/xdp_router.o .
docker cp xdpbuild:/xdp_vxlan_fdb .
docker cp xdpbuild:/tunnels.sh .
docker cp xdpbuild:/update_xdp_vxlan_fdb.sh .
ls -l xdp_stats xdp_loader xdp_tunnels xdp_router.o tunnels.sh xdp_vxlan_fdb
