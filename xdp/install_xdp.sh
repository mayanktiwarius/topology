#!/bin/bash

#set -e

make

#for container in r1; do
for container in r1 r2 r3; do

  docker cp xdp_router.o $container:/
  docker cp xdp_loader $container:/
  docker cp xdp_vxlan_fdb $container:/usr/sbin/
  docker cp update_xdp_vxlan_fdb.sh $container:/

  for interface in eth0 eth1 eth2; do
    echo "installing xdp on $interface @ $container ..."
    docker exec $container /bin/bash -c "ulimit -l 1024 && /xdp_loader -d $interface --auto-mode --force --filename /xdp_router.o --progsec xdp_vxlan && /update_xdp_vxlan_fdb.sh $interface"
  done
done

for interface in $(ifconfig |grep ^veth | cut -d: -f1); do
  sudo ./xdp_loader -d $interface --auto-mode --force --filename ./xdp_router.o --progsec xdp_pass
done
