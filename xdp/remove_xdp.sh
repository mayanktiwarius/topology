#!/bin/bash

set -e

make

#for container in r1 r2 r3; do
for container in r1; do

  for interface in eth0 eth1 eth2; do
    echo "removing xdp on $interface @ $container ..."
    docker exec $container /bin/bash -c "/xdp_loader -d $interface -U"
  done
done
