#!/bin/bash

#set -e

until ip link show eth0 up; do
  echo "waiting for eth0 up ..."
  sleep 1
done

ip addr add 192.168.12.11/24 dev eth0
ip route add 10.1.1.21 dev eth0 scope link
ip route add 10.1.1.0/24 via 10.1.1.21 dev eth0
ip r a 192.168.13.0/24 via 10.1.1.21 dev eth0
ulimit -l 1024 

tail -f /dev/null
