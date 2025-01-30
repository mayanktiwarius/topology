#!/bin/bash

#set -e

echo "setting loopback ip addresses ..."
ip addr add 10.1.0.21/32 dev lo
ip -6 addr add fd01::21/128 dev lo

until ip link show eth1 up; do
  echo "waiting for eth1 up ..."
  sleep 1
done

ip addr add 192.168.12.1/24 dev eth1

