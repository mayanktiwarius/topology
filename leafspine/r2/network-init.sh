#!/bin/bash

#set -e

echo "setting loopback ip addresses ..."
ip addr add 10.0.0.22/32 dev lo
ip -6 addr add fd00::22/128 dev lo

until ip link show eth1 up; do
  echo "waiting for eth1 up ..."
  sleep 1
done

