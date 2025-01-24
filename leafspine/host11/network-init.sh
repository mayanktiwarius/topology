#!/bin/bash

#set -e

until ip link show eth0 up; do
  echo "waiting for eth0 up ..."
  sleep 1
done

ip addr add 192.168.11.11/24 dev eth0
ulimit -l 1024 

tail -f /dev/null
