#!/bin/ash

set -e  # exit script in case of errors

INTERFACE="${INTERFACE:-eth0}"

mount -t bpf bpf /sys/fs/bpf/
ulimit -l 1024
xdp_loader -d $INTERFACE --auto-mode --force --filename xdp_router.o --progsec xdp_gre 
ip link show dev $INTERFACE

tail -f /dev/null
