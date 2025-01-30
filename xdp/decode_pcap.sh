#!/bin/bash
if [ -z "$1" ]; then
  echo "$0 <pcapfile> [options]"
  exit 1
fi
tshark -r $1 -d l2tp.pw_type==1,eth -o 'l2tp.cookie_size: 8 Byte Cookie' -O ipv6.routing $2 $3 $4 $5
