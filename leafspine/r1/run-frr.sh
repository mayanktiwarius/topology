#!/bin/bash

set -e
mount -t bpf bpf /sys/fs/bpf/

if [ -s /etc/frr/network-init.sh ]; then
   /bin/bash /etc/frr/network-init.sh > /root/network-init.log 2>&1 & disown
fi

touch /etc/frr/vtysh.conf

cat > /etc/frr/daemons <<EOF
bgpd=yes
vtysh_enable=yes
EOF

/usr/lib/frr/frrinit.sh start

#iptables -t nat -A POSTROUTING --destination 10.0.0.0/24 -j SNAT --to-source 10.0.0.11

tail -f /dev/null
