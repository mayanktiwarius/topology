FROM xdpbuild as xdp

FROM ubuntu:20.04
RUN apt-get update \
  && apt-get -y --no-install-recommends install \
  netsniff-ng iproute2 net-tools iputils-ping frr avahi-autoipd \
  traceroute \
  tcpdump bwm-ng ethtool fping vim-tiny iptables bridge-utils  tcptraceroute mtr \
  && rm -rf /var/lib/apt/lists/*

# for whatever reason, keeping tcpdump in the original location fails to launch on aarm64
RUN mv /usr/sbin/tcpdump /bin/

COPY --from=xdp /xdp_stats /xdp_loader /xdp_vxlan_fdb /sbin/
COPY --from=xdp /xdp_router.o /update_xdp_vxlan_fdb.sh /root/

RUN chmod a+rx /root/*.sh && ln -s /usr/bin/vtysh /usr/bin/cli

WORKDIR /root
