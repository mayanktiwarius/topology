FROM xdpbuild as xdp
FROM ubuntu:20.04
RUN apt-get update \
  && apt-get -y --no-install-recommends install \
  netsniff-ng iproute2 net-tools iputils-ping avahi-autoipd \
  traceroute tcptraceroute mtr \
  tcpdump bwm-ng ethtool fping vim-tiny \
  && rm -rf /var/lib/apt/lists/*

# for whatever reason, keeping tcpdump in the original location fails to launch on aarm64
RUN mv /usr/sbin/tcpdump /bin/

COPY --from=xdp /xdp_stats /xdp_loader /sbin/
COPY --from=xdp /xdp_router.o /root/

WORKDIR /root
