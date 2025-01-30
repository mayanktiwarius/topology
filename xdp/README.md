# xdp_router for l2tpv3 packets

To decode L2TPv3 packets with Ethernet payload and 8 Bytes cookie, one can use tshark with some options:

```
tshark -r l2tpv3.pcap -d l2tp.pw_type==1,eth -o 'l2tp.cookie_size: 8 Byte Cookie' -O ipv6.routing
```

```
$ ./decode_pcap.sh l2tpv3.pcap
Frame 1: 126 bytes on wire (1008 bits), 126 bytes captured (1008 bits)
Ethernet II, Src: IntelCor_99:cc:14 (00:1b:21:99:cc:14), Dst: IntelCor_99:cc:15 (00:1b:21:99:cc:15)
Internet Protocol Version 6, Src: fd02::100, Dst: fd02::1
Layer 2 Tunneling Protocol version 3
Ethernet II, Src: 32:f8:94:e2:ed:91 (32:f8:94:e2:ed:91), Dst: 6a:af:a8:cc:38:4f (6a:af:a8:cc:38:4f)
Internet Protocol Version 4, Src: 172.20.0.100, Dst: 10.3.254.254
User Datagram Protocol, Src Port: 1, Dst Port: 98
Data (15 bytes)

Frame 2: 164 bytes on wire (1312 bits), 164 bytes captured (1312 bits)
Ethernet II, Src: IntelCor_99:cc:14 (00:1b:21:99:cc:14), Dst: IntelCor_99:cc:15 (00:1b:21:99:cc:15)
Internet Protocol Version 6, Src: fd02::100, Dst: fd02::1
Layer 2 Tunneling Protocol version 3
Ethernet II, Src: 32:f8:94:e2:ed:91 (32:f8:94:e2:ed:91), Dst: 6a:af:a8:cc:38:4f (6a:af:a8:cc:38:4f)
Internet Protocol Version 4, Src: 192.168.100.2, Dst: 10.3.3.254
Internet Control Message Protocol
```

```
enum {
  BPF_FIB_LKUP_RET_SUCCESS = 0,
  BPF_FIB_LKUP_RET_BLACKHOLE = 1,
  BPF_FIB_LKUP_RET_UNREACHABLE = 2,
  BPF_FIB_LKUP_RET_PROHIBIT = 3,
  BPF_FIB_LKUP_RET_NOT_FWDED = 4,
  BPF_FIB_LKUP_RET_FWD_DISABLED = 5,
  BPF_FIB_LKUP_RET_UNSUPP_LWT = 6,
  BPF_FIB_LKUP_RET_NO_NEIGH = 7,
  BPF_FIB_LKUP_RET_FRAG_NEEDED = 8,
};
```

