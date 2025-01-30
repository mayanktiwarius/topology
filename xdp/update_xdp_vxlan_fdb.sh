#!/bin/bash

# this walks the evpn mac vni list from FRR via CLI in JSON and
# feeds the output into xdp_vxlan_fdb to update the xdp map.

src_vtep=$(hostname -I | cut -d' ' -f1)
vtysh -c "show evpn mac vni all json" | xdp_vxlan_fdb -d $1 $src_vtep
