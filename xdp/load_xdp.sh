#!/bin/bash
ulimit -l unlimited
./xdp_loader -d ens1f0 --native-mode --force  --filename ./xdp_router.o --progsec xdp_l2tpv3
#sudo ./xdp_loader -d ens1f1 --native-mode --force  --filename ./xdp_router.o --progsec xdp_l2tpv3
