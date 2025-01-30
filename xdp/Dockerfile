FROM ubuntu:20.04 as libbpf
RUN apt-get update \
  && apt-get install --no-install-recommends -y build-essential clang llvm \
    libelf-dev

# build static libbpf.a -> /libbpf/src/root/
COPY libbpf /libbpf/
RUN test -d /libbpf/src || (echo "\nuse 'git submodule update --init' to popluate libbpf/\n" && exit 1)
WORKDIR /libbpf/src
RUN mkdir -p build root \
  && NO_PKG_CONFIG=1 BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=root make install
RUN ls -lR /libbpf/src/root

FROM ubuntu:20.04
RUN apt-get update \
  && apt-get install --no-install-recommends -y build-essential clang llvm libelf-dev libjson-c-dev
RUN ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm

COPY --from=libbpf /libbpf/src/root/ /
RUN if [ -e /usr/lib64/libbpf.a ]; then ln -s /usr/lib64/libbpf.a /usr/lib/libbpf.a; fi

COPY *.[ch] tunnels.sh update_xdp_vxlan_fdb.sh /

RUN clang -O2 -g -c -target bpf -Wno-compare-distinct-pointer-types -o xdp_router.o xdp_router.c \
  && llvm-objdump -S xdp_router.o

RUN clang -Wall -O2 -lz -lelf -o xdp_loader xdp_loader.c common_params.c common_user_bpf_xdp.c /usr/lib/libbpf.a
RUN clang -Wall -O2 -lz -lelf -o xdp_stats xdp_stats.c common_params.c common_user_bpf_xdp.c /usr/lib/libbpf.a
RUN clang -Wall -O2 -lz -lelf -o xdp_tunnels xdp_tunnels.c common_params.c common_user_bpf_xdp.c /usr/lib/libbpf.a
RUN clang -Wall -O2 -lz -lelf -o xdp_vxlan_fdb xdp_vxlan_fdb.c common_params.c common_user_bpf_xdp.c /usr/lib/libbpf.a -ljson-c -I/usr/include/json-c -L/usr/lib/x86_64-linux-gnu/ -Wno-incompatible-pointer-types-discards-qualifiers
RUN strip xdp_loader xdp_stats xdp_tunnels xdp_vxlan_fdb
