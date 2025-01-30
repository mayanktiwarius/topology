all: build extract

build:
	docker build -t xdpbuild .
#	docker run -ti --rm --user `id -u`:`id -g` -v ${PWD}:/build xdpbuild /bin/bash /build/build.sh

build-no-cache:
	docker build --no-cache -t xdpbuild .

vr1: build
	./install_xdp_vr1.sh

extract:
	./extract.sh

run:
	docker run -ti --rm --user `id -u`:`id -g` -v ${PWD}:/build xdpbuild

clean:
	rm -f xdp_loader xdp_stats xdp_tunnels xdp_router.o
