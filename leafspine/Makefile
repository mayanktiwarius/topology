all: build down up validate

build:
	cd .. && make -C xdp
	docker-compose build

up:
	docker-compose up -d
	docker-compose ps

#validate:
#	./validate.sh

#xdp:
#	@echo ""
#	@echo "installing xdp_router on all interfaces in r1, r2 and r3 ..."
#	@echo ""
#	./install_xdp.sh
#	@echo ""
#	@echo "testing connectivity with XDP:"
#	@echo ""
#	./validate.sh

#frr: build down
#	docker-compose -f docker-compose-frr.yml build
#	docker-compose -f docker-compose-frr.yml up -d
#	./validate.sh
#
#mac:
#	docker-compose build
#	docker-compose up -d
#	./validate-mac.sh
#
#down:
#	./remove_xdp.sh || true
#	docker-compose down
#	sudo chown -R mwiget r*

ps:
	docker-compose ps
