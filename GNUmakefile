default: build

build:
	go build -v ./...

build-fips:
	GOEXPERIMENT=boringcrypto go build -v ./...

test:
	go test -v ./... -count=1

test-fips:
	GOEXPERIMENT=boringcrypto go test -v ./... -count=1

testacc:
	@test -f .env.test && export $$(grep -v '^#' .env.test | xargs) || true; \
	TF_ACC=1 go test -v ./... -count=1 -timeout 120m

testacc-token:
	@echo "Provisioning fresh Technitium API token..."
	@TOKEN=$$(curl -sf "http://127.0.0.1:5380/api/user/login?user=admin&pass=admin" | \
		python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null) && \
	API_TOKEN=$$(curl -sf "http://127.0.0.1:5380/api/user/createToken?user=admin&pass=admin&tokenName=terraform-test-$$(date +%s)&token=$$TOKEN" | \
		python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null) && \
	sed -i'' -e "s/^TECHNITIUM_API_TOKEN=.*/TECHNITIUM_API_TOKEN=$$API_TOKEN/" .env.test && \
	echo "Token provisioned and written to .env.test"

testacc-up:
	@test -f .env.test || (echo "ERROR: .env.test not found. Copy .env.test.example to .env.test and fill in values." && exit 1)
	docker compose -f docker-compose.test.yml up -d --wait
	$(MAKE) testacc-token
	$(MAKE) testacc

testacc-down:
	docker compose -f docker-compose.test.yml down -v

# --- TLS-enabled acceptance test path -----------------------------------------
#
# Generates a fresh self-signed CA + server cert, brings up a Technitium
# container with HTTPS enabled on port 5443, and runs the full acceptance
# suite over TLS. This unblocks the NSS-mode and STIG-mode test families
# that require encrypted transport (DNS-REQ-028 / NIST SC-8).
#
# All generated material lives under ./testdata/tls/ and is gitignored.

testacc-tls-prep:
	@echo "Generating test TLS material in ./testdata/tls/ ..."
	@mkdir -p ./testdata/tls
	go run ./tools/gen_test_tls -out ./testdata/tls -hosts 127.0.0.1,localhost -duration 24h -pfx-password test

testacc-token-tls:
	@echo "Provisioning fresh Technitium API token over HTTPS..."
	@PW=$$( (test -f .env.test && grep -E '^DNS_ADMIN_PASSWORD=' .env.test | cut -d= -f2) || echo admin ); \
	test -n "$$PW" || (echo "ERROR: DNS_ADMIN_PASSWORD is empty in .env.test"; exit 1); \
	TOKEN=$$(curl -sf --cacert ./testdata/tls/ca.pem "https://127.0.0.1:5443/api/user/login?user=admin&pass=$$PW" | \
		python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null) && \
	API_TOKEN=$$(curl -sf --cacert ./testdata/tls/ca.pem "https://127.0.0.1:5443/api/user/createToken?user=admin&pass=$$PW&tokenName=terraform-test-tls-$$(date +%s)&token=$$TOKEN" | \
		python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null) && \
	(umask 077 && echo "$$API_TOKEN" > ./testdata/tls/api-token) && \
	echo "Token written to ./testdata/tls/api-token (mode 0600)"

testacc-tls:
	@test -f ./testdata/tls/api-token || (echo "ERROR: ./testdata/tls/api-token missing; run testacc-token-tls first" && exit 1)
	@TECHNITIUM_SERVER_URL=https://127.0.0.1:5443 \
	 TECHNITIUM_CACERT=$$(pwd)/testdata/tls/ca.pem \
	 TECHNITIUM_API_TOKEN=$$(cat ./testdata/tls/api-token) \
	 TF_ACC=1 \
	 go test -v ./... -count=1 -timeout 120m

testacc-up-tls:
	$(MAKE) testacc-tls-prep
	docker compose -f docker-compose.test.yml -f docker-compose.test.tls.yml up -d --wait
	@echo "Waiting for HTTPS admin endpoint to accept requests..."
	@PW=$$( (test -f .env.test && grep -E '^DNS_ADMIN_PASSWORD=' .env.test | cut -d= -f2) || echo admin ); \
	for i in $$(seq 1 60); do \
		if curl -sf --cacert ./testdata/tls/ca.pem --max-time 2 \
		    "https://127.0.0.1:5443/api/user/login?user=admin&pass=$$PW" >/dev/null 2>&1; then \
			echo "HTTPS endpoint ready after $$i attempt(s)"; break; \
		fi; \
		if [ $$i -eq 60 ]; then \
			echo "ERROR: HTTPS endpoint never became ready (60 attempts, ~60s)"; exit 1; \
		fi; \
		sleep 1; \
	done
	$(MAKE) testacc-token-tls
	$(MAKE) testacc-tls

testacc-down-tls:
	docker compose -f docker-compose.test.yml -f docker-compose.test.tls.yml down -v
	# .testdata/config is a bind mount, not a docker volume, so `down -v`
	# does not clear it. Files inside it are owned by root (because the
	# Technitium container runs as root — see issue #36), so a host-side
	# `rm -rf` would need sudo. Use a throwaway container to wipe it
	# instead, which avoids any host privilege requirement.
	@if [ -d ./.testdata/config ]; then \
		docker run --rm -v "$$(pwd)/.testdata:/wipe" alpine:latest rm -rf /wipe/config; \
	fi
	rm -rf ./testdata/tls

generate:
	go generate ./...
	go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.24.0 generate

docs:
	go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.24.0 generate

lint:
	golangci-lint run ./...

install:
	go build -o ~/.terraform.d/plugins/registry.terraform.io/darkhonor/technitium/0.0.1/$$(go env GOOS)_$$(go env GOARCH)/terraform-provider-technitium

generate-stig:
	@echo "Generating STIG baselines..."
	go run ./tools/generate_stig_baselines.go
	@echo "Generated internal/provider/validators/stig_baselines_gen.go"

.PHONY: build build-fips test test-fips testacc testacc-token testacc-up testacc-down testacc-tls-prep testacc-token-tls testacc-tls testacc-up-tls testacc-down-tls generate docs lint install generate-stig
