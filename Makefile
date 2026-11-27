.PHONY: install build test test-ts test-go test-py simulate dev clean

install:
	pnpm install

build:
	pnpm build
	mkdir -p bin
	cd services/gate && go build -o ../../bin/vectoll-gate ./cmd/vectoll-gate

test: test-ts test-go test-py

test-ts:
	pnpm test

test-go:
	cd services/gate && go test -race -v ./...

test-py:
	PYTHONPATH=sdks/python/src pytest -v sdks/python

simulate:
	node packages/cli/dist/bin.js simulate --rail x402_usdc

dev:
	node packages/cli/dist/bin.js dev --config examples/global-cloud-ai/vectoll.yaml

clean:
	rm -rf bin packages/*/dist apps/*/dist
