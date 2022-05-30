SHELL := /bin/bash

build:
	@goreleaser build --skip-validate --single-target --rm-dist

test:
	@go test

# Note that sourceme contains GITHUB_TOKEN for release.
release:
	@source sourceme && goreleaser release

.PHONY: build release test
