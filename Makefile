build:
	@go build -ldflags="-s -w" -o bin/kittendns main.go

include plugins/Makefile

release:
	@goreleaser release

.PHONY: build release
