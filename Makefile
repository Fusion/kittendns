build:
	@go build -ldflags="-s -w" -o kittendns main.go

release:
	@goreleaser release

.PHONY: build release
