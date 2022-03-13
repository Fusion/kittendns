build:
	@go build -ldflags="-s -w" -o kittendns main.go

.PHONY: build
