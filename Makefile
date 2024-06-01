SHELL := /bin/bash
BUILD_FLAGS?=-s -w
TRIM_FLAGS=
MAIN_TARGETS?=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64
PLUGIN_TARGETS?=linux/amd64,linux/arm64,darwin/amd64,darwin/arm64
GO_RELEASE_V=$(shell go version | { read _ _ v _; echo $${v#go}; })

#include plugins/Makefile

build:
	@mkdir -p bin && go build ${TRIM_FLAGS} -ldflags "${BUILD_FLAGS}" -o bin/kittendns main.go

test:
	@go test

linuxamd64:
	@mkdir -p dist/$@ && GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o dist/$@/kittendns main.go

linuxarm64:
	@mkdir -p dist/$@ && GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o dist/$@/kittendns main.go

darwinamd64:
	@mkdir -p dist/$@ && GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o dist/$@/kittendns main.go

darwinarm64:
	@mkdir -p dist/$@ && GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o dist/$@/kittendns main.go

winamd64:
	@mkdir -p dist/$@ && GOOS=windows GOARCH=amd64 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -o dist/$@/kittendns main.go

plugins:
	@PLUGIN_OS=linux PLUGIN_ARCH=amd64 make plugin_example plugin_jsscript

plugins_darwin:
	@PLUGIN_OS=darwin PLUGIN_ARCH=amd64 make plugin_example plugin_jsscript
	@PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin_example plugin_jsscript

fullrelease:
	@cd scripts && ./release.sh main

release: linuxamd64 linuxarm64 winamd64

release_darwin: darwinamd64 darwinarm64

releasemain:
	@xgo -v -ldflags="${BUILD_FLAGS}" -trimpath -go ${GO_RELEASE_V} -out kittendns -dest bin -buildvcs=false --targets="${MAIN_TARGETS}" .

releaseplugin:
	@echo "Building $P plugin $M"; \
	xgo -v -ldflags="${BUILD_FLAGS}" -trimpath -go ${GO_RELEASE_V} -out $P -dest bin -buildvcs=false -buildmode=plugin --targets="${PLUGIN_TARGETS}" --pkg $M/$P.go . && \
	(cd bin && for lib in $$(ls $$P-*); do sudo mv $$lib $$lib.so; done); \

releaseplugins:
	@for pkg in $$(find plugins/* -depth -maxdepth 0 -type d); do \
		P=$$(echo $$pkg | cut -d'/' -f 2) M=$$pkg make releaseplugin; \
	done

.PHONY: build release release_darwin test linuxamd64 linuxarm64 darwinamd64 darwinarm64 winamd64 plugins plugins_darwin
