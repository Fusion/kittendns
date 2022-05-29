PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugin_example: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/example.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/example.so: plugins/example/example.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_example_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin_example