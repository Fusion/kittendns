PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugin_jsscript: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/jsscript.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/jsscript.so: plugins/jsscript/jsscript.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_jsscript_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin_jsscript
