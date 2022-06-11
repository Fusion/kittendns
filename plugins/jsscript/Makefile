plugin_jsscript: dist/$(PLUGIN_OS)$(PLUGIN_ARCH)/jsscript.so

dist/$(PLUGIN_OS)$(PLUGIN_ARCH)/jsscript.so: plugins/jsscript/jsscript.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^
