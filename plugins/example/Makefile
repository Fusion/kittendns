plugin_example: dist/$(PLUGIN_OS)$(PLUGIN_ARCH)/example.so

dist/$(PLUGIN_OS)$(PLUGIN_ARCH)/example.so: plugins/example/example.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) CGO_ENABLED=1 go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^
