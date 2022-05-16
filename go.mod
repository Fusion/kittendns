module github.com/fusion/kittendns

go 1.18

replace github.com/miekg/dns => ./dns

require (
	github.com/antonmedv/expr v1.9.0
	github.com/davecgh/go-spew v1.1.1
	github.com/hydronica/toml v0.5.0
	github.com/miekg/dns v1.1.47
	github.com/stretchr/testify v1.5.1
)

require (
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20210726213435-c6fcb2dbf985 // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/tools v0.1.6-0.20210726203631-07bc1bf47fb2 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/yaml.v2 v2.2.2 // indirect
)
