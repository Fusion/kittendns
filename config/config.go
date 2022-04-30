package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/hydronica/toml"
)

type Parent struct {
	// May be suffixed with [:port]
	Address string
}
type Settings struct {
	Listen     uint16
	DebugLevel uint8
	// If true, when multiple records are found for a domain, only one is returned
	// A different one every time.
	// If false, all records are returned.
	LoadBalance bool
	// In lazy mode, when a CNAME is found, the CNAME is returned and the
	// target is not resolved.
	Lazy bool
	// A caching DNS will not refresh its knowledge until Ttl value expires
	Cache bool
	// If true, CNAME chains will be merged into a single record
	Flatten bool
	// Disabling the rule engine speeds up simple DNS lookups
	DisableRuleEngine bool

	// DNS to recurse to when an authoritative answer does not exist.
	Parent Parent
}

type Auth struct {
	Ns     string
	Email  string
	Serial uint32
}

type Record struct {
	Type uint16

	Host string

	// A
	IPv4  string
	IPv4s []string

	// AAAA
	IPv6  string
	IPv6s []string

	// CNAME
	Aliased string

	// SRV
	Service  string
	Proto    string
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string

	Origin string
	TTL    uint32
	Auth   Auth
}

type Zone struct {
	Origin string
	TTL    uint32
	Auth   Auth
	Record []Record
}

type Rule struct {
	Condition string
	Action    string
}

type Config struct {
	Settings Settings
	Zone     []Zone
	Records  map[string]Record
	Rule     []Rule
}

func GetConfig() *Config {
	var config Config
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Fatal(err)
	}
	// Default parent dns to port 53 is not set, but parent _is_ set
	if config.Settings.Parent.Address != "" && !strings.Contains(config.Settings.Parent.Address, ":") {
		config.Settings.Parent.Address = fmt.Sprintf("%s:%d", config.Settings.Parent.Address, 53)
	}
	return &config
}
