package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/fusion/kittendns/secret"
	"github.com/hydronica/toml"
)

type Parent struct {
	// May be suffixed with [:port]
	Address string
}
type Settings struct {
	DebugLevel uint8
	AutoReload bool
	// ["ip:port", ...]
	// Each instance should identify a working ip address from this list
	Listeners []string
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

type Mailer struct {
	Host     string
	Priority uint16
	TTL      uint32
	NoMailer bool
}

type NameServer struct {
	Host   string
	Target string
	TTL    uint32
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
	Service   string
	Priority  uint16
	Proto     string
	Weight    uint16
	Port      uint16
	Target    string
	NoService bool

	// TXT
	Text string

	Origin string
	TTL    uint32
	Auth   Auth
}

type Zone struct {
	Origin     string
	TTL        uint32
	Auth       Auth
	Record     []Record
	Mailer     []Mailer
	NameServer []NameServer
}

type Rule struct {
	Condition string
	Action    string
}

type Plugin struct {
	Enabled     bool
	Path        string
	PreHandler  string
	PostHandler string
	Arguments   []string
	Monitor     []string
}

type Config struct {
	Settings Settings
	Zone     []Zone
	Records  map[string]Record
	Rule     []Rule
	Plugin   []Plugin
	Monitor  []string
	Secret   secret.Secret
}

func GetConfig() *Config {
	var config Config
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Fatal(err)
	}
	var secret secret.Secret
	// TODO Place secret in another, convenient location!
	if _, err := toml.DecodeFile("secret.toml", &secret); err != nil {
		log.Fatal(err)
	}
	config.Secret = secret

	// Default parent dns to port 53 is not set, but parent _is_ set
	if config.Settings.Parent.Address != "" && !strings.Contains(config.Settings.Parent.Address, ":") {
		config.Settings.Parent.Address = fmt.Sprintf("%s:%d", config.Settings.Parent.Address, 53)
	}
	return &config
}
