package config

type Settings struct {
	Listen     uint16
	DebugLevel uint8
}

type Auth struct {
	Ns     string
	Email  string
	Serial uint32
}

type Record struct {
	Type uint16

	Host string

	IPv4  string
	IPv4s []string

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
