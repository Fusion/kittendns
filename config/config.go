package config

type Settings struct {
	Listen     uint16
	DebugLevel uint8
}

type Record struct {
	Host string
	IPv4 string
	TTL  uint32
}

type Zone struct {
	Origin string
	TTL    uint32
	Record []Record
}

type Rule struct {
	Condition string
	Action    string
}

type Config struct {
	Settings Settings
	Zone     []Zone
	Records  map[string]*Record
	Rule     []Rule
}
