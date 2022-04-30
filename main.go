package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/antonmedv/expr"
	"github.com/davecgh/go-spew/spew"
	"github.com/fusion/kittendns/cache"
	"github.com/fusion/kittendns/config"
	"github.com/miekg/dns"
)

type ResolverEntry struct {
	NextIPv4 uint8
	NextIPv6 uint8
}
type Resolver struct {
	sync.RWMutex
	entries *map[string]ResolverEntry
}
type App struct {
	Config   *config.Config
	Records  *map[string]config.Record
	Resolver *Resolver
	Cache    *cache.RcCache
}

func main() {

	app := App{}

	app.Config = config.GetConfig()
	app.Records = flattenRecords(app.Config)
	app.Resolver = &Resolver{entries: &map[string]ResolverEntry{}}
	app.Cache = &cache.RcCache{}

	// attach request handler func
	dns.HandleFunc(".", app.handleDnsRequest)

	// start server
	port := int(app.Config.Settings.Listen)
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Listening on port %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func flattenRecords(cfg *config.Config) *map[string]config.Record {
	var noAuth config.Auth

	records := map[string]config.Record{}
	for _, zone := range cfg.Zone {
		for _, record := range zone.Record {
			if zone.Auth != noAuth {
				record.Auth = config.Auth{
					Ns:     zone.Auth.Ns,
					Email:  zone.Auth.Email,
					Serial: zone.Auth.Serial,
				}
			}
			record.Origin = zone.Origin
			if record.TTL == 0 {
				record.TTL = zone.TTL
			}

			// SRV Record
			if record.Service != "" {
				if record.Host != "" {
					log.Println("Ignored:: Host and Service cannot be set at the same time.")
					continue
				}
				if record.Target == "" {
					log.Println("Ignored:: No Target specified for a Service.")
					continue
				}
				record.Target = canonicalize(record.Origin, record.Target)
				if record.Proto == "" {
					record.Proto = "tcp"
				}
				if record.Priority == 0 {
					record.Priority = 10
				}
				if record.Weight == 0 {
					record.Weight = 10
				}
				record.Type = dns.TypeSRV
				records[fmt.Sprintf("_%s._%s.%s", record.Service, record.Proto, zone.Origin)] = record
				continue
			}

			// CNAME Record
			if record.Aliased != "" {
				ipv4 := flattenIPs(record.IPv4, record.IPv4s, NotMandatory)
				ipv6 := flattenIPs(record.IPv6, record.IPv6s, NotMandatory)
				if len(ipv4) > 0 || len(ipv6) > 0 {
					log.Println("Ignored:: Aliased and IPv4/IPv6 cannot be set at the same time.")
					continue
				}
				if record.Host == "@" {
					log.Println("Ignored:: Origin record cannot be aliased.")
					continue
				}
				record.Aliased = canonicalize(record.Origin, record.Aliased)
				record.Type = dns.TypeCNAME
				records[canonicalize(zone.Origin, record.Host)] = record
				continue
			}

			// A Record
			record.IPv4s = flattenIPs(record.IPv4, record.IPv4s, NotMandatory)
			record.IPv6s = flattenIPs(record.IPv6, record.IPv6s, NotMandatory)
			record.Type = dns.TypeA
			if record.Host == "@" {
				records[zone.Origin] = record
				continue
			}

			if len(record.IPv4s) == 0 && len(record.IPv6s) == 0 {
				log.Fatal("Found record with no IPs, not alias.")
			}

			records[canonicalize(zone.Origin, record.Host)] = record
		}
	}
	if cfg.Settings.DebugLevel > 2 {
		spew.Dump(records)
	}
	return &records
}

func canonicalize(origin string, host string) string {
	if strings.HasSuffix(host, ".") {
		return host
	}
	return fmt.Sprintf("%s.%s", host, origin)
}

type MandatoryValue int

const (
	Mandatory MandatoryValue = iota
	NotMandatory
)

func flattenIPs(ip string, ips []string, mandatory MandatoryValue) []string {
	var emptyIP string
	mergedIps := []string{}
	if ip != emptyIP {
		mergedIps = append(mergedIps, ip)
	}
	if ips != nil {
		mergedIps = append(mergedIps, ips...)
	}
	if mandatory == Mandatory {
		if len(mergedIps) == 0 {
			log.Fatal("Found record with no IPs")
		}
	}
	return mergedIps
}

func (app *App) handleDnsRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		app.parseQuery(ctx, m)
	}

	w.WriteMsg(m)
}

func (app *App) parseQuery(ctx context.Context, m *dns.Msg) {
	for _, q := range m.Question {
		// This variable will be set to true if this is something
		// we can resolve locally.
		authoritative := false
		lowerName := strings.ToLower(q.Name)
		for _, zone := range app.Config.Zone {
			if strings.HasSuffix(lowerName, zone.Origin) {
				authoritative = true
				break
			}
		}
		if authoritative {
			app.authoritativeSearch(ctx, m, q)
			continue
		} else {
			// TODO Check if RecursionRequested
			app.recursiveSearch(ctx, m, q)
		}

	}
}

func (app *App) authoritativeSearch(ctx context.Context, m *dns.Msg, q dns.Question) {
	var noAuth config.Auth

	var answers []dns.RR
	var soa, noSoa dns.RR
	var record config.Record
	var ok bool

	lowerName := strings.ToLower(q.Name)

	switch q.Qtype {

	case dns.TypeSOA:
		if app.Config.Settings.DebugLevel > 0 {
			log.Printf("Zone SOA Query %s\n", q.Name)
		}
		for _, zone := range app.Config.Zone {
			if zone.Origin == lowerName {
				soa := newSOA(zone.Origin, zone.Auth.Ns, zone.Auth.Email, zone.Auth.Serial)
				m.Ns = []dns.RR{soa}
			}
		}

	case dns.TypeSRV:
		if app.Config.Settings.DebugLevel > 0 {
			log.Printf("SRV Query %s\n", q.Name)
		}
		record, ok := (*app.Records)[lowerName]
		if ok && record.Type == dns.TypeSRV {
			srv := newSRV(q.Name, record.Target, record.Port, record.Priority, record.Weight, record.TTL)
			answers = []dns.RR{srv}
		}

	case dns.TypeAAAA, dns.TypeA, dns.TypeCNAME:
		record, ok = (*app.Records)[lowerName]
		if ok {
			if record.Type == dns.TypeCNAME {
				if app.Config.Settings.DebugLevel > 0 {
					log.Printf("CNAME Query for %s\n", q.Name)
				}
				alias := newCNAME(q.Name, record.Aliased, record.TTL)
				answers = []dns.RR{alias}
			} else if (record.Type == dns.TypeA || record.Type == dns.TypeAAAA) && q.Qtype != dns.TypeCNAME {
				if app.Config.Settings.DebugLevel > 0 {
					log.Printf("Query for %s\n", q.Name)
				}
				if app.Config.Settings.LoadBalance {
					app.Resolver.RWMutex.RLock()
					resolver, ok := (*app.Resolver.entries)[lowerName]
					app.Resolver.RWMutex.RUnlock()
					if !ok {
						app.Resolver.RWMutex.Lock()
						(*app.Resolver.entries)[lowerName] = ResolverEntry{
							NextIPv4: 0,
							NextIPv6: 0}
						app.Resolver.RWMutex.Unlock()
					}

					var nextIP *uint8
					var recordIPs *[]string

					if q.Qtype == dns.TypeAAAA {
						nextIP = &resolver.NextIPv6
						recordIPs = &record.IPv6s
					} else {
						nextIP = &resolver.NextIPv4
						recordIPs = &record.IPv4s
					}

					if len(*recordIPs) == 0 {
						break
					}

					app.Resolver.RWMutex.Lock()
					resolver = (*app.Resolver.entries)[lowerName]
					nextNextIP, ip := getNextIP(nextIP, recordIPs)
					*nextIP = nextNextIP
					(*app.Resolver.entries)[lowerName] = resolver
					app.Resolver.RWMutex.Unlock()

					rr, err := newRR(q.Qtype, q.Name, record.Host, ip, record.TTL)
					if err == nil {
						answers = []dns.RR{rr}
					}
				} else {
					var recordIPs *[]string

					if q.Qtype == dns.TypeAAAA {
						recordIPs = &record.IPv6s
					} else {
						recordIPs = &record.IPv4s
					}
					for _, ip := range *recordIPs {
						rr, err := newRR(q.Qtype, q.Name, record.Host, ip, record.TTL)
						if err == nil {
							answers = append(answers, rr)
						}
					}
				}
			}
		}

	default:
		if app.Config.Settings.DebugLevel > 0 {
			log.Println(fmt.Sprintf("Not supported: request type=%d", q.Qtype))
		}
	}

	if record.Auth != noAuth {
		soa = newSOA(record.Origin, record.Auth.Ns, record.Auth.Email, record.Auth.Serial)
	}

	// To the rule engine
	if app.Config.Settings.DisableRuleEngine {
		if app.Config.Settings.DebugLevel > 2 {
			log.Println("Skipping the rule engine")
		}
		for _, answer := range answers {
			if app.Config.Settings.DebugLevel > 2 {
				log.Println("Providing answer", answer)
			}
			m.Answer = append(m.Answer, answer)

			if !app.Config.Settings.Lazy {
				// If this is a CNAME, keep digging until we find an A record
				if answer.Header().Rrtype == dns.TypeCNAME {
					q.Name = answer.(*dns.CNAME).Target
					app.authoritativeSearch(ctx, m, q)
				}
			}

			if soa != noSoa {
				m.Ns = []dns.RR{soa}
			}
		}
		return
	}

	remoteip := ""
	remoteAddr := ctx.Value("remoteaddr")
	if remoteAddr != nil {
		remoteip = strings.Split(remoteAddr.(string), ":")[0]
	}

	for _, answer := range answers {
		action := app.parseRules(remoteip, lowerName, answer)
		if action == "" {
			if app.Config.Settings.DebugLevel > 2 {
				log.Println("Providing answer", answer)
			}
			m.Answer = append(m.Answer, answer)

			if !app.Config.Settings.Lazy {
				// If this is a CNAME, keep digging until we find an A record
				if answer.Header().Rrtype == dns.TypeCNAME {
					q.Name = answer.(*dns.CNAME).Target
					app.authoritativeSearch(ctx, m, q)
				}
			}

			if soa != noSoa {
				m.Ns = []dns.RR{soa}
			}
			continue
		}
		if action == "drop" {
			// Do nothing ... no response
			continue
		}
		if action == "inspect" {
			spew.Dump(record)
			continue
		}
		if strings.HasPrefix(action, "rewrite ") {
			shadowIP := unquote(strings.TrimPrefix(action, "rewrite "))
			rr, _ := newRR(dns.TypeA, q.Name, q.Name, shadowIP, 3600) // TODO Fix TTL and type
			m.Answer = append(m.Answer, rr)
			continue
		}
	}
}

func (app *App) recursiveSearch(ctx context.Context, m *dns.Msg, q dns.Question) {
	if app.Config.Settings.Parent.Address == "" {
		if app.Config.Settings.DebugLevel > 2 {
			log.Println("Not recursing as no parent was defined.")
		}
		return

	}

	lowerName := strings.ToLower(q.Name)

	answers, ok, remaining := app.Cache.Get(lowerName)
	if ok {
		if app.Config.Settings.DebugLevel > 2 {
			log.Println("Cache hit for", q.Name, "remaining", remaining, "seconds")
		}
		m.Answer = answers
	} else {
		recM := new(dns.Msg)
		recM.Id = dns.Id()
		recM.RecursionDesired = true
		recM.Question = []dns.Question{q}
		client := new(dns.Client)
		if app.Config.Settings.DebugLevel > 0 {
			log.Println("Recursing to", app.Config.Settings.Parent.Address)
		}
		response, _, err := client.Exchange(recM, app.Config.Settings.Parent.Address)
		if err != nil {
			log.Println(err)
			return
		}

		if len(response.Answer) < 1 {
			log.Println("No answer")
			return
		}
		app.Cache.Set(
			cache.Flatten,
			lowerName,
			q.Qtype,
			response.Answer,
			uint32(response.Answer[0].Header().Ttl))
		m.Answer = response.Answer
	}
	// Do not copy Ns as we cannot be authoritative

	// TODO Implement rule engine knowing that all answers are within a single message
}

func getNextIP(idx *uint8, ips *[]string) (uint8, string) {
	ip := (*ips)[*idx]
	nextIdx := *idx + 1
	if nextIdx >= uint8(len(*ips)) {
		nextIdx = 0
	}
	return nextIdx, ip
}

func (app *App) parseRules(remoteip string, host string, answer dns.RR) string {
	if app.Config.Settings.DebugLevel > 2 {
		log.Printf("Parsing rules for host [%s], remoteip [%s]\n", host, remoteip)
	}

	env := map[string]interface{}{
		"host":     host,
		"remoteip": remoteip,
	}
	for _, rule := range app.Config.Rule {
		out, err := expr.Eval(rule.Condition, env)
		if err != nil {
			log.Println("Bad rule", err)
			continue
		}
		if out == false {
			continue
		}
		// Matched
		if app.Config.Settings.DebugLevel > 2 {
			log.Println("Matched rule", rule.Condition, "->", rule.Action)
		}
		return rule.Action
	}
	if app.Config.Settings.DebugLevel > 2 {
		log.Println("No rule applies")
	}
	return ""
}

func newRR(recordType uint16, query string, host string, ip string, ttl uint32) (dns.RR, error) {
	textType := "A"
	if recordType == dns.TypeAAAA {
		textType = "AAAA"
	}
	rr, err := dns.NewRR(
		fmt.Sprintf(
			"%s %d %s %s",
			query,
			ttl,
			textType,
			ip))
	return rr, err
}

func newCNAME(query string, target string, ttl uint32) dns.RR {
	alias := new(dns.CNAME)
	alias.Hdr = dns.RR_Header{
		Name:   query,
		Rrtype: dns.TypeCNAME,
		Class:  dns.ClassINET,
		Ttl:    ttl}
	alias.Target = target
	return alias
}

func newSRV(query string, target string, port uint16, priority uint16, weight uint16, ttl uint32) dns.RR {
	srv := new(dns.SRV)
	srv.Hdr = dns.RR_Header{
		Name:     query,
		Rrtype:   dns.TypeSRV,
		Class:    dns.ClassINET,
		Ttl:      ttl,
		Rdlength: 0}
	srv.Port = port
	srv.Priority = priority
	srv.Weight = weight
	srv.Target = target
	return srv
}

func newSOA(origin string, ns string, mbox string, serial uint32) dns.RR {
	soa := new(dns.SOA)
	soa.Hdr = dns.RR_Header{
		Name:     origin,
		Rrtype:   dns.TypeSOA,
		Class:    dns.ClassINET,
		Ttl:      14400,
		Rdlength: 0}
	soa.Ns = fmt.Sprintf("%s.", ns)
	soa.Mbox = fmt.Sprintf("%s.", mbox)
	soa.Serial = serial
	soa.Refresh = 86400
	soa.Retry = 7200
	soa.Expire = (86400 + 7200*2)
	soa.Minttl = 7200
	return soa
}

func unquote(str string) string {
	if len(str) > 0 && str[0] == '\'' {
		str = str[1:]
	}
	if len(str) > 0 && str[len(str)-1] == '\'' {
		str = str[:len(str)-1]
	}
	return str
}
