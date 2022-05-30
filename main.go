package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/antonmedv/expr"
	"github.com/davecgh/go-spew/spew"
	"github.com/fsnotify/fsnotify"
	"github.com/fusion/kittendns/builders"
	"github.com/fusion/kittendns/cache"
	"github.com/fusion/kittendns/config"
	"github.com/fusion/kittendns/plugins"
	"github.com/miekg/dns"
)

type ResolverEntry struct {
	NextIPv4 uint8
	NextIPv6 uint8
}
type Resolver struct {
	sync.RWMutex
	entries *map[uint16]map[string]ResolverEntry
}
type App struct {
	Config   *config.Config
	Plugins  *plugins.Plugins
	Records  *map[uint16]map[string]config.Record
	Mailers  *map[string][]config.Mailer
	Resolver *Resolver
	Cache    *cache.RcCache
}

func main() {
	for {
		if err := singleLifeCycle(); err != nil {
			return
		}
	}
}

func singleLifeCycle() error {
	app := App{}

	app.Config = config.GetConfig()
	app.Plugins = plugins.Load(app.Config)
	app.Mailers = flattenMailers(app.Config)
	app.Records = flattenRecords(app.Config)
	app.Resolver = &Resolver{entries: &map[uint16]map[string]ResolverEntry{
		dns.TypeA:     {},
		dns.TypeAAAA:  {},
		dns.TypeCNAME: {},
		//dns.TypeNS: {},
		//dns.TypePTR: {},
		dns.TypeSOA: {},
		dns.TypeSRV: {},
		dns.TypeTXT: {},
	}}
	app.Cache = &cache.RcCache{}

	// attach request handler func
	dns.HandleFunc(".", app.handleDnsRequest)

	// start server
	port := int(app.Config.Settings.Listen)
	server_u := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp", MsgAcceptFunc: moreLenientAcceptFunc}
	server_t := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "tcp", MsgAcceptFunc: moreLenientAcceptFunc}
	if app.Config.Secret.Signature != "" {
		server_u.TsigSecret = map[string]string{app.Config.Secret.Key: app.Config.Secret.Signature}
		server_t.TsigSecret = map[string]string{app.Config.Secret.Key: app.Config.Secret.Signature}
	}
	log.Printf("Listening on port %d\n", port)
	go server_u.ListenAndServe()
	go server_t.ListenAndServe()

	// server lifecycle
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println("Warning: unable to start watching config changes.")
		return err
	}

	if app.Config.Settings.AutoReload {
		log.Println("Watching config for changes.")
		watchable := []string{"config.toml", "secret.toml"}
		for _, path := range watchable {
			if err := watcher.Add(path); err != nil {
				// NOTE: be careful... we may the one modifying dynamic.toml!
				log.Println("Warning: unable to watch config changes to " + path + ".")
			}
		}
	}

	// If we receive notification of configuration change, we will wait a bit before reloading.
	// If we are too fast, we will find out that we got the notification before the file was
	// committed to disk!
	for {
		select {
		case event := <-watcher.Events:
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Rename == fsnotify.Rename {
				log.Printf("Config file changed, reloading.\n")
				time.Sleep(1 * time.Second)
				watcher.Close()
				return nil
			}
		case received := <-sig:
			if received == syscall.SIGHUP {
				log.Printf("Signal %s received, restarting.\n", received.String())
				watcher.Close()
				return nil
			}
			log.Printf("Signal %s received, stopping.\n", received.String())
			return errors.New("Signal received.")
		}
	}
}

const (
	_QR = 1 << 15 // query/response (response=1)
)

func moreLenientAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	if isResponse := dh.Bits&_QR != 0; isResponse {
		return dns.MsgIgnore
	}

	// Don't allow dynamic updates, because then the sections can contain a whole bunch of RRs.
	opcode := int(dh.Bits>>11) & 0xF

	//log.Printf("opcode: %+v %+v %+v %+v %+v", opcode, dh.Qdcount, dh.Ancount, dh.Nscount, dh.Arcount)

	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeNotify && opcode != dns.OpcodeUpdate {
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	// NOTIFY requests can have a SOA in the ANSWER section. See RFC 1996 Section 3.7 and 3.11.
	if dh.Ancount > 1 {
		return dns.MsgReject
	}
	// IXFR request could have one SOA RR in the NS section. See RFC 1995, section 3.
	if dh.Nscount > 1 {
		return dns.MsgReject
	}
	if dh.Arcount > 2 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}

func flattenMailers(cfg *config.Config) *map[string][]config.Mailer {
	mailers := map[string][]config.Mailer{}
	for _, zone := range cfg.Zone {
		if zone.Mailer != nil {
			zoneMailers := []config.Mailer{}
			noMailer := false
			for _, mailer := range zone.Mailer {
				if mailer.TTL == 0 {
					mailer.TTL = zone.TTL
				}
				if mailer.NoMailer {
					noMailer = true
					continue
				}
				mailer.Host = canonicalize(zone.Origin, mailer.Host)
				zoneMailers = append(zoneMailers, mailer)
			}
			// RFC7505
			if noMailer {
				if len(zoneMailers) > 0 {
					log.Println("Ignored:: Defined both 'no mailer' and actual mailers.")
				} else {
					zoneMailers = []config.Mailer{{Host: ".", Priority: 0, TTL: zone.TTL}}
				}
			}
			mailers[zone.Origin] = zoneMailers
		}
	}
	return &mailers
}

func flattenRecords(cfg *config.Config) *map[uint16]map[string]config.Record {
	var noAuth config.Auth

	records := map[uint16]map[string]config.Record{
		dns.TypeA:     {},
		dns.TypeAAAA:  {},
		dns.TypeCNAME: {},
		//dns.TypeNS: {},
		//dns.TypePTR: {},
		dns.TypeSOA: {},
		dns.TypeSRV: {},
		dns.TypeTXT: {},
	}
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
				if record.Text != "" {
					log.Println("Ignored:: Text and Service cannot be set at the same time.")
					continue
				}
				if record.Target != "" && record.NoService {
					log.Println("Ignored:: Both 'no service' and an actual target defined for Service.")
					continue
				}
				// RFC2782
				if record.NoService {
					record.Target = "."
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
				records[dns.TypeSRV][fmt.Sprintf("_%s._%s.%s", record.Service, record.Proto, zone.Origin)] = record
			}
			// TXT Record
			if record.Text != "" {
				if record.Host != "" {
					log.Println("Ignored:: Host and Text cannot be set at the same time.")
					continue
				}
				if record.Target == "" {
					log.Println("Ignored:: No Target specified for a Text record.")
					continue
				}
				record.Type = dns.TypeTXT
				records[dns.TypeTXT][fmt.Sprintf("%s.%s", record.Text, zone.Origin)] = record
			}
			// Finally, our default resolution records
			ipv4 := flattenIPs(record.IPv4, record.IPv4s, NotMandatory)
			ipv6 := flattenIPs(record.IPv6, record.IPv6s, NotMandatory)
			// CNAME Record
			if record.Aliased != "" {
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
				records[dns.TypeCNAME][canonicalize(zone.Origin, record.Host)] = record
				continue
			}
			if len(ipv4) == 0 && len(ipv6) == 0 {
				continue
			}
			// A Record
			record.IPv4s = ipv4
			record.IPv6s = ipv6
			record.Type = dns.TypeA
			if record.Host == "@" {
				records[dns.TypeA][zone.Origin] = record
				continue
			}
			/*
				if len(record.IPv4s) == 0 && len(record.IPv6s) == 0 {
					log.Fatal("Found record with no IPs, not alias.")
				}
			*/
			records[dns.TypeA][canonicalize(zone.Origin, record.Host)] = record
		}
	}
	if cfg.Settings.DebugLevel > 2 {
		spew.Dump(records)
	}
	return &records
}

func canonicalize(origin string, host string) string {
	if host == "@" {
		return origin
	}
	if !strings.Contains((host), ".") {
		host = fmt.Sprintf("%s.%s", host, origin)
	}
	if !strings.HasSuffix(host, ".") {
		host = fmt.Sprintf("%s.", host)
	}
	return host
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

	for _, e := range r.Extra {
		// Are you trying to escalate privilege, maybe?
		if e.Header().Rrtype == dns.TypeTSIG {
			if w.TsigStatus() != nil {
				log.Println("TSIG not validated:", w.TsigStatus())
				w.WriteMsg(m)
				return
			}
			ctx = context.WithValue(ctx, "privileged", true)
		}
	}

	switch r.Opcode {
	case dns.OpcodeQuery:
		app.parseQuery(ctx, m)
	case dns.OpcodeUpdate:
		m.Ns = r.Ns
		app.parseUpdate(ctx, m)
	}

	w.WriteMsg(m)
}

func (app *App) parseQuery(ctx context.Context, m *dns.Msg) {
	for _, q := range m.Question {
		done, err := app.processPrePlugins(ctx, m, &q)
		if done {
			continue
		}
		if err != nil {
			break
		}
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
		} else {
			// TODO Check if RecursionRequested
			app.recursiveSearch(ctx, m, q)
		}
		err = app.processPostPlugins(ctx, m, &q)
		if err != nil {
			break
		}
	}
}

func (app *App) processPrePlugins(ctx context.Context, m *dns.Msg, q *dns.Question) (bool, error) {
	done := false
	for _, plugin := range app.Plugins.PreHandler {
		update, err := plugin.ProcessQuery(plugins.Pre, m, q)
		if err != nil {
			return false, err
		}
		if update != nil {
			if update.Done {
				done = true
			}
			if update.Action == plugins.Reply {
				m.Answer = append(m.Answer, update.RR...)
			} else if update.Action == plugins.Question {
				q = update.Question
			}
			if update.Stop {
				return done, nil
			}
		}
	}
	return done, nil
}

func (app *App) processPostPlugins(ctx context.Context, m *dns.Msg, q *dns.Question) error {
	for _, plugin := range app.Plugins.PostHandler {
		update, err := plugin.ProcessQuery(plugins.Post, m, q)
		if err != nil {
			return err
		}
		if update != nil {
			if update.Action == plugins.Reply {
				m.Answer = append(m.Answer, update.RR...)
			} else if update.Action == plugins.Rewrite {
				m.Answer = update.RR
			}
			if update.Stop {
				return nil
			}
		}
	}
	return nil
}

func (app *App) parseUpdate(ctx context.Context, m *dns.Msg) {
	for _, n := range m.Ns {
		app.authoritativeUpdate(ctx, m, n, m.Extra)
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
				soaanswer := builders.NewSOA(zone.Origin, zone.Auth.Ns, zone.Auth.Email, zone.Auth.Serial)
				answers = []dns.RR{soaanswer}
				break
			}
		}

	case dns.TypeSRV:
		if app.Config.Settings.DebugLevel > 0 {
			log.Printf("SRV Query %s\n", q.Name)
		}
		record, ok := (*app.Records)[dns.TypeSRV][lowerName]
		if ok {
			srv := builders.NewSRV(q.Name, record.Target, record.Port, record.Priority, record.Weight, record.TTL)
			answers = []dns.RR{srv}
		}

	case dns.TypeTXT:
		if app.Config.Settings.DebugLevel > 0 {
			log.Printf("TXT Query %s\n", q.Name)
		}
		record, ok := (*app.Records)[dns.TypeTXT][lowerName]
		if ok {
			txt := builders.NewTXT(q.Name, record.Target, record.TTL)
			answers = []dns.RR{txt}
		}

	case dns.TypeMX:
		if app.Config.Settings.DebugLevel > 0 {
			log.Printf("MX Query %s\n", q.Name)
		}
		mailers, ok := (*app.Mailers)[lowerName]
		if ok {
			for _, mailer := range mailers {
				mx := builders.NewMX(q.Name, mailer.Host, mailer.Priority, mailer.TTL)
				answers = append(answers, mx)
			}
		}

	case dns.TypeAAAA, dns.TypeA, dns.TypeCNAME:
		record, ok = (*app.Records)[dns.TypeA][lowerName]
		if !ok {
			record, ok = (*app.Records)[dns.TypeCNAME][lowerName]
		}
		if ok {
			if record.Type == dns.TypeCNAME {
				if app.Config.Settings.DebugLevel > 0 {
					log.Printf("CNAME Query for %s\n", q.Name)
				}
				alias := builders.NewCNAME(q.Name, record.Aliased, record.TTL)
				answers = []dns.RR{alias}
			} else if (record.Type == dns.TypeA || record.Type == dns.TypeAAAA) && q.Qtype != dns.TypeCNAME {
				if app.Config.Settings.DebugLevel > 0 {
					log.Printf("Query for %s\n", q.Name)
				}
				if app.Config.Settings.LoadBalance {
					app.Resolver.RWMutex.RLock()
					resolver, ok := (*app.Resolver.entries)[record.Type][lowerName]
					app.Resolver.RWMutex.RUnlock()
					if !ok {
						app.Resolver.RWMutex.Lock()
						(*app.Resolver.entries)[record.Type][lowerName] = ResolverEntry{
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
					resolver = (*app.Resolver.entries)[record.Type][lowerName]
					nextNextIP, ip := getNextIP(nextIP, recordIPs)
					*nextIP = nextNextIP
					(*app.Resolver.entries)[record.Type][lowerName] = resolver
					app.Resolver.RWMutex.Unlock()

					rr, err := builders.NewRR(q.Qtype, q.Name, record.Host, ip, record.TTL)
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
						rr, err := builders.NewRR(q.Qtype, q.Name, record.Host, ip, record.TTL)
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
		soa = builders.NewSOA(record.Origin, record.Auth.Ns, record.Auth.Email, record.Auth.Serial)
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
			rr, _ := builders.NewRR(dns.TypeA, q.Name, q.Name, shadowIP, 3600) // TODO Fix TTL and type
			m.Answer = append(m.Answer, rr)
			continue
		}
	}
}

func (app *App) authoritativeUpdate(ctx context.Context, m *dns.Msg, n dns.RR, extra []dns.RR) {
	// TXT only for now!
	// I could assume that the question section will always contain the SOA name.
	// I have a strong feeling that this would be a mistake. Therefore I am going in a different direction.
	if n.Header().Rrtype == dns.TypeTXT {
		entry, _ := n.(*dns.TXT)
		if len(entry.Txt) != 1 {
			log.Println("I do not know, yet, how to handle records of a size other than 1.")
			return
		}
		recordName := entry.Header().Name
		recordTxt := entry.Txt[0]
		ttl := entry.Header().Ttl

		if app.Config.Settings.DebugLevel > 0 {
			log.Printf("Zone TXT Update %s (%d) -> %s\n", recordName, ttl, recordTxt)
		}

		if ctx.Value("privileged") == nil {
			log.Println("TXT update: Not privileged.")
			return
		}

		(*app.Records)[dns.TypeTXT][recordName] = config.Record{
			Type:   dns.TypeTXT,
			Text:   recordName,
			Target: recordTxt,
			TTL:    ttl,
		}
	}
	/*
		lowerName := strings.ToLower(q.Name)

		switch q.Qtype {

		case dns.TypeSOA:
			if app.Config.Settings.DebugLevel > 0 {
				log.Printf("Zone SOA Update %s\n", q.Name)
			}
			for _, zone := range app.Config.Zone {
				if zone.Origin == lowerName {
					log.Println("I WILL UPDATE, YES")
					spew.Dump(m)
					break
				}
			}
		default:
			if app.Config.Settings.DebugLevel > 0 {
				log.Println(fmt.Sprintf("Not supported: request type=%d", q.Qtype))
			}
		}
	*/
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

func unquote(str string) string {
	if len(str) > 0 && str[0] == '\'' {
		str = str[1:]
	}
	if len(str) > 0 && str[len(str)-1] == '\'' {
		str = str[:len(str)-1]
	}
	return str
}
