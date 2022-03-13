package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/davecgh/go-spew/spew"
	"github.com/fusion/kittendns/config"
	"github.com/hydronica/toml"
	"github.com/miekg/dns"
)

type App struct {
	Config  *config.Config
	Records *map[string]config.Record
}

func main() {

	app := App{}

	app.Config = getConfig()
	app.Records = flattenRecords(app.Config)

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

func getConfig() *config.Config {
	var config config.Config
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Fatal(err)
	}
	return &config
}

func flattenRecords(cfg *config.Config) *map[string]config.Record {
	records := map[string]config.Record{}
	for _, zone := range cfg.Zone {
		for _, record := range zone.Record {
			if record.TTL == 0 {
				record.TTL = zone.TTL
			}
			if strings.HasSuffix(record.Host, ".") {
				records[record.Host] = record
				continue
			}
			records[fmt.Sprintf("%s.%s", record.Host, zone.Origin)] = record
		}
	}
  spew.Dump(records)
	return &records
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
		switch q.Qtype {
		case dns.TypeA:
			var answer dns.RR
			log.Printf("Query for %s\n", q.Name)
			record, ok := (*app.Records)[q.Name]
			if ok {
				rr, err := newRR(q.Name, record.Host, record.IPv4, record.TTL)
				if err == nil {
					answer = rr
				}
			}

			remoteip := ""
			remoteAddr := ctx.Value("remoteaddr")
			if remoteAddr != nil {
				remoteip = strings.Split(remoteAddr.(string), ":")[0]
			}

			action := app.parseRules(remoteip, q.Name, answer)
			if action == "" {
				if answer != nil {
                                    if app.Config.Settings.DebugLevel > 2 {
                                        log.Println("Providing answer")
                                    }
					m.Answer = append(m.Answer, answer)
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
				rr, _ := newRR(q.Name, q.Name, shadowIP, 3600) // TODO Fix TTL
				m.Answer = append(m.Answer, rr)
				return
			}
		}
	}
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
		log.Println("Matched rule", rule.Condition, "->", rule.Action)
		return rule.Action
	}
        log.Println("No rule applies")
	return ""
}

func newRR(query string, host string, ipv4 string, ttl uint32) (dns.RR, error) {
	rr, err := dns.NewRR(
		fmt.Sprintf(
			"%s %d A %s",
			query,
			ttl,
			ipv4))
	return rr, err
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
