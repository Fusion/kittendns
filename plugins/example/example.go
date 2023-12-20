package main

import (
	"fmt"

	"github.com/fusion/kittendns/plugins"
	"github.com/miekg/dns"
)

/*
 * Here is what this example plugin does. Note that's is a very contrived set of rules.
 * First, if checks whether it is being invoked during the "pre" phase (i.e. before actually processing a query),
 * or, conversely, in the "post" phase (i.e. after processing a query and creating an answer).
 * If in the "pre" phase, and we are requesting a specific TXT record, it builds one and replies with it.
 * It also asks kittendns to not process the query any further ("Done"), but other plugins may decide otherwise.
 * If querying "plugintest" it simply rewrites the query to "test.example.com." so that this is what kittendns
 * will answer. Other "pre" plugins will not be run ("stop")
 * During the "post" phase, if we previously rewrote the query, we will add ("reply") an additional entry.
 * If we did not rewrite the query, and "test.example.com." was thus the original query, we will instead
 * override ("rewrite") the answer with a longer TTL.
 */

type exampleHandler struct {
	iRewroteSomething bool
}

var (
	instance *exampleHandler
)

func main() {} // Keeping toolchain happy

func ExamplePreHandler(arguments []string) plugins.PreHandler {
	if instance == nil {
		instance = &exampleHandler{}
	}
	return instance
}

func ExamplePostHandler(arguments []string) plugins.PostHandler {
	if instance == nil {
		instance = &exampleHandler{}
	}
	return instance
}

func (h *exampleHandler) ProcessQuery(p plugins.PreOrPost, ip string, m *dns.Msg, q *dns.Question) (*plugins.Update, error) {
	if p == plugins.Pre {
		h.iRewroteSomething = false
		if q.Qtype == dns.TypeTXT && q.Name == "magic.example.com." {
			srv := new(dns.TXT)
			srv.Hdr = dns.RR_Header{
				Name:     q.Name,
				Rrtype:   dns.TypeTXT,
				Class:    dns.ClassINET,
				Ttl:      60,
				Rdlength: 0}
			srv.Txt = []string{"this is a magic record"}
			return &plugins.Update{
					Action: plugins.Reply,
					Done:   true,
					RR:     []dns.RR{srv}},
				nil
		}
		if q.Qtype == dns.TypeA && q.Name == "plugintest.example.com." {
			h.iRewroteSomething = true
			newQuestion := q
			newQuestion.Name = "test.example.com."
			return &plugins.Update{
					Action:   plugins.Question,
					Stop:     true,
					Question: newQuestion},
				nil
		}
	} else {
		if h.iRewroteSomething {
			if q.Qtype == dns.TypeA && q.Name == "test.example.com." {
				rr, _ := dns.NewRR(
					fmt.Sprintf(
						"%s %d %s %s",
						q.Name,
						60,
						"A",
						"5.6.7.8"))
				return &plugins.Update{
						Action: plugins.Reply,
						RR:     []dns.RR{rr}},
					nil
			}
		} else {
			if q.Qtype == dns.TypeA && q.Name == "test.example.com." {
				newAnswers := []dns.RR{}
				for _, rr := range m.Answer {
					rr.Header().Ttl = 3600
					newAnswers = append(newAnswers, rr)
				}
				return &plugins.Update{
						Action: plugins.Rewrite,
						RR:     newAnswers},
					nil
			}
		}
	}
	return nil, nil
}
