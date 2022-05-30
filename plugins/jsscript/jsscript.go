package main

import (
	"log"
	"os"

	"github.com/dop251/goja"
	"github.com/fusion/kittendns/builders"
	"github.com/fusion/kittendns/plugins"
	"github.com/miekg/dns"
)

type jsscriptHandler struct {
	vm     *goja.Runtime
	mainFn *goja.Callable
	script string
}

var (
	instance *jsscriptHandler
)

func main() {} // Keeping toolchain happy

func JsScriptPreHandler(arguments []string) plugins.PreHandler {
	instance = nil
	thisinit(arguments)
	return instance
}

func JsScriptPostHandler(arguments []string) plugins.PostHandler {
	thisinit(arguments)
	return instance
}

func thisinit(arguments []string) {
	if instance == nil {
		if len(arguments) != 1 {
			log.Fatal("Invalid number of arguments for jsscript plugin, should be 1: <script path>")
		}
		raw, err := os.ReadFile(arguments[0])
		if err != nil {
			log.Fatal("Unable to load script:", err)
		}
		vm := goja.New()
		instance = &jsscriptHandler{vm: vm}
		_, err = vm.RunString(string(raw))
		if err != nil {
			log.Fatal("Unable to understand script:", err)
		}
		mainFn, ok := goja.AssertFunction(vm.Get("main"))
		if !ok {
			log.Fatal("Unable to find main function in script:", err)
		}
		instance.mainFn = &mainFn
		vm.RunString("const pre=0;const post=1;")
		vm.RunString("const Noop=0;const Question=1;const Reply=2;const Rewrite=3;const Deny=4;")
		vm.RunString("const typeA=1;const typeNS=2;const typeCNAME=5;const typeSOA=6;const typePTR=12;const typeMX=15;const typeTXT=16;const typeAAAA=28;const typeSRV=33;")
	}
}

func (h *jsscriptHandler) ProcessQuery(p plugins.PreOrPost, m *dns.Msg, q *dns.Question) (*plugins.Update, error) {
	var preOrPost uint16
	var existingAnswers goja.Value
	if p == plugins.Pre {
		preOrPost = 0
		existingAnswers = nil
	} else {
		preOrPost = 1
		existingAnswers = h.vm.ToValue(m.Answer)
	}

	raw, err := (*h.mainFn)(
		goja.Undefined(),
		h.vm.ToValue(preOrPost),
		existingAnswers,
		h.vm.ToValue(q.Qtype),
		h.vm.ToValue(q.Name))
	if err != nil {
		log.Println("Error running script:", err)
	}
	res, ok := raw.Export().(map[string]interface{})
	if !ok {
		return nil, nil
	}
	action, ok := res["action"].(int64)
	if !ok { // Noop
		return nil, nil
	}
	replyDone := false
	if done, ok := res["done"]; ok {
		replyDone = done.(bool)
	}
	replyStop := false
	if stop, ok := res["stop"]; ok {
		replyStop = stop.(bool)
	}

	if action == int64(plugins.Question) {
		newQuestion := q
		newQuestion.Name = res["question"].(map[string]interface{})["name"].(string)
		newQuestion.Qtype = (uint16)(res["question"].(map[string]interface{})["type"].(int64))
		return nil, nil
	}
	if action == int64(plugins.Reply) {
		replyType := uint16(res["type"].(int64))
		replyTTL := uint32(res["TTL"].(int64))
		replyRRs := res["RR"].([]interface{})
		answers := []dns.RR{}
		for _, rr := range replyRRs {
			answers = buildReply(answers, q.Name, replyType, replyTTL, rr.(map[string]interface{}))
		}
		return &plugins.Update{
				Action: plugins.Reply,
				Done:   replyDone,
				Stop:   replyStop,
				RR:     answers},
			nil
	}
	if action == int64(plugins.Rewrite) {
		replyType := uint16(res["type"].(int64))
		replyTTL := uint32(res["TTL"].(int64))
		replyRRs := res["RR"].([]interface{})
		answers := []dns.RR{}
		for _, rr := range replyRRs {
			answers = buildReply(answers, q.Name, replyType, replyTTL, rr.(map[string]interface{}))
		}
		return &plugins.Update{
				Action: plugins.Rewrite,
				Done:   replyDone,
				Stop:   replyStop,
				RR:     answers},
			nil
	}
	return nil, nil
}

func buildReply(answers []dns.RR, name string, replyType uint16, replyTTL uint32, mrr map[string]interface{}) []dns.RR {
	switch replyType {
	case dns.TypeSOA:
		log.Println("jsscript plugin: SOA unsupported.")
	case dns.TypeSRV:
		if check(&mrr, []string{"target", "port", "priority", "weight"}) {
			answers = append(answers,
				builders.NewSRV(name,
					mrr["target"].(string),
					uint16(mrr["port"].(uint64)),
					uint16(mrr["priority"].(uint64)),
					uint16(mrr["weight"].(uint64)),
					replyTTL))
		}
	case dns.TypeTXT:
		if check(&mrr, []string{"target"}) {
			answers = append(answers,
				builders.NewTXT(name,
					mrr["target"].(string),
					replyTTL))
		}
	case dns.TypeMX:
		if check(&mrr, []string{"host", "priority"}) {
			answers = append(answers,
				builders.NewMX(name,
					mrr["host"].(string),
					uint16(mrr["priority"].(uint64)),
					replyTTL))
		}
	case dns.TypeA, dns.TypeAAAA:
		if check(&mrr, []string{"host", "ip"}) {
			newRR, _ := builders.NewRR(replyType, name,
				mrr["host"].(string),
				mrr["ip"].(string),
				replyTTL)
			answers = append(answers, newRR)
		}
	case dns.TypeCNAME:
		if check(&mrr, []string{"aliased"}) {
			answers = append(answers,
				builders.NewCNAME(name,
					mrr["aliased"].(string),
					replyTTL))
		}
	}
	return answers
}

func check(m *map[string]interface{}, req []string) bool {
	for _, key := range req {
		if _, ok := (*m)[key]; !ok {
			log.Println("Missing key to build record:", key)
			return false
		}
	}
	return true
}
