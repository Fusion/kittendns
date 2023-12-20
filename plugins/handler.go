package plugins

import (
	"github.com/miekg/dns"
)

type Action uint64

const (
	Noop Action = iota
	Question
	Reply
	Rewrite
	Deny
)

type PreOrPost uint64

const (
	Pre PreOrPost = iota
	Post
)

type PreHandler interface {
	ProcessQuery(p PreOrPost, ip string, m *dns.Msg, q *dns.Question) (*Update, error)
}

type PreParam struct {
	RemoteIp  string
	QueryType string
	Question  string
}

type PostHandler interface {
	ProcessQuery(p PreOrPost, ip string, m *dns.Msg, q *dns.Question) (*Update, error)
}

type PostParam struct {
	RemoteIp  string
	QueryType string
	Question  string
}

type Update struct {
	Action   Action
	Stop     bool // Stop processing plugins
	Done     bool // Stop processing question
	Question *dns.Question
	RR       []dns.RR
}
