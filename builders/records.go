package builders

import (
	"fmt"

	"github.com/miekg/dns"
)

func NewRR(recordType uint16, query string, host string, ip string, ttl uint32) (dns.RR, error) {
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

func NewCNAME(query string, target string, ttl uint32) dns.RR {
	alias := new(dns.CNAME)
	alias.Hdr = dns.RR_Header{
		Name:   query,
		Rrtype: dns.TypeCNAME,
		Class:  dns.ClassINET,
		Ttl:    ttl}
	alias.Target = target
	return alias
}

func NewSRV(query string, target string, port uint16, priority uint16, weight uint16, ttl uint32) dns.RR {
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

func NewTXT(query string, target string, ttl uint32) dns.RR {
	srv := new(dns.TXT)
	srv.Hdr = dns.RR_Header{
		Name:     query,
		Rrtype:   dns.TypeTXT,
		Class:    dns.ClassINET,
		Ttl:      ttl,
		Rdlength: 0}
	srv.Txt = []string{target}
	return srv
}

func NewMX(query string, host string, priority uint16, ttl uint32) dns.RR {
	mailer := new(dns.MX)
	mailer.Hdr = dns.RR_Header{
		Name:   query,
		Rrtype: dns.TypeMX,
		Class:  dns.ClassINET,
		Ttl:    ttl}
	mailer.Mx = host
	mailer.Preference = priority
	return mailer
}

func NewNS(query string, host string, ttl uint32) dns.RR {
	nameserver := new(dns.NS)
	nameserver.Hdr = dns.RR_Header{
		Name:   query,
		Rrtype: dns.TypeNS,
		Class:  dns.ClassINET,
		Ttl:    ttl}
	nameserver.Ns = host
	return nameserver
}

func NewSOA(origin string, ns string, mbox string, serial uint32) dns.RR {
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
