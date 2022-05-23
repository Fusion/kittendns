package main

import (
	"log"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestStartOfAuthority(t *testing.T) {
	result := runit("example.com", "SOA")
	if !lookup(result, `(?s)ANSWER SECTION:+example.com. 14400 IN SOA	dns1.example.com. dev.zteo.com. 1 86400 7200 100800 7200`) {
		inform(t, `a complete SOA record for example.com`, result)
	}
}

func TestMailXchange(t *testing.T) {
	result := runit("example.com", "MX")
	if !lookup(result, `(?s)ANSWER SECTION:+example.com. 20 IN MX 0 one.example.com.+example.com. 20 IN MX 0 two.example.com.`) {
		inform(t, `two mailers for example.com`, result)
	}
}

// RFC7505
func TestNullMailXchange(t *testing.T) {
	result := runit("example.org", "MX")
	if !lookup(result, `(?s)ANSWER SECTION:+example.org. 20 IN MX 0 .`) {
		inform(t, `null mailer for example.org`, result)
	}
}

func TestCanonicalNameRecordAsIPv4(t *testing.T) {
	result := runit("www.example.com", "A")
	if !lookup(result, `(?s)ANSWER SECTION:+www.example.com. 20 IN CNAME example.com.+example.com. 20 IN A 1.2.3.4`) {
		inform(t, `two steps CNAME resolution for example.com`, result)
	}
}

func TestCanonicalNameRecordExplicitly(t *testing.T) {
	result := runit("www.example.com", "CNAME")
	if !lookup(result, `(?s)ANSWER SECTION:+www.example.com. 20 IN CNAME example.com.`) {
		inform(t, `single steps explicit CNAME resolution for example.com`, result)
	}
}

func TestCanonicalNameRecordImplicitly(t *testing.T) {
	result := runit("www.example.com")
	if !lookup(result, `(?s)ANSWER SECTION:+www.example.com. 20 IN CNAME example.com.+example.com. 20 IN A 1.2.3.4`) {
		inform(t, `two steps implicit CNAME resolution for example.com`, result)
	}
}

func TestService(t *testing.T) {
	result := runit("_sip._tcp.example.com", "SRV")
	if !lookup(result, `(?s)ANSWER SECTION:+_sip._tcp.example.com. 20 IN SRV 10 5 0 test.example.com.`) {
		inform(t, `a service record for SIP over TCP at example.com`, result)
	}
}

func TestMultiA(t *testing.T) {
	result := runit("test.example.com", "A")
	if !lookup(result, `(?s)ANSWER SECTION:+test.example.com. 20 IN A 192.168.1.2+test.example.com. 20 IN A 192.168.2.2+test.example.com. 20 IN A 192.168.3.2`) {
		inform(t, `three A records for test.example.com`, result)
	}
}

func TestAuthoritative(t *testing.T) {
	result := runit("test.example.com", "A")
	if !lookup(result, `(?s)AUTHORITY SECTION:+example.com. 14400	IN SOA dns1.example.com. dev.zteo.com. 1 86400 7200 100800 7200`) {
		inform(t, `authoritative assertion for test.example.com`, result)
	}
}

func runit(args ...string) string {
	stdout, err := exec.Command("dig", append([]string{"@localhost"}, args...)...).Output()
	if err != nil {
		log.Fatal(err)
	}
	return string(stdout)
}

func lookup(source string, str string) bool {
	r := regexp.MustCompile(ex(str))
	return r.FindString(source) != ""
}

func ex(raw string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(raw,
				".", "\\."),
			"+", ".+?"),
		" ", "\\s+?")
}

func inform(t *testing.T, expected string, msg string) {
	t.Errorf("Expected %s, got (full output) %s", expected, msg)
}
