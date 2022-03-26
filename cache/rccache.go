package cache

import (
	"time"

	"github.com/miekg/dns"
)

type RcCacheEntry struct {
	Type     uint16
	ExpireTS int64
	Targets  []dns.RR
}

type RcCache struct {
	Entries map[string]RcCacheEntry
	BackRef map[string]string
}

func (c *RcCache) Get(name string) ([]dns.RR, bool, uint32) {
	if entry, ok := c.Entries[name]; ok {
		remaining := uint32(entry.ExpireTS - time.Now().Unix())
		if remaining > 0 {
			return entry.Targets, true, remaining
		}
		delete(c.Entries, name)
	}
	return nil, false, 0
}

type MaybeFlatten int

const (
	Flatten MaybeFlatten = iota
	DoNotFlatten
)

func (c *RcCache) Set(flatten MaybeFlatten, name string, dnsType uint16, targets []dns.RR, ttl uint32) {
	if c.Entries == nil {
		c.Entries = make(map[string]RcCacheEntry)
	}
	if c.BackRef == nil {
		c.BackRef = make(map[string]string)
	}

	expireTs := time.Now().Unix() + int64(ttl)

	c.Entries[name] = RcCacheEntry{
		Type:     dnsType,
		ExpireTS: expireTs,
		Targets:  targets,
	}
	if flatten == Flatten {
		switch dnsType {
		case dns.TypeCNAME:
			if len(targets) > 0 {
				c.BackRef[targets[0].(*dns.CNAME).Target] = name
			}
		case dns.TypeA:
			for {
				backRefName, ok := c.BackRef[name]
				if !ok {
					break
				}
				backRefEntry := c.Entries[backRefName]
				c.Entries[backRefName] = RcCacheEntry{
					Type:     dns.TypeA,
					ExpireTS: backRefEntry.ExpireTS,
					Targets:  targets,
				}
				name = backRefName
			}
		}
	}
}

// TODO Create ageing function that will clean up both entries and backrefs
