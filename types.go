package main

import (
	"github.com/miekg/bitradix"
	"net"
	"sync"
)


type ASN uint32

type ASPath []ASN

type Prefixes map[string]ASN

type Neighbor struct {
	lock      sync.RWMutex
	State     string
	Ip	  string
	AsnPrefix map[ASN]Prefixes
	PrefixAsn Prefixes
	Updates   int
	trie      *bitradix.Radix32
}

type Route struct {
	Options    map[string]string
	Prefix     *net.IPNet
	ASPath     ASPath
	PrimaryASN ASN
}

type Neighbors map[string]*Neighbor

type ExaMsg struct {
        Exabgp   string
        Host     string
        Pid      string
        Ppid     string
        Time     float64
        Type     string
        Neighbor struct {
                Ip      string
                State    string
                Address struct {
                        Local string
                        Peer  string
                }
                Asn struct {
                        Local string
                        Peer  string
                }
                Message struct {
                        Update map[string]interface{}
                }
        }
}

type ExaAttrs struct {
        ASPath  ASPath
}

const (
	parseKey = iota
	parseValue
	parseList
	parseSkip
)

var DEBUG bool

func (n *Neighbor) PrefixCount() int {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return len(n.PrefixAsn)
}

func (n *Neighbor) AsnCount() int {
	n.lock.RLock()
	defer n.lock.RUnlock()
	return len(n.AsnPrefix)
}
