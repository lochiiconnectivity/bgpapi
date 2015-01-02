package main

import (
	"bufio"
	"encoding/json"
	"github.com/miekg/bitradix"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)


var neighbors Neighbors
var neighbors_lock sync.RWMutex

func bgpReader() {

	neighbors = make(Neighbors)

	r := bufio.NewReader(os.Stdin)

	var err error
	for line, err := r.ReadString('\n'); err == nil; line, err = r.ReadString('\n') {
		line = strings.TrimSpace(line)

		if line == "shutdown" {
			log.Println("Shutdown command received")
			return
		}

		if len(line) > 0 {
			processLine(line)
		}

	}

	if err != nil && err != io.EOF {
		log.Println(err)
		return
	} else {
		log.Println("EOF")
	}
}

func getNeighbor (neighborIp string) *Neighbor {

	neighbors_lock.RLock()
	defer neighbors_lock.RUnlock()

	if neighbors[neighborIp] == nil {
		neighbors_lock.RUnlock()
		neighbors_lock.Lock()

		neighbor := new(Neighbor)
		neighbor.Ip = neighborIp
		neighbor.trie = bitradix.New32()

		neighbors[neighborIp] = neighbor

		neighbors_lock.Unlock()
		neighbors_lock.RLock()
		defer neighbors_lock.RUnlock() // double?
	}

	neighbor := neighbors[neighborIp]

	neighbor.lock.Lock()
	defer neighbor.lock.Unlock()

	return neighbor
}

// Processes a line (JSON blob) from ExaBGP
func processLine(line string) {

	var exaMsg ExaMsg
        exaAttrs := ExaAttrs{ASPath: make(ASPath, 0)}

	if err := json.Unmarshal([]byte(line), &exaMsg); err == nil {

		neighbor := getNeighbor(exaMsg.Neighbor.Ip)

		if exaMsg.Type == "state"  {
			neighbor.State = exaMsg.Neighbor.State
			log.Printf("Neighbor %s State change to %s\n", exaMsg.Neighbor.Ip, exaMsg.Neighbor.State)
		} else if exaMsg.Type == "update" {

			// Extract Important stuff(tm) from update, if is some (e.g AS Path)
			if attribute, ok := exaMsg.Neighbor.Message.Update["attribute"]; ok {
			   extractUpdateAttrSection(&exaAttrs, attribute.(map[string]interface{}))
			}
			
			// Process announced prefixes, store them with their important stuff(tm)
			if announce, ok := exaMsg.Neighbor.Message.Update["announce"]; ok {
			   processUpdatePrefixSection(neighbor, &exaAttrs, "announce", announce.(map[string]interface{}))
			}
			
			// Process withdrawn prefixes
			if withdraw, ok := exaMsg.Neighbor.Message.Update["withdraw"]; ok {
			   processUpdatePrefixSection(neighbor, &exaAttrs, "withdraw", withdraw.(map[string]interface{}))
			}
		}
	}
}

// Extract attributes
func extractUpdateAttrSection(exaAttrs *ExaAttrs, attributeSectionData map[string]interface{}) {
	if asPathRaw, ok:= attributeSectionData["as-path"]; ok {
		asPathRawArray := asPathRaw.([]interface{})
		for key := range asPathRawArray  {
			if asn, ok := asPathRawArray[key].(float64); ok {
				exaAttrs.ASPath = append(exaAttrs.ASPath, ASN(asn))
			}
		}
	}
}

// Process an update
func processUpdatePrefixSection(neighbor *Neighbor, exaAttrs *ExaAttrs, updatePrefixSection string, updatePrefixSectionData map[string]interface{}) {
	if (updatePrefixSection == "announce") || (updatePrefixSection == "withdraw") {
		for afi := range updatePrefixSectionData {
		    processUpdatePrefixAFISection(neighbor, exaAttrs, updatePrefixSection, afi, updatePrefixSectionData[afi].(map[string]interface{}))
		}
	}
}

// Process an update for an AFI
func processUpdatePrefixAFISection (neighbor *Neighbor, exaAttrs *ExaAttrs, updatePrefixSection string, afi string, updatePrefixAFISectionData map[string]interface{}) {
	for nexthop := range updatePrefixAFISectionData {
		for prefix := range updatePrefixAFISectionData[nexthop].(map[string]interface{}) {

			neighbor.Updates++

			_, parsedPrefix, err := net.ParseCIDR(prefix)
			if err != nil {
				log.Printf("Could not parse prefix %s %e\n", prefix, err)
				panic("bad prefix")
			}

			route := new(Route)
			route.Prefix = parsedPrefix

			if (updatePrefixSection == "announce") { 
				if len(exaAttrs.ASPath) > 0 {
					route.PrimaryASN = ASN(exaAttrs.ASPath[len(exaAttrs.ASPath)-1])
					route.ASPath = exaAttrs.ASPath
				}
	
				if neighbor.AsnPrefix == nil {
					neighbor.AsnPrefix = make(map[ASN]Prefixes)
				}
	
				if neighbor.PrefixAsn == nil {
					neighbor.PrefixAsn = make(Prefixes)
				}
	
				if neighbor.AsnPrefix[route.PrimaryASN] == nil {
					neighbor.AsnPrefix[route.PrimaryASN] = make(Prefixes)
				}
	
				neighbor.AsnPrefix[route.PrimaryASN][route.Prefix.String()] = 0
				neighbor.PrefixAsn[route.Prefix.String()] = route.PrimaryASN

				addRoute(neighbor.trie, route.Prefix, route)

			} else if (updatePrefixSection == "withdraw") {

				removeRoute(neighbor.trie, route.Prefix)
			
				if asn, exists := neighbor.PrefixAsn[route.Prefix.String()]; exists {
					delete(neighbor.PrefixAsn, route.Prefix.String())
					delete(neighbor.AsnPrefix[asn], route.Prefix.String())
				} else {
					log.Println("Could not find prefix in PrefixAsn")
					log.Println("%#v", neighbor.PrefixAsn)
				}
			}

			if neighbor.Updates%25000 == 0 {
				log.Printf("Processed %v updates from %s\n", neighbor.Updates, neighbor.Ip)
			}
		}
  	}
}
