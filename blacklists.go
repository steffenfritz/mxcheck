package main

import (
	"strings"

	. "github.com/logrusorgru/aurora"
	"github.com/miekg/dns"
)

// List of DNSBL services
var dnsbllistip = []string{"ix.dnsbl.manitu.net", "b.barracudacentral.org", "truncate.gbudb.net"}
var dnsbllistname = []string{"dbl.spamhaus.org"}

// checkdnsblIP checks if an IP address is listed in a DNS blacklist
// We use an A record request as DNSBL answer to any type of request
func checkdnsblIP(ipaddr string, dnsServer string) {
	// debug
	println("test dnsbl by ip")
	// Reverse the ip address
	ipslice := strings.Split(ipaddr, ".")
	rddapi := ipslice[3] + "." + ipslice[2] + "." + ipslice[1] + "." + ipslice[0]

	for _, dnsbl := range dnsbllistip {
		resp, err := getA(rddapi+"."+dnsbl, dnsServer)

		if err != nil {
			println(resp)
		} else {
			println(err.Error())
		}
	}
}

// checkdnsblName checks if a domain name is listed in a DNS blacklist
func checkdnsblName(domainname string, dnsServer string) {
	for _, dnsbl := range dnsbllistname {
		requestname := domainname + "." + dnsbl + "."

		m := new(dns.Msg)
		m.SetQuestion(requestname, dns.TypeA)

		c := new(dns.Client)

		in, _, err := c.Exchange(m, dnsServer+":53")
		if err != nil {
			println(err.Error())
		}

		if len(in.Answer) == 0 {
			InfoLogger.Println(Green("+ Not listed in " + dnsbl))
		} else {
			InfoLogger.Println(Red("- Listed in " + dnsbl))
		}
	}
}
