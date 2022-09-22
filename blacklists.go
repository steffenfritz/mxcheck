package main

import (
	"strings"

	"github.com/miekg/dns"
)

// List of DNSBL services
var dnsbllistip = []string{"ix.dnsbl.manitu.net.",
	"b.barracudacentral.org.",
	"truncate.gbudb.net.",
	"dnsbl.dronebl.org.",
	"rblspamassassin.interserver.net.",
	"ix.dnsbl.manitu.net.",
	"bl.spamcop.net.",
	"dnsbl-2.uceprotect.net.",
	"spam.dnsbl.sorbs.net.",
	"bl.mailspike.net."}

var dnsbllistname = []string{"dbl.spamhaus.org.",
	"bl.0spam.org."}

// checkdnsblIP checks if an IP address is listed in a DNS blacklist
// We use an A record request as DNSBL answer to any type of request
func checkdnsblIP(ipaddr string, dnsServer string) (map[string]string, map[string]string) {
	iplisted := make(map[string]string)
	ipnotlisted := make(map[string]string)

	// Reverse the ip address
	ipslice := strings.Split(ipaddr, ".")
	rddapi := ipslice[3] + "." + ipslice[2] + "." + ipslice[1] + "." + ipslice[0]

	for _, dnsbl := range dnsbllistip {
		requestip := rddapi + "." + dnsbl
		resp, err := getA(requestip, dnsServer)

		if err != nil && err.Error() != "no answer from DNS" {
			ErrorLogger.Println(err)
		}

		if len(resp) != 0 {
			iplisted[dnsbl] = ipaddr
		} else {
			ipnotlisted[dnsbl] = ipaddr
		}
	}
	return iplisted, ipnotlisted
}

// checkdnsblName checks if a domain name is listed in a DNS blacklist
func checkdnsblName(domainname string, dnsServer string) (map[string]string, map[string]string) {
	listed := make(map[string]string)
	notlisted := make(map[string]string)

	for _, dnsbl := range dnsbllistname {
		requestname := domainname + "." + dnsbl

		m := new(dns.Msg)
		m.SetQuestion(requestname, dns.TypeA)

		c := new(dns.Client)

		in, _, err := c.Exchange(m, dnsServer+":53")
		if err != nil {
			println(err.Error())
		}

		if len(in.Answer) == 0 {
			notlisted[dnsbl] = domainname
		} else {
			listed[dnsbl] = domainname
		}
	}

	return listed, notlisted
}
