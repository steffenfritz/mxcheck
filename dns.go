package main

import (
	"strings"

	"github.com/miekg/dns"
)

func getMX(targetHostName *string) (string, bool) {
	var mx string
	var mxstatus bool

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(*targetHostName), dns.TypeMX)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	e(err)

	if len(in.Answer) == 0 {
		mx = *targetHostName
	} else {
		if t, ok := in.Answer[0].(*dns.MX); ok {
			mx = t.Mx
			mxstatus = true
		}
	}
	return mx, mxstatus

}

func getA(targetHostName string) string {
	var a string

	m := new(dns.Msg)
	m.SetQuestion(targetHostName, dns.TypeA)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	e(err)

	if t, ok := in.Answer[0].(*dns.A); ok {
		a = t.A.String()
	}

	return a
}

func getPTR(ipaddr string) string {
	var ptr string

	ipslice := strings.Split(ipaddr, ".")
	rddapi := ipslice[3] + "." + ipslice[2] + "." + ipslice[1] + "." + ipslice[0]

	rddapi = rddapi + ".in-addr.arpa"

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(rddapi), dns.TypePTR)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	e(err)

	if len(in.Answer) == 0 {
		ptr = "No PTR set"
	} else {
		if t, ok := in.Answer[0].(*dns.PTR); ok {
			ptr = t.Ptr
		}
	}
	return ptr
}

func getSPF(targetHostName string) string {
	var spf string

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(targetHostName), dns.TypeSPF)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	e(err)

	if len(in.Answer) == 0 {
		spf = "-- No SPF entry set"
	} else {
		if t, ok := in.Answer[0].(*dns.SPF); ok {
			spf = "++ " + t.Txt[0]
		}
	}

	return spf
}
