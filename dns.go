package main

import "github.com/miekg/dns"

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

	m := new(dns.Msg)
	m.SetQuestion(ipaddr, dns.TypePTR)

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
