package main

import "github.com/miekg/dns"

func getMX(targetHostName *string) string {
	var mx string

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(*targetHostName), dns.TypeMX)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "192.168.1.20:53")
	e(err)

	if t, ok := in.Answer[0].(*dns.MX); ok {
		mx = t.Mx
	} else {
		mx = ""
	}

	return mx
}

func getA() {

}

func getPTR() {

}
