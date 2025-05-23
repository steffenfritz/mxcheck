package main

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
)

// getMX builds an MX record dns request and sends it to a dns server
// It returns a mx entry list, if at least one mx record was found and an error
func getMX(targetHostName *string, dnsServer string) ([]string, bool, error) {
	// var mx string
	var mxstatus bool
	var mxlist []string

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(*targetHostName), dns.TypeMX)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return mxlist, mxstatus, err
	}

	if len(in.Answer) == 0 {
		mxlist = append(mxlist, *targetHostName)
	} else {

		for _, mxentry := range in.Answer {
			if t, ok := mxentry.(*dns.MX); ok {
				mxlist = append(mxlist, t.Mx)
			}
		}

		mxstatus = true
	}

	return mxlist, mxstatus, err

}

// getA builds an A record dns request and sends it to a dns server
// It returns a single ip address and an error
func getA(targetHostName string, dnsServer string) (string, error) {
	var a string

	m := new(dns.Msg)
	m.SetQuestion(targetHostName, dns.TypeA)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return a, err
	}

	if len(in.Answer) == 0 {
		return a, errors.New("no answer from DNS")
	}

	if t, ok := in.Answer[0].(*dns.A); ok {
		a = t.A.String()
		// We check for a second ip address when the first entry is also an mx entry.
		// We also have to update the targetHost because of the cwrt test in openrelay
	} else {
		if t, ok := in.Answer[1].(*dns.A); ok {
			a = t.A.String()
		}
	}

	return a, err
}

// getPTR builds a PTR dns request and sends it to a dns server
// It returns a single ptr entry and an error
func getPTR(ipaddr string, dnsServer string) (string, error) {
	var ptr string

	ipslice := strings.Split(ipaddr, ".")
	rddapi := ipslice[3] + "." + ipslice[2] + "." + ipslice[1] + "." + ipslice[0]

	rddapi = rddapi + ".in-addr.arpa"

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(rddapi), dns.TypePTR)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return ptr, err
	}

	if len(in.Answer) == 0 {
		ptr = "No PTR set"
	} else {
		if t, ok := in.Answer[0].(*dns.PTR); ok {
			ptr = t.Ptr
		}
	}

	return ptr, err
}

// getSPF builds a spf dns request and sends it to a dns server
// It returns a bool if a spf is set, the value of it and an error
func getSPF(targetHostName string, dnsServer string) (bool, string, error) {
	var spf bool
	var spfanswer string

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(targetHostName), dns.TypeTXT)

	c := new(dns.Client)
	c.Net = "tcp"
	in, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return spf, spfanswer, err
	}

	if len(in.Answer) != 0 {
		for n := range in.Answer {
			if t, ok := in.Answer[n].(*dns.TXT); ok {
				for _, v := range t.Txt {
					if strings.HasPrefix(v, "v=spf1") {
						spf = true
						spfanswer = in.Answer[n].String()
					}
				}
			}
		}
	}

	return spf, spfanswer, err
}

// getMTASTS builds a TXT request and sends it to a dns server
// It returns a bool if an mta-sts entry is set and an error
func getMTASTS(targetHostName string, dnsServer string) (bool, error) {
	// This prefix is the fixed subdomain for mta-sts
	mtastsprefix := "_mta-sts."
	var mtasts bool

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(mtastsprefix+targetHostName), dns.TypeTXT)

	c := new(dns.Client)
	c.Net = "tcp"
	in, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return mtasts, err
	}

	if len(in.Answer) != 0 {
		for n := range in.Answer {
			if t, ok := in.Answer[n].(*dns.TXT); ok {
				for _, v := range t.Txt {
					if strings.HasPrefix(v, "v=STSv1") {
						mtasts = true
					}
				}
			}
		}
	}

	return mtasts, err
}

// getDKIM builds a TXT request and sends it to a dns server
// It returns type dkim if an mta-sts entry is set and an error
func getDKIM(selector string, targetHostName string, dnsServer string) (dkim, error) {
	// This infix is a fixed domain part for dkim
	dkiminfix := "_domainkey."
	var dkim dkim
	dkim.domain = selector + "." + dkiminfix + targetHostName

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(dkim.domain), dns.TypeTXT)

	c := new(dns.Client)
	c.Net = "tcp"
	in, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return dkim, err
	}

	if len(in.Answer) != 0 {
		for n := range in.Answer {
			if t, ok := in.Answer[n].(*dns.TXT); ok {
				for _, v := range t.Txt {
					if strings.HasPrefix(v, "v=DKIM1") {
						dkimSplit := strings.Fields(v)
						dkim.dkimset = true
						dkim.selector = selector
						dkim.version = "1"
						for _, partDKIM := range dkimSplit {
							if strings.HasPrefix(partDKIM, "g=") {
								dkim.granularity = strings.TrimRight(strings.Split(partDKIM, "=")[1], ";")
								continue
							}
							if strings.HasPrefix(partDKIM, "h=") {
								dkim.accepAlgo = strings.TrimRight(strings.Split(partDKIM, "=")[1], ";")
								continue
							}
							if strings.HasPrefix(partDKIM, "k=") {
								dkim.keyType = strings.TrimRight(strings.Split(partDKIM, "=")[1], ";")
								continue
							}
							if strings.HasPrefix(partDKIM, "n=") {
								dkim.noteField = strings.TrimRight(strings.Split(partDKIM, "=")[1], ";")
								continue
							}
							if strings.HasPrefix(partDKIM, "p=") {
								dkim.publicKey = strings.TrimRight(strings.Split(partDKIM, "=")[1], ";")
								continue
							}
							if strings.HasPrefix(partDKIM, "t=") {
								dkim.testing = strings.TrimRight(strings.Split(partDKIM, "=")[1], ";")
								continue
							}
						}
					}
				}
			}
		}
	}

	return dkim, err
}

// getDMARC builds a TXT request and sends it to a dns server
// It returns type dmarc and an error
func getDMARC(targetHostName string, dnsServer string) (dmarc, error) {
	var dmarc dmarc
	dmarcdomain := "_dmarc." + targetHostName

	m := new(dns.Msg)
	// ToDo: Implement check if type is not TXT but CNAME
	m.SetQuestion(dns.Fqdn(dmarcdomain), dns.TypeTXT)

	c := new(dns.Client)
	c.Net = "tcp"
	in, _, err := c.Exchange(m, dnsServer+":53")
	if err != nil {
		return dmarc, err
	}

	if len(in.Answer) != 0 {
		for n := range in.Answer {
			if t, ok := in.Answer[n].(*dns.TXT); ok {
				for _, v := range t.Txt {
					if strings.Contains(v, "v=DMARC1") {
						dmarc.dmarcset = true
						dmarc.dmarcfull = in.Answer[n].String()
					}
				}
			}
		}
	}

	return dmarc, nil
}
