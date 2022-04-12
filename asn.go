package main

import (
	"github.com/jamesog/iptoasn"
)

// getASN does a bgp lookup for an ip and returns the asn
func getASN(ip string) (iptoasn.IP, error) {
	as, err := iptoasn.LookupIP(ip)

	return as, err
}
