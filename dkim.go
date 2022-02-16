package main

type dkim struct {
	dkimset     bool
	domain      string // d=
	granularity string // g=
	accepAlgo   string // h=
	keyType     string // k=
	noteField   string // n=
	publicKey   string // p=
	selector    string // s=
	testing     string // t=
	version     string // v=
}
