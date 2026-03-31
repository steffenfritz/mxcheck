package main

// dane holds a parsed TLSA record for a single MX host (RFC 6698, RFC 7672).
type dane struct {
	daneset      bool
	mxhost       string
	usage        uint8  // 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE
	usageName    string
	selector     uint8  // 0=Cert, 1=SPKI
	selectorName string
	matchingType uint8  // 0=Full, 1=SHA2-256, 2=SHA2-512
	matchingName string
	certificate  string // hex-encoded certificate association data
}
