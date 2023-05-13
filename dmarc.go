package main

type dmarc struct {
	dmarcset  bool
	adkim     string // strict or relaxed DKIM Identifier Alignment mode is required
	aspf      string // strict or relaxed SPF Identifier Alignment mode is required: aspf
	fo        string // Failure reporting options
	p         string // Requested Mail Receiver policy
	pct       string // Percentage of messages from the Domain Owner's mail stream to which the DMARC policy is applied
	rf        string // Format to be used for message-specific failure reports
	ri        string // Interval requested between aggregate reports
	rua       string // Addresses to which aggregate feedback is to be sent
	ruf       string // Addresses to which message-specific failure information is to be reported
	sp        string // Requested Mail Receiver policy for all subdomains
	v         string // Version
	dmarcfull string // full answer string used for output without parsing
}
