package main

import "net/http"

// mtastsuri is the fixed uri suffix defined in rfc8461
var mtastsuri = "/.well-known/mta-sts.txt"

// mtastsprefix is the fixed uri suffix defined in rfc8461
var mtastsprefix = "_mta-sts."

// mtsststxt is a struct for the contents of a mta-sts.txt file
type mtaststxt struct {
	version string
	mode    string
	max_age string
	mx      string
}

//mtasts checks if mtasts is wanted and possible
func mtasts(targetHostname string) (mtaststxt, error) {
	var mtaststxt mtaststxt
	resp, err := http.Get(mtastsprefix + targetHostname + mtastsuri)
	if err != nil {
		return mtaststxt, err
	}

	// NEXT
	println(resp)

	return mtaststxt, err
}
