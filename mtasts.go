package main

import (
	"io"
	"net/http"
	"strings"
)

// mtastsuri is the fixed uri suffix defined in rfc8461
var mtastsuri = "/.well-known/mta-sts.txt"

// mtastsprefix is the fixed uri suffix defined in rfc8461
var mtastsprefix = "https://mta-sts."

// mtsststxt is a struct for the contents of a mta-sts.txt file
type mtaststxt struct {
	version string
	mode   string
	maxAge string
	mx     []string
}

//mtasts checks if mtasts is wanted and possible
func mtasts(targetHostname string) (mtaststxt, error) {
	var mtaststxt mtaststxt
	resp, err := http.Get(mtastsprefix + targetHostname + mtastsuri)
	if err != nil {
		return mtaststxt, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	mtastssplit := strings.Split(string(body), "\n")
	mtaststxt.version = mtastssplit[0]
	mtaststxt.mode = mtastssplit[1]
	mtaststxt.maxAge = mtastssplit[2]
	for _, mxentry := range mtastssplit[2:] {
		mtaststxt.mx = append(mtaststxt.mx, mxentry)
	}

	return mtaststxt, err
}
