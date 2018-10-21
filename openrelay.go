package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
)

func openRelay(targetHost string) (string, string) {
	var tlsresult string
	var orresult string
	// set default TLS config
	tlsconfig := &tls.Config{InsecureSkipVerify: true}

	// set email addresses for open relay test
	mailFrom := "foo@bar.baz"
	mailTo := "bar@foo.baz"

	c, err := smtp.Dial(targetHost + ":25")
	e(err)

	// a TLS check
	err = c.StartTLS(tlsconfig)
	if err != nil {
		tlsresult = "-- StartTLS not supported"
	} else {
		tlsresult = "++ StartTLS supported"
	}

	err = c.Mail(mailFrom)
	if err != nil {
		orresult = "++ Server is not an open relay. Last message:"
		log.Println(err)
		return tlsresult, orresult
	}

	log.Println("ii Fake sender accepted.")

	err = c.Rcpt(mailTo)
	if err != nil {
		orresult = "++ Server is not an open relay. Last message: " + err.Error()
		return tlsresult, orresult
	}

	wc, err := c.Data()
	e(err)
	fmt.Fprintf(wc, "From: <"+mailFrom+">\n\n"+"This server is an open relay")
	err = wc.Close()
	e(err)
	err = c.Quit()
	e(err)
	orresult = "!! This server is probably an open relay"

	return tlsresult, orresult
}
