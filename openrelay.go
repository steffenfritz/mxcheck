package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
)

type openResult struct {
	orresult bool
	tlsbool  bool
	tlsvalid bool
}

// openRelay checks if a mail server sends email without
// authentication and with a fake sender address.
// It returns a struct:
func openRelay(mailFrom string, mailTo string, targetHost string) (error, openResult) {
	//var orresult string
	var or openResult

	c, err := smtp.Dial(targetHost + ":25")
	if err != nil {
		return err, or
	}

	// set default TLS config
	tlsconfig := &tls.Config{ServerName: targetHost}

	// a TLS check
	err = c.StartTLS(tlsconfig)
	if err == nil {
		or.tlsbool = true
		or.tlsvalid = true
	} else {
		// update config to ignore invalid TLS certificates and proceed
		tlsconfig = &tls.Config{InsecureSkipVerify: true}
		err = c.StartTLS(tlsconfig)
		if err == nil {
			or.tlsbool = true
			or.tlsvalid = false
		}
	}

	err = c.Mail(mailFrom)
	if err != nil {
		return err, or
	}

	// ToDo: if err == nil print in main
	log.Println("ii Fake sender accepted.")

	err = c.Rcpt(mailTo)
	if err != nil {
		return err, or
	}

	wc, err := c.Data()
	if err != nil {
		return err, or
	}

	_, err = fmt.Fprintf(wc, "From: <"+mailFrom+">\n\n"+"This server is an open relay")
	err = wc.Close()
	if err != nil {
		return err, or
	}
	err = c.Quit()
	if err != nil {
		return err, or
	}

	or.orresult = true

	return err, or
}
