package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
)

type openResult struct {
	orboolresult     bool
	orresult         string
	rcptresult       string
	rcptboolresult   bool
	senderresult     string
	senderboolresult bool
	tlsbool          bool
	tlsvalid         bool
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

	// Set from value
	err = c.Mail(mailFrom)
	if err != nil {
		or.senderresult = err.Error()
	} else {
		or.senderboolresult = true
	}

	if or.senderboolresult {
		log.Println("ii Fake sender accepted.")
	} else {
		log.Println("ww Fake sender not accepted.")
	}

	// Set recipient value
	err = c.Rcpt(mailTo)
	if err != nil {
		or.rcptresult = err.Error()
	} else {
		or.rcptboolresult = true
	}

	if or.rcptboolresult {
		log.Println("ii Recipient accepted.")
	} else {
		log.Println("ii Recipient not accepted. Skipping further open relay tests.")
		return nil, or
	}

	// Create WriteCloser
	wc, err := c.Data()
	if err != nil {
		return err, or
	}

	// Write test message, close and quit
	// If we can write the message to wc we
	// set the orboolresult to true
	_, err = fmt.Fprintf(wc, "From: <"+mailFrom+">\n\n"+"This server is an open relay")
	orerr := wc.Close()
	if orerr != nil {
		or.orresult = orerr.Error()
	} else {
		or.orboolresult = true
	}
	err = c.Quit()
	if err != nil {
		return err, or
	}

	return err, or
}
