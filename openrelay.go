package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
)

func openRelay(targetHost string) (bool, bool) {
	//var orresult string
	var orresult bool
	var tlsbool bool
	// set default TLS config
	tlsconfig := &tls.Config{InsecureSkipVerify: true}

	// set email addresses for open relay test
	mailFrom := "foo@bar.baz"
	mailTo := "bar@foo.baz"

	c, err := smtp.Dial(targetHost + ":25")
	e(err)

	// a TLS check
	err = c.StartTLS(tlsconfig)
	if err == nil {
		tlsbool = true
	}

	err = c.Mail(mailFrom)
	if err != nil {
		//orresult = "++ Server is not an open relay. Last message:"
		//log.Println(err)
		return tlsbool, orresult
	}

	log.Println("ii Fake sender accepted.")

	err = c.Rcpt(mailTo)
	if err != nil {
		//orresult = "++ Server is not an open relay. Last message: " + err.Error()
		return tlsbool, orresult
	}

	wc, err := c.Data()
	e(err)
	_, err = fmt.Fprintf(wc, "From: <"+mailFrom+">\n\n"+"This server is an open relay")
	err = wc.Close()
	e(err)
	err = c.Quit()
	e(err)
	//orresult = "!! This server is probably an open relay"
	orresult = true

	return tlsbool, orresult
}
