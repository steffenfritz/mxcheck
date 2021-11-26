package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
)

// openRelay checks if a mail server sends email without
// authentication and with a fake sender address.
// It returns two booleans: if starttls is used an the result
func openRelay(mailFrom string, mailTo string, targetHost string) (bool, bool, bool) {
	//var orresult string
	var orresult bool
	var tlsbool bool
	var tlsvalid bool

	c, err := smtp.Dial(targetHost + ":25")
	e(err)

	// set default TLS config
	tlsconfig := &tls.Config{ServerName: targetHost}

	// a TLS check
	err = c.StartTLS(tlsconfig)
	if err == nil {
		tlsbool = true
		tlsvalid = true
	} else {
		// update config to ignore invalid TLS certificates and proceed
		tlsconfig = &tls.Config{InsecureSkipVerify: true}
		err = c.StartTLS(tlsconfig)
		if err == nil {
			tlsbool = true
			tlsvalid = false
		}
	}

	err = c.Mail(mailFrom)
	if err != nil {
		//orresult = "++ Server is not an open relay. Last message:"
		//log.Println(err)
		return tlsbool, tlsvalid, orresult
	}

	log.Println("ii Fake sender accepted.")

	err = c.Rcpt(mailTo)
	if err != nil {
		//orresult = "++ Server is not an open relay. Last message: " + err.Error()
		return tlsbool, tlsvalid, orresult
	}

	wc, err := c.Data()
	e(err)
	_, err = fmt.Fprintf(wc, "From: <"+mailFrom+">\n\n"+"This server is an open relay")
	err = wc.Close()
	e(err)
	err = c.Quit()
	e(err)
	orresult = true

	return tlsbool, tlsvalid, orresult
}
