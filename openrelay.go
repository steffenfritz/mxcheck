package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"time"
)

type openResult struct {
	orboolresult     bool
	orresult         string
	rcptresult       string
	rcptboolresult   bool
	senderresult     string
	senderboolresult bool
	serverstring     string
	tlsbool          bool
	tlsvalid         bool
}

// openRelay checks if a mail server sends email without
// authentication and with a fake sender address.
// It returns a struct:
func openRelay(mailFrom string, mailTo string, targetHost string) (openResult, error) {
	//var orresult string
	var or openResult

	c, err := smtp.Dial(targetHost + ":25")
	if err != nil {
		return or, err
	}

	// Print server string. You can trust the server string, but you shouldn't...
	conn, err := net.DialTimeout("tcp", targetHost+":25", 15*time.Second)
	defer conn.Close()

	if err != nil {
		or.serverstring = "Could not read banner: " + err.Error()
	} else {
		buf := bufio.NewReader(conn)
		bannerbytes, err := buf.ReadBytes('\n')
		if err != nil {
			log.Fatalf("ee Fatal error: %s", err.Error())
		}
		or.serverstring = string(bannerbytes)
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

	// Set recipient value
	err = c.Rcpt(mailTo)
	if err != nil {
		or.rcptresult = err.Error()
	} else {
		or.rcptboolresult = true
	}

	if !or.rcptboolresult {
		return or, nil
	}

	// Create WriteCloser
	wc, err := c.Data()
	if err != nil {
		return or, err
	}
	defer wc.Close()

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

	return or, err
}
