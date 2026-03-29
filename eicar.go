package main

import (
	"fmt"
	"net/smtp"
)

type eicarResult struct {
	sent   bool
	result string
}

// eicarString assembles the EICAR test string at runtime to avoid static AV detection.
func eicarString() string {
	p1 := `X5O!P%@AP[4\PZX54(P^)7CC)7}`
	p2 := `$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	return p1 + p2
}

// sendEICAR sends the EICAR test file as an email attachment to the target mail server.
// A virus filter that detects it will reject the message; sent=true means it was accepted.
func sendEICAR(mailFrom string, mailTo string, targetHost string, targetPort string) (eicarResult, error) {
	var er eicarResult

	c, err := smtp.Dial(targetHost + ":" + targetPort)
	if err != nil {
		return er, err
	}
	defer c.Quit() //nolint:errcheck

	if err = c.Mail(mailFrom); err != nil {
		er.result = err.Error()
		return er, nil
	}

	if err = c.Rcpt(mailTo); err != nil {
		er.result = err.Error()
		return er, nil
	}

	wc, err := c.Data()
	if err != nil {
		return er, err
	}

	body := "MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"eicartest\"\r\n" +
		"Subject: EICAR AV Test\r\n" +
		"From: " + mailFrom + "\r\n" +
		"To: " + mailTo + "\r\n\r\n" +
		"--eicartest\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"eicar.com\"\r\n\r\n" +
		eicarString() + "\r\n" +
		"--eicartest--\r\n"

	if _, err = fmt.Fprint(wc, body); err != nil {
		er.result = err.Error()
		wc.Close() //nolint:errcheck
		return er, nil
	}

	if err = wc.Close(); err != nil {
		er.result = err.Error()
		return er, nil
	}

	er.sent = true
	return er, nil
}
