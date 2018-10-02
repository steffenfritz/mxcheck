package main

import (
	"fmt"
	"log"
	"net/smtp"
)

func openRelay(targetHost string) {
	// set email addresses for open relay test
	mailFrom := "foo@bar.baz"
	mailTo := "bar@foo.baz"

	c, err := smtp.Dial(targetHost + ":25")
	e(err)
	err = c.Mail(mailFrom)
	if err != nil {
		log.Println("Server is not an open relay. Last message: ")
		log.Println(err)
		return
	}
	log.Println("Fake sender accepted.")

	err = c.Rcpt(mailTo)
	if err != nil {
		log.Println("Server is not an open relay. Last message: ")
		log.Println(err)
		return
	}

	wc, err := c.Data()
	e(err)
	fmt.Fprintf(wc, "This server is an open relay")
	err = wc.Close()
	e(err)
	err = c.Quit()
	e(err)
	log.Println("This server is probably an open relay")
}
