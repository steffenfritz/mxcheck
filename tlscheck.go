package main

import (
	"crypto/tls"
	"errors"
	. "github.com/logrusorgru/aurora"
	"net"
	"strings"
)

var tlsversions = map[uint16]string{
	tls.VersionSSL30: "SSL",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

func tlsCheck(targetHost string, port string) (string, bool, bool, error) {
	tlsbool := false
	tlsvalid := false

	conn, err := net.Dial("tcp", targetHost+":"+port)
	if err != nil {
		return "", tlsbool, tlsvalid, errors.New("error connecting to TCP port")
	}
	defer conn.Close()

	// Check if TLS handshake succeeds
	tlsconfig := &tls.Config{ServerName: targetHost}
	tlsConn := tls.Client(conn, tlsconfig)
	if err := tlsConn.Handshake(); err != nil {
		InfoLogger.Println(Red("TLS handshake failed"))
		if err == nil || strings.HasSuffix(err.Error(), "certificate name does not match input") {
			// Update TLS configuration
			tlsbool = true
			tlsconfig = &tls.Config{InsecureSkipVerify: true}
		}
		tlsConn = tls.Client(conn, tlsconfig)
	} else {
		tlsbool = true
		tlsvalid = true
	}

	// Check if TLS is available
	tlsstate := tlsConn.ConnectionState()

	if len(tlsstate.PeerCertificates) > 0 {
		return tlsversions[tlsstate.Version], tlsbool, tlsvalid, nil
	} else {
		return "TLS is not available", tlsbool, tlsvalid, nil
	}
}
