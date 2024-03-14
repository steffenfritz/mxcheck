package main

import (
	"crypto/tls"
	"fmt"
	"net"
)

func tlsCheck(targetHost string, port string) {
	conn, err := net.Dial("tcp", targetHost+":"+port)
	if err != nil {
		fmt.Println("Error connecting to TCP port:", err)
		return
	}
	defer conn.Close()

	// Check if TLS handshake succeeds
	tlsconfig := &tls.Config{ServerName: targetHost}
	tlsConn := tls.Client(conn, tlsconfig)
	if err := tlsConn.Handshake(); err != nil {
		fmt.Println("TLS handshake failed:", err)
		// Update TLS configuration
		tlsconfig = &tls.Config{InsecureSkipVerify: true}

	}

	// Check if TLS is available
	tlsstate := tlsConn.ConnectionState()

	tlsversions := map[uint16]string{
		tls.VersionSSL30: "SSL",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	if len(tlsstate.PeerCertificates) > 0 {
		println(tlsversions[tlsstate.Version])
	} else {
		fmt.Println("TLS is not available")
	}
}
