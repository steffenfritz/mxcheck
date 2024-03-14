package main

import (
	"crypto/tls"
	"fmt"
	"net"
)

func tlsCheck(address string, port string) {
	conn, err := net.Dial("tcp", address+":"+port)
	if err != nil {
		fmt.Println("Error connecting to TCP port:", err)
		return
	}
	defer conn.Close()

	// Check if TLS handshake succeeds
	config := &tls.Config{InsecureSkipVerify: false} // Skip verifying the certificate
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	// Check if TLS is available
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		fmt.Println("TLS is available")
	} else {
		fmt.Println("TLS is not available")
	}
}
