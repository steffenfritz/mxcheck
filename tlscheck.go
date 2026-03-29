package main

import (
	"crypto/tls"
	"errors"
	"strings"
	"time"

	"net"
)

var tlsversions = map[uint16]string{
	tls.VersionSSL30: "SSL",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// tlscertinfo holds TLS connection and certificate details.
type tlscertinfo struct {
	version   string    // negotiated TLS version
	tlsok     bool      // TLS handshake succeeded
	certvalid bool      // certificate passed host validation
	expiry    time.Time // NotAfter from leaf certificate
	subjectCN string    // Subject Common Name of leaf certificate
	issuerCN  string    // Issuer Common Name of leaf certificate
	sans      []string  // Subject Alternative Names (DNS names)
}

func tlsCheck(targetHost string, port string) (tlscertinfo, error) {
	var info tlscertinfo

	conn, err := net.Dial("tcp", targetHost+":"+port)
	if err != nil {
		return info, errors.New("error connecting to TCP port")
	}
	defer conn.Close()

	// Check if TLS handshake succeeds
	tlsconfig := &tls.Config{ServerName: targetHost}
	tlsConn := tls.Client(conn, tlsconfig)
	if err := tlsConn.Handshake(); err != nil {
		printFail("TLS handshake failed")
		if strings.HasSuffix(err.Error(), "certificate name does not match input") {
			// Update TLS configuration
			info.tlsok = true
			tlsconfig = &tls.Config{InsecureSkipVerify: true}
		}
		tlsConn = tls.Client(conn, tlsconfig)
	} else {
		info.tlsok = true
		info.certvalid = true
	}

	// Check if TLS is available
	tlsstate := tlsConn.ConnectionState()
	info.version = tlsversions[tlsstate.Version]

	if len(tlsstate.PeerCertificates) > 0 {
		leaf := tlsstate.PeerCertificates[0]
		info.expiry = leaf.NotAfter
		info.subjectCN = leaf.Subject.CommonName
		info.issuerCN = leaf.Issuer.CommonName
		info.sans = leaf.DNSNames
	} else {
		info.version = "TLS is not available"
	}

	return info, nil
}
