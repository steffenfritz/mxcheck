package main

import (
	"net"
	"time"
)

var portList = []string{"25", "465", "587"}

// portScan scans a list of tcp ports defined in portList
// It returns a list of open ports
func portScan(targetHost string) []string {
	var openPorts []string
	for _, port := range portList {

		_, err := net.DialTimeout("tcp", targetHost+":"+port, 10*time.Second)
		if err == nil {
			openPorts = append(openPorts, port)
		}
	}

	return openPorts
}
