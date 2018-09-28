package main

import (
	"net"
)

var portList = []string{"25", "465", "587"}

func portScan(targetHost string) []string {
	var openPorts []string
	for _, port := range portList {

		_, err := net.Dial("tcp", targetHost+":"+port)
		if err == nil {
			openPorts = append(openPorts, port)
		}
	}

	return openPorts
}
