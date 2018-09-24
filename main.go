package main

import "flag"

func main() {

	targetHost := flag.String("targetHost", "localhost", "The target host to check")
	flag.Parse()

	openPorts := portScan(targetHost)

	for _, port := range openPorts {
		println(port)
	}
}
