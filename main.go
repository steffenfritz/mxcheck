package main

import (
	"flag"
	"log"
)

func main() {

	targetHostName := flag.String("targetHost", "localhost", "The target host to check")
	flag.Parse()
	log.Println("Checking: " + *targetHostName)

	targetHost := getMX(targetHostName)
	log.Println("Found MX: " + targetHost)

	openPorts := portScan(targetHost)
	log.Print("Open ports: ", openPorts)

	log.Println("Checking for open relay")
	openRelay(targetHost)
}
