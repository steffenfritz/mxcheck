package main

import (
	"flag"
	"log"
)

func main() {

	targetHostName := flag.String("targetHost", "localhost", "The target host to check")
	flag.Parse()
	log.Println("Checking: " + *targetHostName)

	targetHost, mxstatus := getMX(targetHostName)
	if mxstatus {
		log.Println("Found MX: " + targetHost)
	} else {
		log.Println("No MX entry found. Using Target Host Name.")
	}

	log.Println("Checking for A record")
	ipaddr := getA(targetHost)
	log.Println("IP address MX: " + ipaddr)

	log.Println("Checking for PTR record")
	ptrentry := getPTR(ipaddr)
	log.Println("PTR entry: " + ptrentry)

	if ptrentry == targetHost {
		log.Println("PTR matches MX record")
	} else {
		log.Println("PTR does not match MX record")
	}

	log.Println("Checking for open mail ports")
	openPorts := portScan(targetHost)
	log.Print("Open ports: ", openPorts)

	if len(openPorts) == 0 {
		log.Println("No open ports to connect to. Quitting.")
		return
	}

	for _, port := range openPorts {
		if port == "25" {
			log.Println("Checking for open relay")
			openRelay(targetHost)
		}
	}

}
