package main

import (
	"flag"
	"log"
)

func main() {

	println()
	println(versionmsg)

	targetHostName := flag.String("t", "localhost", "The target host to check")
	flag.Parse()
	log.Println("ii Checking: " + *targetHostName)

	targetHost, mxstatus := getMX(targetHostName)
	if mxstatus {
		log.Println("ii Found MX: " + targetHost)
	} else {
		log.Println("-- No MX entry found. Using Target Host Name.")
	}

	log.Println("ii Checking for A record")
	ipaddr := getA(targetHost)
	log.Println("ii IP address MX: " + ipaddr)

	log.Println("ii Checking for PTR record")
	ptrentry := getPTR(ipaddr)
	log.Println("ii PTR entry: " + ptrentry)

	if ptrentry == targetHost {
		log.Println("++ PTR matches MX record")
	} else {
		log.Println("-- PTR does not match MX record")
	}

	log.Println("ii Checking for SPF record")
	spfentry := getSPF(*targetHostName)
	log.Println(spfentry)

	log.Println("ii Checking for open mail ports")
	openPorts := portScan(targetHost)
	log.Print("ii Open ports: ", openPorts)

	if len(openPorts) == 0 {
		log.Println("ii No open ports to connect to. Quitting.")
		return
	}

	for _, port := range openPorts {
		if port == "25" {
			log.Println("ii Checking for open relay")
			tlsresult, orresult := openRelay(targetHost)

			log.Println(tlsresult)
			log.Println(orresult)
			println()
		}
	}

}
