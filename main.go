// mxcheck is a security scanner for mail servers
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	. "github.com/logrusorgru/aurora"
	flag "github.com/spf13/pflag"
)

func main() {

	println()

	dnsServer := flag.StringP("dnsserver", "d", "8.8.8.8", "The dns server to consult")
	mailFrom := flag.StringP("mailfrom", "f", "info@foo.wtf", "Set the mailFrom address")
	mailTo := flag.StringP("mailto", "t", "info@baz.wtf", "Set the mailTo address")
	noprompt := flag.BoolP("no-prompt", "n", false, "answer yes to all questions")
	targetHostName := flag.StringP("service", "s", "",
		"The service host to check")
	verbose := flag.BoolP("version", "v", false, "version and license")

	flag.Parse()

	if *verbose {
		println(versionmsg)
	}

	if len(*targetHostName) == 0 {
		log.Println("ee The service flag is mandatory.")
		return
	}

	log.Println("ii Checking: " + *targetHostName)

	err, targetHosts, mxstatus := getMX(targetHostName, *dnsServer)
	if err != nil {
		log.Fatalln(err)
	}
	if mxstatus {
		log.Println("ii Found MX: ")
		for _, mxentry := range targetHosts {
			log.Println("ii           " + mxentry)
		}
	} else {
		log.Println("ww No MX entry found. Using Target Host Name.")
	}

	if !*noprompt {
		reader := bufio.NewReader(os.Stdin)
		logfixingdate := time.Now().Format("2006/01/02 15:04:05")
		fmt.Print(logfixingdate + " ii Continue [y/n]: ")
		response, err := reader.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" {
			log.Println("ii User terminated. Bye.")
			return
		}
	}

	for _, targetHost := range targetHosts {
		log.Println("ii Checking for A record")
		err, ipaddr := getA(targetHost, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		log.Println("ii IP address MX: " + ipaddr)

		log.Println("ii Checking for PTR record")
		err, ptrentry := getPTR(ipaddr, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		log.Println("ii PTR entry: " + ptrentry)

		if ptrentry == targetHost {
			log.Println(Green("++ PTR matches MX record"))
		} else {
			log.Println(Red("-- PTR does not match MX record"))
		}

		log.Println("ii Checking for SPF record")
		err, spfentry, spfanswer := getSPF(*targetHostName, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		if spfentry {
			log.Println(Green("++ SPF set"))
			if *verbose {
				log.Println("ii " + spfanswer)
			}
		} else {
			log.Println(Red("-- No SPF set"))
		}

		log.Println("ii Checking for MTA-STS")
		err, mtastsset := getMTASTS(*targetHostName, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		if mtastsset {
			log.Println(Green("++ MTA-STS subdomain set"))
			log.Println("ii Checking MTA-STS settings")
			mtasts(*targetHostName)
		} else {
			log.Println(Red("-- MTA-STS not set"))
		}

		log.Println("ii Checking for open mail ports")
		openPorts := portScan(targetHost)
		log.Print("ii Open ports: ", openPorts)

		if len(openPorts) == 0 {
			log.Println(Cyan("ii No open ports to connect to. Quitting."))
			return
		}

		for _, port := range openPorts {
			if port == "25" {
				log.Println("ii Checking for open relay")
				err, orresult := openRelay(*mailFrom, *mailTo, targetHost)
				if err != nil {
					log.Println("ww " + err.Error())
				}

				if orresult.tlsbool {
					log.Println(Green("++ StartTLS supported"))
				} else {
					log.Println("-- StartTLS not supported")
				}

				if orresult.tlsbool && orresult.tlsvalid {
					log.Println(Green("++ Certificate is valid"))
				}

				if orresult.tlsbool && !orresult.tlsvalid {
					log.Println("-- Certificate not valid")
				}

				if orresult.orboolresult {
					log.Println(Red("!! Server is probably an open relay"))
				} else {
					log.Println(Green("++ Server is not an open relay"))
				}
				println()
			}
		}
	}
}
