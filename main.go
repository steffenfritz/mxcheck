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

// runresult is used to store the metadata of a single run
type runresult struct {
	testdate         string
	targetdomainname string
	ststext          mtaststxt
	dnsserver        string
	mailfrom         string
	mailto           string
	mxresults        []mxresult
	dkimresult       dkim
}

// mxresult is used to store a mx scan result for further processing
type mxresult struct {
	mxentry      string
	ipaddr       string
	ptrentry     string
	ptrmatch     bool
	spfset       bool
	stsset       bool
	openports    []string
	fakesender   bool
	fakercpt     bool
	starttls     bool
	tlscertvalid bool
	openrelay    bool
}

func main() {

	println()

	dkimSelector := flag.StringP("dkim-selector", "S", "",
		"The DKIM selector. If set a dkim check is performed on the provided service domain.")
	dnsServer := flag.StringP("dnsserver", "d", "8.8.8.8", "The dns server to consult")
	mailFrom := flag.StringP("mailfrom", "f", "info@foo.wtf", "Set the mailFrom address")
	mailTo := flag.StringP("mailto", "t", "info@baz.wtf", "Set the mailTo address")
	noprompt := flag.BoolP("no-prompt", "n", false, "Answer yes to all questions")
	targetHostName := flag.StringP("service", "s", "",
		"The service host to check")
	verbose := flag.BoolP("version", "v", false, "Version and license")
	writetsv := flag.BoolP("write-tsv", "w", false, "Write tsv formated report to file")

	flag.Parse()

	if *verbose {
		println(versionmsg)
		return
	}

	if len(*targetHostName) == 0 {
		log.Println("ee The service flag is mandatory.")
		return
	}

	runresult := runresult{}
	runresult.testdate = time.Now().Format(time.RFC3339)
	runresult.dnsserver = *dnsServer
	runresult.mailfrom = *mailFrom
	runresult.mailto = *mailTo

	runresult.targetdomainname = *targetHostName
	log.Println("ii Checking: " + *targetHostName)

	targetHosts, mxstatus, err := getMX(targetHostName, *dnsServer)
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

	if len(*dkimSelector) > 0 {
		log.Println("ii Checking DKIM record")
		runresult.dkimresult, err = getDKIM(*dkimSelector, *targetHostName, *dnsServer)
		if err != nil {
			log.Printf("ee %s", err.Error())
		} else {
			if runresult.dkimresult.dkimset {
				log.Println("ii DKIM Domain " + runresult.dkimresult.domain)
				log.Println("ii DKIM Version " + runresult.dkimresult.version)
				log.Println("ii DKIM Key Type " + runresult.dkimresult.keyType)
				if len(runresult.dkimresult.accepAlgo) > 0 {
					log.Println("ii DKIM Accepted Algorithms " + runresult.dkimresult.accepAlgo)
				} else {
					log.Println("ii DKIM Accepted Algorithms not set")
				}
				if len(runresult.dkimresult.noteField) > 0 {
					log.Println("ii DKIM  Note " + runresult.dkimresult.noteField)
				} else {
					log.Println("ii DKIM No note set")
				}
			} else {
				log.Println("ii DKIM not set or wrong selector")
			}
		}
	}

	for _, targetHost := range targetHosts {
		// Create temp mxresult to store single mx result
		singlemx := mxresult{}
		singlemx.mxentry = targetHost

		log.Println("ii Checking for A record")
		ipaddr, err := getA(targetHost, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		singlemx.ipaddr = ipaddr
		log.Println("ii IP address MX: " + ipaddr)

		log.Println("ii Checking for PTR record")
		ptrentry, err := getPTR(ipaddr, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		singlemx.ptrentry = ptrentry
		log.Println("ii PTR entry: " + ptrentry)

		if ptrentry == targetHost {
			singlemx.ptrmatch = true
			log.Println(Green("++ PTR matches MX record"))
		} else {
			log.Println(Red("-- PTR does not match MX record"))
		}

		log.Println("ii Checking for SPF record")
		spfentry, spfanswer, err := getSPF(*targetHostName, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		if spfentry {
			singlemx.spfset = true
			log.Println(Green("++ SPF set"))
			if *verbose {
				log.Println("ii " + spfanswer)
			}
		} else {
			log.Println(Red("-- No SPF set"))
		}

		log.Println("ii Checking for MTA-STS")
		mtastsset, err := getMTASTS(*targetHostName, *dnsServer)
		if err != nil {
			log.Fatalln("ee " + err.Error())
		}
		if mtastsset {
			singlemx.stsset = true
			log.Println(Green("++ MTA-STS subdomain set"))
			log.Println("ii Checking MTA-STS settings")
			mtaststxt, err := mtasts(*targetHostName)
			if err != nil {
				log.Printf("ee %s", err.Error())
			} else {
				runresult.ststext = mtaststxt
			}

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
		singlemx.openports = openPorts

		for _, port := range openPorts {
			if port == "25" {
				log.Println("ii Checking for open relay")
				orresult, err := openRelay(*mailFrom, *mailTo, targetHost)
				if err != nil {
					log.Println("ww " + err.Error())
				}

				if orresult.tlsbool {
					singlemx.starttls = true
					log.Println(Green("++ StartTLS supported"))
				} else {
					log.Println("-- StartTLS not supported")
				}

				if orresult.tlsbool && orresult.tlsvalid {
					singlemx.tlscertvalid = true
					log.Println(Green("++ Certificate is valid"))
				}

				if orresult.tlsbool && !orresult.tlsvalid {
					log.Println("-- Certificate not valid")
				}

				if orresult.orboolresult {
					singlemx.openrelay = true
					log.Println(Red("!! Server is probably an open relay"))
				} else {
					log.Println(Green("++ Server is not an open relay"))
				}
				runresult.mxresults = append(runresult.mxresults, singlemx)
				println()
			}
		}
	}
	if *writetsv {
		err := writeTSV(*targetHostName, runresult)
		if err != nil {
			log.Printf("ee %s", err.Error())
		}

	}
}
