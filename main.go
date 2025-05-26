// mxcheck is a security scanner for mail servers
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	. "github.com/logrusorgru/aurora"
	flag "github.com/spf13/pflag"
)

// runresult is used to store the metadata of a single run
type runresult struct {
	testdate           string
	targetdomainname   string
	ststext            mtaststxt
	dnsserver          string
	mailfrom           string
	mailto             string
	mxresults          []mxresult
	dkimresult         dkim
	bldnsnamelisted    map[string]string
	bldnsnamenotlisted map[string]string
	bldnsiplisted      map[string]string
	bldnsipnotlisted   map[string]string
	dmarcset           bool
	dmarcfull          string
}

// mxresult is used to store a mx scan result for further processing
type mxresult struct {
	mxentry         string
	ipaddr          string
	asnum           int
	ascountry       string
	ptrentry        string
	ptrmatch        bool
	serverstring    string
	spfset          bool
	stsset          bool
	openports       []string
	fakesender      bool
	fakercpt        bool
	starttls        bool
	starttlsversion string
	tlscertvalid    bool
	tlsversion      string
	smtps           bool
	openrelay       bool
	vrfysupport     bool
}

var (
	WarningLogger *log.Logger
	InfoLogger    *log.Logger
	ErrorLogger   *log.Logger
)

func init() {
	InfoLogger = log.New(os.Stdout, "INFO:  ", log.Ldate|log.Ltime)
	WarningLogger = log.New(os.Stdout, "WARN:  ", log.Ldate|log.Ltime)
	ErrorLogger = log.New(os.Stdout, "ERROR: ", log.Ldate|log.Ltime)
}

func main() {

	println()

	blacklist := flag.BoolP("blacklist", "b", false, "Check if the service is on blacklists")
	dkimSelector := flag.StringP("dkim-selector", "S", "",
		"The DKIM selector. If set a DKIM check is performed on the provided service domain")
	dnsServer := flag.StringP("dnsserver", "d", "8.8.8.8", "The dns server to be requested")
	disablePortScan := flag.BoolP("disable-port-scan", "p", false, "Disable SMTP port scan")
	mailFrom := flag.StringP("mailfrom", "f", "info@foo.wtf", "Set the mailFrom address")
	mailTo := flag.StringP("mailto", "t", "info@baz.wtf", "Set the mailTo address")
	noprompt := flag.BoolP("no-prompt", "n", false, "Answer yes to all questions")
	targetHostName := flag.StringP("service", "s", "",
		"The service host to check")
	updatecheck := flag.BoolP("updatecheck", "u", false, "Check for new version of mxcheck")
	version := flag.BoolP("version", "v", false, "Version and license")
	writetsv := flag.BoolP("write-tsv", "w", false, "Write tsv formated report to file")

	flag.Parse()

	if *version {
		fmt.Println(versionmsg)
		return
	}

	if *updatecheck {
		err := getLatestVersion()
		if err != nil {
			ErrorLogger.Println("Error getting latest version:", err)
		}
		return
	}

	if len(*targetHostName) == 0 {
		ErrorLogger.Println("The service flag is mandatory.")
		return
	}

	runresult := runresult{}
	runresult.testdate = time.Now().Format(time.RFC3339)
	runresult.dnsserver = *dnsServer
	runresult.mailfrom = *mailFrom
	runresult.mailto = *mailTo

	runresult.targetdomainname = *targetHostName
	InfoLogger.Println("== Checking: " + *targetHostName + " ==")

	targetHosts, mxstatus, err := getMX(targetHostName, *dnsServer)
	if err != nil {
		ErrorLogger.Fatalln(err)
	}

	if mxstatus {
		InfoLogger.Println("Found MX: ")
		for _, mxentry := range targetHosts {
			InfoLogger.Println("         " + mxentry)
		}
	} else {
		WarningLogger.Println("No MX entry found. Using Target Host Name.")
	}

	if !*noprompt {
		reader := bufio.NewReader(os.Stdin)
		// Fixing the newline "feature" in log
		fmt.Printf("INFO:  %s Continue [y/n]: ", time.Now().Format("2006/01/02 15:04:05"))
		response, err := reader.ReadString('\n')
		if err != nil {
			ErrorLogger.Fatal(err)
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" {
			InfoLogger.Println("ii User terminated. Bye.")
			return
		}
	}

	if len(*dkimSelector) > 0 {
		InfoLogger.Println("== Checking DKIM record ==")
		runresult.dkimresult, err = getDKIM(*dkimSelector, *targetHostName, *dnsServer)
		if err != nil {
			ErrorLogger.Printf("%s", err.Error())
		} else {
			if runresult.dkimresult.dkimset {
				InfoLogger.Println("DKIM Domain " + runresult.dkimresult.domain)
				InfoLogger.Println("DKIM Version " + runresult.dkimresult.version)
				InfoLogger.Println("DKIM Key Type " + runresult.dkimresult.keyType)
				if len(runresult.dkimresult.accepAlgo) > 0 {
					InfoLogger.Println("DKIM Accepted Algorithms " + runresult.dkimresult.accepAlgo)
				} else {
					InfoLogger.Println("DKIM Accepted Algorithms not set")
				}
				if len(runresult.dkimresult.noteField) > 0 {
					InfoLogger.Println("DKIM  Note " + runresult.dkimresult.noteField)
				} else {
					InfoLogger.Println("DKIM No note set")
				}
			} else {
				InfoLogger.Println("DKIM not set or wrong selector")
			}
		}
	}

	// DMARC lookup
	InfoLogger.Println("== Checking DMARC record ==")
	dmarcentry, err := getDMARC(*targetHostName, *dnsServer)
	if err != nil {
		ErrorLogger.Fatalln(err.Error())
	}
	if dmarcentry.dmarcset {
		runresult.dmarcset = true
		// this copying makes little sense tbh right now. But if we parse the answer it will help.
		runresult.dmarcfull = dmarcentry.dmarcfull
		InfoLogger.Println(Green("DMARC set"))
		InfoLogger.Println(runresult.dmarcfull)
	} else {
		// This is just yellow because DMARC has its friends and foes...
		InfoLogger.Println(Yellow("No DMARC set"))
	}

	// Check blacklists for domain name
	// InfoLogger.Println("Checking if domain is blacklisted")
	if *blacklist {
		runresult.bldnsnamelisted, runresult.bldnsnamenotlisted = checkdnsblName(*targetHostName, *dnsServer)
	}

	for _, targetHost := range targetHosts {
		// Create temp mxresult to store single mx result
		singlemx := mxresult{}
		singlemx.mxentry = targetHost

		InfoLogger.Println("== Checking for A record ==")
		ipaddr, err := getA(targetHost, *dnsServer)
		if err != nil {
			ErrorLogger.Fatalln(err.Error())
		}
		singlemx.ipaddr = ipaddr
		InfoLogger.Println("IP address MX: " + ipaddr)

		if *blacklist {
			runresult.bldnsiplisted, runresult.bldnsipnotlisted = checkdnsblIP(ipaddr, *dnsServer)
		}

		// ASN lookup
		asn, err := getASN(ipaddr)
		if err != nil {
			ErrorLogger.Println(err.Error())
		} else {
			singlemx.asnum = int(asn.ASNum)
			singlemx.ascountry = asn.Country
			InfoLogger.Println("AS Number: " + strconv.Itoa(singlemx.asnum))
			InfoLogger.Println("AS Country: " + singlemx.ascountry)
		}

		// PTR lookup
		InfoLogger.Println("== Checking for PTR record ==")
		ptrentry, err := getPTR(ipaddr, *dnsServer)
		if err != nil {
			ErrorLogger.Fatalln(err.Error())
		}

		singlemx.ptrentry = ptrentry
		InfoLogger.Println("PTR entry: " + ptrentry)

		if ptrentry == targetHost {
			singlemx.ptrmatch = true
			InfoLogger.Println(Green("PTR matches MX record"))
		} else {
			InfoLogger.Println(Red("PTR does not match MX record"))
		}

		// SPF lookup
		InfoLogger.Println("== Checking for SPF record ==")
		spfentry, spfanswer, err := getSPF(*targetHostName, *dnsServer)
		if err != nil {
			ErrorLogger.Fatalln(err.Error())
		}
		if spfentry {
			singlemx.spfset = true
			InfoLogger.Println(Green("SPF set"))
			InfoLogger.Println(spfanswer)
		} else {
			InfoLogger.Println(Red("No SPF set"))
		}

		// MTA-STS lookup
		InfoLogger.Println("== Checking for MTA-STS ==")
		mtastsset, err := getMTASTS(*targetHostName, *dnsServer)
		if err != nil {
			ErrorLogger.Fatalln(err.Error())
		}
		if mtastsset {
			singlemx.stsset = true
			InfoLogger.Println(Green("MTA-STS subdomain set"))
			InfoLogger.Println("Checking MTA-STS settings")
			mtaststxt, err := mtasts(*targetHostName)
			if err != nil {
				ErrorLogger.Printf("%s", err.Error())
			} else {
				runresult.ststext = mtaststxt
			}

		} else {
			InfoLogger.Println(Red("MTA-STS not set"))
		}

		if *blacklist {
			InfoLogger.Println("== Result of DNS Blacklist checks ==")
			for k, v := range runresult.bldnsnamelisted {
				InfoLogger.Println(Red("- " + k + " lists " + v))
			}
			for k, v := range runresult.bldnsiplisted {
				InfoLogger.Println(Red("- " + k + " lists " + v))
			}
			for k, v := range runresult.bldnsnamenotlisted {
				InfoLogger.Println(Green("+ " + k + " does not list " + v))
			}
			for k, v := range runresult.bldnsipnotlisted {
				InfoLogger.Println(Green("+ " + k + " does not list " + v))
			}
		}

		if !*disablePortScan {
			// Checking for open e-mail ports
			InfoLogger.Println("== Checking for open e-mail ports ==")
			openPorts := portScan(targetHost)
			InfoLogger.Print("Open ports: ", openPorts)

			if len(openPorts) == 0 {
				InfoLogger.Println(Cyan("No open ports to connect to. I cannot check this host."))
				continue
			}
			singlemx.openports = openPorts

			var orresult openResult

			for _, port := range openPorts {
				if port == "25" {
					InfoLogger.Println("== Checking for open relay on port " + port + " ==")
					orresult, err = openRelay(*mailFrom, *mailTo, targetHost, port)
					if err != nil {
						WarningLogger.Println(err.Error())
					}

					// Server string
					if len(orresult.serverstring) > 0 {
						InfoLogger.Printf("Server Banner: %s", orresult.serverstring)
						singlemx.serverstring = strings.ReplaceAll(orresult.serverstring, "\r\n", "")
					}

					// Sender accepted
					singlemx.fakesender = orresult.senderboolresult
					if orresult.senderboolresult {
						InfoLogger.Println("Fake sender accepted.")
					} else {
						InfoLogger.Println("Fake sender not accepted.")
					}

					// Recipient accepted
					singlemx.fakercpt = orresult.rcptboolresult
					if orresult.rcptboolresult {
						InfoLogger.Println("Recipient accepted.")
					} else {
						InfoLogger.Println("Recipient not accepted. Skipped further open relay tests.")
					}

					// Open Relay test
					if orresult.orboolresult {
						singlemx.openrelay = true
						InfoLogger.Println(Red("Server is probably an open relay"))
					} else {
						InfoLogger.Println(Green("Server is not an open relay"))
					}

					// STARTTLS test
					InfoLogger.Println("== Checking for STARTTLS on port 25 ==")

					singlemx.starttls = orresult.starttlsbool
					singlemx.starttlsversion = orresult.starttlsversion
					if orresult.starttlsbool {
						InfoLogger.Println(Green("STARTTLS supported"))
						if orresult.starttlsversion == "TLS 1.3" || orresult.starttlsversion == "TLS 1.2" {
							InfoLogger.Println(Green("STARTTLS - TLS Version: " + orresult.starttlsversion))
						} else if orresult.starttlsversion == "TLS 1.1" {
							InfoLogger.Println(Yellow("STARTTLS - TLS Version: " + orresult.starttlsversion))
						} else {
							InfoLogger.Println("STARTTLS - TLS Version: " + orresult.starttlsversion)
						}
					} else {
						InfoLogger.Println(Cyan("STARTTLS not supported"))
					}

					if orresult.starttlsbool && orresult.starttlsvalid {
						singlemx.tlscertvalid = true
						InfoLogger.Println(Green("Certificate is valid"))
					}

					if orresult.starttlsbool && !orresult.starttlsvalid {
						InfoLogger.Println(Red("Certificate not valid"))
					}
					// VRFY test
					InfoLogger.Println("== Checking for VRFY support ==")
					singlemx.vrfysupport = orresult.vrfybool
					if orresult.vrfybool {
						InfoLogger.Println(Red("VRFY command supported."))
					} else {
						InfoLogger.Println(Green("VRFY command not supported."))
					}

				}
				// TLS test
				if port == "465" {
					InfoLogger.Println("== Checking for TLS support on port " + port + " ==")
					orresult.tlsversion, orresult.tlsbool, orresult.tlsvalid, err = tlsCheck(targetHost, port)
					if err != nil {
						InfoLogger.Println(err)
					}
					singlemx.tlsversion = orresult.tlsversion
					if orresult.tlsbool {
						InfoLogger.Println(Green("SMTPS supported"))
						if orresult.tlsvalid {
							InfoLogger.Println(Green("SMTPS TLS certificate valid"))
						} else {
							InfoLogger.Println(Yellow("SMTPS TLS certificate not valid"))
						}
						if orresult.tlsversion == "TLS 1.3" || orresult.tlsversion == "TLS 1.2" {
							InfoLogger.Println(Green("SMTPS TLS Version: " + orresult.tlsversion))
						} else if orresult.tlsversion == "TLS 1.1" {
							InfoLogger.Println(Yellow("SMTPS TLS Version: " + orresult.tlsversion))
						} else {
							InfoLogger.Println("SMTPS TLS Version: " + orresult.tlsversion)
						}
					} else {
						InfoLogger.Println(Cyan("SMTPS not supported"))
					}

					runresult.mxresults = append(runresult.mxresults, singlemx)
					println()
				}
			}
		}
	}

	// Output to tsv file
	if *writetsv {
		InfoLogger.Println("Writing report to file")
		err := writeTSV(*targetHostName, runresult, *blacklist)
		if err != nil {
			ErrorLogger.Printf("%s", err.Error())
		}

	}
	InfoLogger.Println("Test finished.")
}
