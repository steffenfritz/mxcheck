// mxcheck is a security scanner for mail servers
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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
	dmarcresult        dmarc
	tlsrptresult       tlsrpt
	bimiresult         bimi
}

// mxresult is used to store a mx scan result for further processing
type mxresult struct {
	mxentry          string
	ipaddr           string
	asnum            int
	ascountry        string
	asname           string
	asbgpprefix      string
	asregistry       string
	asallocated      string
	ptrentry         string
	ptrmatch         bool
	serverstring     string
	spfset           bool
	stsset           bool
	openports        []string
	fakesender       bool
	fakercpt         bool
	starttls         bool
	starttlsversion  string
	tlscertvalid     bool
	tlsversion       string
	tlscertexpiry    time.Time
	tlscertsubjectcn string
	tlscertissuercn  string
	tlscertsans      []string
	smtps            bool
	openrelay        bool
	vrfysupport      bool
	smugglevuln      bool
	smuggleresp      string
	smuggleerror     string
}

func main() {
	blacklist := flag.BoolP("blacklist", "b", false, "Check if the service is on blacklists")
	dkimSelector := flag.StringP("dkim-selector", "S", "",
		"The DKIM selector. If set a DKIM check is performed on the provided service domain")
	dnsServer := flag.StringP("dnsserver", "d", "8.8.8.8", "The dns server to be requested")
	disablePortScan := flag.BoolP("disable-port-scan", "p", false, "Disable SMTP port scan")
	mailFrom := flag.StringP("mailfrom", "f", "info@foo.wtf", "Set the mailFrom address")
	smtpsmuggle := flag.BoolP("smuggle", "g", false, "Test for SMTPSmuggling vulnerability")
	mailTo := flag.StringP("mailto", "t", "info@baz.wtf", "Set the mailTo address")
	noprompt := flag.BoolP("no-prompt", "n", false, "Answer yes to all questions")
	targetHostName := flag.StringP("service", "s", "",
		"The service host to check")
	updatecheck := flag.BoolP("updatecheck", "u", false, "Check for new version of mxcheck")
	verboseFlag := flag.BoolP("verbose", "V", false, "Show timestamps in output")
	version := flag.BoolP("version", "v", false, "Version and license")
	writetsv := flag.BoolP("write-tsv", "w", false, "Write tsv formated report to file")

	flag.Parse()

	verbose = *verboseFlag

	if *version {
		fmt.Println(versionmsg)
		return
	}

	if *updatecheck {
		err := getLatestVersion()
		if err != nil {
			printError("Error getting latest version: " + err.Error())
		}
		return
	}

	if len(*targetHostName) == 0 {
		printError("The service flag is mandatory.")
		return
	}

	runresult := runresult{}
	runresult.testdate = time.Now().Format(time.RFC3339)
	runresult.dnsserver = *dnsServer
	runresult.mailfrom = *mailFrom
	runresult.mailto = *mailTo
	runresult.targetdomainname = *targetHostName

	printHeader(*targetHostName, runresult.testdate)

	targetHosts, mxstatus, err := getMX(targetHostName, *dnsServer)
	if err != nil {
		printErrorFatal(err.Error())
	}

	printSection("MX Records")
	if mxstatus {
		for _, mxentry := range targetHosts {
			printInfoRaw(mxentry)
		}
	} else {
		printWarn("No MX entry found. Using Target Host Name.")
	}

	if !*noprompt {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\nContinue [y/n]: ")
		response, err := reader.ReadString('\n')
		if err != nil {
			printErrorFatal(err.Error())
		}
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" {
			printInfoRaw("User terminated. Bye.")
			return
		}
	}

	if len(*dkimSelector) > 0 {
		printSection("DKIM")
		runresult.dkimresult, err = getDKIM(*dkimSelector, *targetHostName, *dnsServer)
		if err != nil {
			printError(err.Error())
		} else {
			if runresult.dkimresult.dkimset {
				printOK("DKIM set")
				printInfo("Domain", runresult.dkimresult.domain)
				printInfo("Version", runresult.dkimresult.version)
				printInfo("Key Type", runresult.dkimresult.keyType)
				if len(runresult.dkimresult.accepAlgo) > 0 {
					printInfo("Accepted Algorithms", runresult.dkimresult.accepAlgo)
				} else {
					printWarn("Accepted Algorithms not set")
				}
				if len(runresult.dkimresult.noteField) > 0 {
					printInfo("Note", runresult.dkimresult.noteField)
				}
			} else {
				printWarn("DKIM not set or wrong selector")
			}
		}
	}

	// DMARC lookup
	printSection("DMARC")
	dmarcentry, err := getDMARC(*targetHostName, *dnsServer)
	if err != nil {
		printErrorFatal(err.Error())
	}
	if dmarcentry.dmarcset {
		runresult.dmarcset = true
		runresult.dmarcfull = dmarcentry.dmarcfull
		runresult.dmarcresult = dmarcentry
		printOK("DMARC set")
		printInfo("Policy", dmarcentry.p)
		if len(dmarcentry.sp) > 0 {
			printInfo("Subdomain Policy", dmarcentry.sp)
		}
		if len(dmarcentry.adkim) > 0 {
			printInfo("DKIM Alignment", dmarcentry.adkim)
		}
		if len(dmarcentry.aspf) > 0 {
			printInfo("SPF Alignment", dmarcentry.aspf)
		}
		if len(dmarcentry.fo) > 0 {
			printInfo("Failure Options", dmarcentry.fo)
		}
		if len(dmarcentry.rua) > 0 {
			printInfo("RUA", dmarcentry.rua)
		}
		if len(dmarcentry.ruf) > 0 {
			printInfo("RUF", dmarcentry.ruf)
		}
		if len(dmarcentry.pct) > 0 {
			printInfo("Pct", dmarcentry.pct)
		}
	} else {
		// This is just yellow because DMARC has its friends and foes...
		printWarn("No DMARC set")
	}

	// TLSRPT lookup
	printSection("TLSRPT")
	tlsrptentry, err := getTLSRPT(*targetHostName, *dnsServer)
	if err != nil {
		printError(err.Error())
	}
	runresult.tlsrptresult = tlsrptentry
	if tlsrptentry.tlsrptset {
		printOK("TLSRPT set")
		printInfo("RUA", tlsrptentry.rua)
	} else {
		printWarn("No TLSRPT set")
	}

	// BIMI lookup
	printSection("BIMI")
	bimientry, err := getBIMI(*targetHostName, *dnsServer)
	if err != nil {
		printError(err.Error())
	}
	runresult.bimiresult = bimientry
	if bimientry.bimiset {
		printOK("BIMI set")
		printInfo("Logo URI", bimientry.l)
		if len(bimientry.a) > 0 {
			printInfo("Authority URI", bimientry.a)
		}
	} else {
		printWarn("No BIMI set")
	}

	// Check blacklists for domain name
	if *blacklist {
		runresult.bldnsnamelisted, runresult.bldnsnamenotlisted = checkdnsblName(*targetHostName, *dnsServer)
	}

	for _, targetHost := range targetHosts {
		// Create temp mxresult to store single mx result
		singlemx := mxresult{}
		singlemx.mxentry = targetHost

		printSection("MX Host: " + targetHost)
		ipaddr, err := getA(targetHost, *dnsServer)
		if err != nil {
			printErrorFatal(err.Error())
		}
		singlemx.ipaddr = ipaddr
		printInfo("IP Address", ipaddr)

		if *blacklist {
			runresult.bldnsiplisted, runresult.bldnsipnotlisted = checkdnsblIP(ipaddr, *dnsServer)
		}

		// ASN lookup
		asn, err := getASN(ipaddr)
		if err != nil {
			printError(err.Error())
		} else {
			singlemx.asnum = int(asn.ASNum)
			singlemx.ascountry = asn.Country
			singlemx.asname = asn.ASName
			singlemx.asbgpprefix = asn.BGPPrefix
			singlemx.asregistry = asn.Registry
			singlemx.asallocated = asn.Allocated
			printInfo("AS Number", strconv.Itoa(singlemx.asnum))
			printInfo("AS Name", singlemx.asname)
			printInfo("AS Country", singlemx.ascountry)
			printInfo("AS Registry", singlemx.asregistry)
			printInfo("AS Allocated", singlemx.asallocated)
			printInfo("BGP Prefix", singlemx.asbgpprefix)
		}

		// PTR lookup
		ptrentry, err := getPTR(ipaddr, *dnsServer)
		if err != nil {
			printErrorFatal(err.Error())
		}
		singlemx.ptrentry = ptrentry
		printInfo("PTR Entry", ptrentry)
		if ptrentry == targetHost {
			singlemx.ptrmatch = true
			printOK("PTR matches MX record")
		} else {
			printFail("PTR does not match MX record")
		}

		// SPF lookup
		printSection("SPF")
		spfentry, spfanswer, err := getSPF(*targetHostName, *dnsServer)
		if err != nil {
			printErrorFatal(err.Error())
		}
		if spfentry {
			singlemx.spfset = true
			printOK("SPF set")
			printInfoRaw(spfanswer)
		} else {
			printFail("No SPF set")
		}

		// MTA-STS lookup
		printSection("MTA-STS")
		mtastsset, err := getMTASTS(*targetHostName, *dnsServer)
		if err != nil {
			printErrorFatal(err.Error())
		}
		if mtastsset {
			singlemx.stsset = true
			printOK("MTA-STS subdomain set")
			mtaststxt, err := mtasts(*targetHostName)
			if err != nil {
				printError(err.Error())
			} else {
				runresult.ststext = mtaststxt
			}
		} else {
			printFail("MTA-STS not set")
		}

		if *blacklist {
			printSection("DNSBL")
			for k, v := range runresult.bldnsnamelisted {
				printFail(k + " lists " + v)
			}
			for k, v := range runresult.bldnsiplisted {
				printFail(k + " lists " + v)
			}
			for k, v := range runresult.bldnsnamenotlisted {
				printOK(k + " does not list " + v)
			}
			for k, v := range runresult.bldnsipnotlisted {
				printOK(k + " does not list " + v)
			}
		}

		if *smtpsmuggle {
			printSection("SMTP Smuggling")
			smuggleresult := TestSMTPSmuggling(targetHost+":25", *mailFrom, *mailTo, false)
			if smuggleresult.Accepted {
				singlemx.smugglevuln = smuggleresult.Accepted
				printFail(targetHost + " seems to be vulnerable to SMTP Smuggling")
			} else {
				printOK(targetHost + " seems not to be vulnerable to SMTP Smuggling")
			}
			singlemx.smuggleresp = strings.NewReplacer("\n", "", "\r", "").Replace(smuggleresult.Response)
			printInfo("Response", singlemx.smuggleresp)
			if smuggleresult.Error != nil {
				singlemx.smuggleerror = smuggleresult.Error.Error()
			}
		}

		if !*disablePortScan {
			printSection("Port Scan")
			openPorts := portScan(targetHost)
			printInfo("Open ports", strings.Join(openPorts, ", "))

			if len(openPorts) == 0 {
				printWarn("No open ports to connect to. Cannot check this host.")
				continue
			}
			singlemx.openports = openPorts

			var orresult openResult

			for _, port := range openPorts {
				if port == "25" {
					printSection("SMTP Port " + port)
					orresult, err = openRelay(*mailFrom, *mailTo, targetHost, port)
					if err != nil {
						printWarn(err.Error())
					}

					// Server string
					if len(orresult.serverstring) > 0 {
						printInfo("Server Banner", orresult.serverstring)
						singlemx.serverstring = strings.ReplaceAll(orresult.serverstring, "\r\n", "")
					}

					// Sender accepted
					singlemx.fakesender = orresult.senderboolresult
					if orresult.senderboolresult {
						printInfoRaw("Fake sender accepted")
					} else {
						printInfoRaw("Fake sender not accepted")
					}

					// Recipient accepted
					singlemx.fakercpt = orresult.rcptboolresult
					if orresult.rcptboolresult {
						printInfoRaw("Recipient accepted")
					} else {
						printInfoRaw("Recipient not accepted. Skipped further open relay tests.")
					}

					// Open Relay test
					if orresult.orboolresult {
						singlemx.openrelay = true
						printFail("Server is probably an open relay")
					} else {
						printOK("Server is not an open relay")
					}

					// STARTTLS test
					printSection("STARTTLS")
					singlemx.starttls = orresult.starttlsbool
					singlemx.starttlsversion = orresult.starttlsversion
					if orresult.starttlsbool {
						printOK("STARTTLS supported")
						if orresult.starttlsversion == "TLS 1.3" || orresult.starttlsversion == "TLS 1.2" {
							printOK("TLS Version: " + orresult.starttlsversion)
						} else if orresult.starttlsversion == "TLS 1.1" {
							printWarn("TLS Version: " + orresult.starttlsversion)
						} else {
							printInfo("TLS Version", orresult.starttlsversion)
						}
					} else {
						printWarn("STARTTLS not supported")
					}

					if orresult.starttlsbool && orresult.starttlsvalid {
						singlemx.tlscertvalid = true
						printOK("Certificate is valid")
					}
					if orresult.starttlsbool && !orresult.starttlsvalid {
						printFail("Certificate not valid")
					}

					// VRFY test
					printSection("VRFY")
					singlemx.vrfysupport = orresult.vrfybool
					if orresult.vrfybool {
						printFail("VRFY command supported")
					} else {
						printOK("VRFY command not supported")
					}
				}

				// TLS/SMTPS test
				if port == "465" {
					printSection("SMTPS Port " + port)
					certinfo, err := tlsCheck(targetHost, port)
					if err != nil {
						printError(err.Error())
					}
					orresult.tlsbool = certinfo.tlsok
					orresult.tlsvalid = certinfo.certvalid
					orresult.tlsversion = certinfo.version
					singlemx.tlsversion = certinfo.version
					singlemx.tlscertexpiry = certinfo.expiry
					singlemx.tlscertsubjectcn = certinfo.subjectCN
					singlemx.tlscertissuercn = certinfo.issuerCN
					singlemx.tlscertsans = certinfo.sans
					if orresult.tlsbool {
						printOK("SMTPS supported")
						if orresult.tlsvalid {
							printOK("TLS certificate valid")
						} else {
							printWarn("TLS certificate not valid")
						}
						if orresult.tlsversion == "TLS 1.3" || orresult.tlsversion == "TLS 1.2" {
							printOK("TLS Version: " + orresult.tlsversion)
						} else if orresult.tlsversion == "TLS 1.1" {
							printWarn("TLS Version: " + orresult.tlsversion)
						} else {
							printInfo("TLS Version", orresult.tlsversion)
						}
						if !certinfo.expiry.IsZero() {
							printInfo("Cert Expiry", certinfo.expiry.Format(time.RFC3339))
							printInfo("Cert Subject CN", certinfo.subjectCN)
							printInfo("Cert Issuer CN", certinfo.issuerCN)
							printInfo("Cert SANs", strings.Join(certinfo.sans, ", "))
						}
					} else {
						printWarn("SMTPS not supported")
					}
				}
			}
			runresult.mxresults = append(runresult.mxresults, singlemx)
		}
	}

	// Output to tsv file
	if *writetsv {
		printInfoRaw("Writing report to file")
		err := writeTSV(*targetHostName, runresult, *blacklist)
		if err != nil {
			printError(err.Error())
		}
	}
	fmt.Println()
	printOK("Test finished.")
}
