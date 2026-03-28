package main

import (
	"encoding/csv"
	"io"
	"os"
	"slices"
	"strconv"
	"time"
)

// NewTSVWriter returns a new TSV writer used in writeTSV()
func NewTSVWriter(w io.Writer) (writer *csv.Writer) {
	writer = csv.NewWriter(w)
	writer.Comma = '\t'

	return
}

func writeTSV(targetHostName string, runresult runresult, blacklist bool) error {
	fd, err := os.Create(targetHostName + "-" + time.Now().Format(time.RFC3339) + ".tsv")
	if err != nil {
		return err
	}
	defer fd.Close()
	tsv := NewTSVWriter(fd)
	if err = tsv.Write([]string{"Test Date", runresult.testdate}); err != nil {
		return err
	}
	if err = tsv.Write([]string{"Target Domain Name", runresult.targetdomainname}); err != nil {
		return err
	}
	if err = tsv.Write([]string{"DNS Server", runresult.dnsserver}); err != nil {
		return err
	}
	if err = tsv.Write([]string{"MailFrom", runresult.mailfrom}); err != nil {
		return err
	}
	if err = tsv.Write([]string{"MailTo", runresult.mailto}); err != nil {
		return err
	}
	if !runresult.dkimresult.dkimset {
		if err = tsv.Write([]string{"DKIM Set", "false or not checked"}); err != nil {
			return err
		}
	} else {
		if err = tsv.Write([]string{"DKIM Set", "true"}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"DKIM DNS Entry", runresult.dkimresult.domain}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"DKIM DNS Version", runresult.dkimresult.version}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"DKIM Key Type", runresult.dkimresult.keyType}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"DKIM Accepted Algorithm", runresult.dkimresult.accepAlgo}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"DKIM Granularity", runresult.dkimresult.granularity}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"DKIM Note", runresult.dkimresult.noteField}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"DKIM Public Key", runresult.dkimresult.publicKey}); err != nil {
			return err
		}
	}

	if err = tsv.Write([]string{"DMARC Set", strconv.FormatBool(runresult.dmarcset)}); err != nil {
		return err
	}
	if runresult.dmarcset {
		if err = tsv.Write([]string{"DMARC Entry", runresult.dmarcfull}); err != nil {
			return err
		}
	}

	for i, mxentry := range runresult.mxresults {
		if err = tsv.Write([]string{"MX Entry Seq Number ", strconv.Itoa(i)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"MX Entry DNS", mxentry.mxentry}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"IP Address", mxentry.ipaddr}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"AS Number", strconv.Itoa(mxentry.asnum)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"AS Country", mxentry.ascountry}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"Server string", mxentry.serverstring}); err != nil {
			return err
		}
		portlist := ""
		for _, port := range mxentry.openports {
			portlist += port + " "
		}
		if err = tsv.Write([]string{"Open Ports", portlist}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"PTR Entry", mxentry.ptrentry}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"PTR Match", strconv.FormatBool(mxentry.ptrmatch)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"SPF Set", strconv.FormatBool(mxentry.spfset)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"MTA-STS Set", strconv.FormatBool(mxentry.stsset)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"STARTTLS PORT 25 Supported", strconv.FormatBool(mxentry.starttls)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"STARTTLS TLS Version", mxentry.starttlsversion}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"Certificate Valid", strconv.FormatBool(mxentry.tlscertvalid)}); err != nil {
			return err
		}
		if slices.Contains(mxentry.openports, "465") {
			if err = tsv.Write([]string{"TLS Version PORT 465 ", mxentry.tlsversion}); err != nil {
				return err
			}
		}
		if err = tsv.Write([]string{"VRFY Supported", strconv.FormatBool(mxentry.vrfysupport)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"SMTP Smuggling Vulnerability", strconv.FormatBool(mxentry.smugglevuln)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"SMTP Smuggling Response", mxentry.smuggleresp}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"Fake Sender Accepted", strconv.FormatBool(mxentry.fakesender)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"Fake Recipient Accepted", strconv.FormatBool(mxentry.fakercpt)}); err != nil {
			return err
		}
		if err = tsv.Write([]string{"Open Relay", strconv.FormatBool(mxentry.openrelay)}); err != nil {
			return err
		}
	}

	if blacklist {
		for bldns, blacklistresult := range runresult.bldnsnamelisted {
			if err = tsv.Write([]string{"Blacklist " + bldns + " lists ", blacklistresult}); err != nil {
				return err
			}
		}
		for bldns, blacklistresult := range runresult.bldnsnamenotlisted {
			if err = tsv.Write([]string{"Blacklist " + bldns + " does not list ", blacklistresult}); err != nil {
				return err
			}
		}
		for bldns, blacklistresult := range runresult.bldnsiplisted {
			if err = tsv.Write([]string{"Blacklist " + bldns + " lists ", blacklistresult}); err != nil {
				return err
			}
		}
		for bldns, blacklistresult := range runresult.bldnsipnotlisted {
			if err = tsv.Write([]string{"Blacklist " + bldns + " does not list ", blacklistresult}); err != nil {
				return err
			}
		}
	}

	tsv.Flush()

	return tsv.Error()
}
