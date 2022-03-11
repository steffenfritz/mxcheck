package main

import (
	"encoding/csv"
	"io"
	"os"
	"strconv"
	"time"
)

// NewTSVWriter returns a new writer used to write the results to a TSV file
func NewTSVWriter(w io.Writer) (writer *csv.Writer) {
	writer = csv.NewWriter(w)
	writer.Comma = '\t'

	return
}

func writeTSV(targetHostName string, runresult runresult) error {
	fd, err := os.Create(targetHostName + "-" + time.Now().Format(time.RFC3339) + ".tsv")
	if err != nil {
		return err
	}
	tsv := NewTSVWriter(fd)
	err = tsv.Write([]string{"Test Date", runresult.testdate})
	err = tsv.Write([]string{"Target Domain Name", runresult.targetdomainname})
	err = tsv.Write([]string{"DNS Server", runresult.dnsserver})
	err = tsv.Write([]string{"MailFrom", runresult.mailfrom})
	err = tsv.Write([]string{"MailTo", runresult.mailto})
	if !runresult.dkimresult.dkimset {
		err = tsv.Write([]string{"DKIM Set", "false"})
	} else {
		err = tsv.Write([]string{"DKIM Set", "true"})
		err = tsv.Write([]string{"DKIM DNS Entry", runresult.dkimresult.domain})
		err = tsv.Write([]string{"DKIM DNS Version", runresult.dkimresult.version})
		err = tsv.Write([]string{"DKIM Key Type", runresult.dkimresult.keyType})
		err = tsv.Write([]string{"DKIM Accepted Algorithm", runresult.dkimresult.accepAlgo})
		err = tsv.Write([]string{"DKIM Granularity", runresult.dkimresult.granularity})
		err = tsv.Write([]string{"DKIM Note", runresult.dkimresult.noteField})
		err = tsv.Write([]string{"DKIM Public Key", runresult.dkimresult.publicKey})
	}

	for i, mxentry := range runresult.mxresults {
		err = tsv.Write([]string{"MX Entry Seq Number ", strconv.Itoa(i)})
		err = tsv.Write([]string{"MX Entry DNS", mxentry.mxentry})
		err = tsv.Write([]string{"IP Address", mxentry.ipaddr})
		err = tsv.Write([]string{"Server string", mxentry.serverstring})
		portlist := ""
		for _, port := range mxentry.openports {
			portlist += port + " "
		}
		err = tsv.Write([]string{"Open Ports", portlist})
		err = tsv.Write([]string{"PTR Entry", mxentry.ptrentry})
		err = tsv.Write([]string{"PTR Match", strconv.FormatBool(mxentry.ptrmatch)})
		err = tsv.Write([]string{"SPF Set", strconv.FormatBool(mxentry.spfset)})
		err = tsv.Write([]string{"MTA-STS Set", strconv.FormatBool(mxentry.stsset)})
		err = tsv.Write([]string{"STARTTLS Supported", strconv.FormatBool(mxentry.starttls)})
		err = tsv.Write([]string{"Certificate Valid", strconv.FormatBool(mxentry.tlscertvalid)})
		err = tsv.Write([]string{"Fake Sender Accepted", strconv.FormatBool(mxentry.fakesender)})
		err = tsv.Write([]string{"Fake Recipient Accepted", strconv.FormatBool(mxentry.fakercpt)})
		err = tsv.Write([]string{"Open Relay", strconv.FormatBool(mxentry.openrelay)})
	}

	tsv.Flush()

	return err
}
