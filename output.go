package main

import (
	"encoding/csv"
	"io"
	"os"
	"time"
)

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
	err = tsv.Write([]string{"Test date", runresult.testdate})
	tsv.Flush()

	return err
}
