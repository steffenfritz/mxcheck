package main

import (
	"bytes"
	"testing"
)

func TestNewTSVWriter(t *testing.T) {
	tests := []struct {
		name  string
		wantW string
	}{
		{"New TSV Writer", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("NewTSVWriter() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func Test_writeTSV(t *testing.T) {
	type args struct {
		targetHostName string
		runresult      runresult
		blacklist      bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"Write TSV file", args{targetHostName: "deadbeef", runresult: runresult{}, blacklist: false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := writeTSV(tt.args.targetHostName, tt.args.runresult, tt.args.blacklist); (err != nil) != tt.wantErr {
				t.Errorf("writeTSV() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
