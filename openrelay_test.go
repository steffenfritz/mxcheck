package main

import (
	"reflect"
	"testing"
)

func Test_openRelay(t *testing.T) {
	type args struct {
		mailFrom   string
		mailTo     string
		targetHost string
		targetPort string
	}

	var result openResult
	tests := []struct {
		name    string
		args    args
		want    openResult
		wantErr bool
	}{
		{"Open Relay Test", args{"foo@baz.com", "baz@foo.com", "fritz.wtf", "25"}, result, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := openRelay(tt.args.mailFrom, tt.args.mailTo, tt.args.targetHost, tt.args.targetPort)
			if (err != nil) != tt.wantErr {
				t.Errorf("openRelay() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.orboolresult, tt.want.orboolresult) {
				t.Errorf("openRelay() got = %v, want %v", got.orboolresult, tt.want)
			}
		})
	}
}
