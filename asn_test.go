package main

import (
	"github.com/jamesog/iptoasn"
	"reflect"
	"testing"
)

func Test_getASN(t *testing.T) {
	type args struct {
		ip string
	}

	var ipasntest iptoasn.IP
	ipasntest.ASNum = 24940

	tests := []struct {
		name    string
		args    args
		want    uint32
		wantErr bool
	}{
		{"ASN Test", args{"159.69.212.31"}, 24940, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getASN(tt.args.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("getASN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.ASNum, tt.want) {
				t.Errorf("getASN() got = %v, want %v", got.ASNum, tt.want)
			}
		})
	}
}
