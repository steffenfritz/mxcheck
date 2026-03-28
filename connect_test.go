package main

import (
	"reflect"
	"testing"
)

func Test_portScan(t *testing.T) {
	type args struct {
		targetHost string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"PortScan", args{"fritz.wtf"}, "25"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portScan(tt.args.targetHost)
			if len(got) == 0 {
				t.Errorf("portScan() = [], want %v", tt.want)
				return
			}
			if !reflect.DeepEqual(got[0], tt.want) {
				t.Errorf("portScan() = %v, want %v", got[0], tt.want)
			}
		})
	}
}
