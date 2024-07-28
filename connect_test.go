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
			if got := portScan(tt.args.targetHost); !reflect.DeepEqual(got[0], tt.want) {
				t.Errorf("portScan() = %v, want %v", got[0], tt.want)
			}
		})
	}
}
