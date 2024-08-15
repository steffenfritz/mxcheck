package main

import "testing"

func Test_tlsCheck(t *testing.T) {
	type args struct {
		targetHost string
		port       string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   bool
		want2   bool
		wantErr bool
	}{
		{"TLS check", args{"fritz.wtf", "465"}, "TLS 1.3", true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, err := tlsCheck(tt.args.targetHost, tt.args.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("tlsCheck() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("tlsCheck() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("tlsCheck() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("tlsCheck() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}
