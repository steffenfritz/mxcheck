package main

import "testing"

func Test_getLatestVersion(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"VersionCheck", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := getLatestVersion(); (err != nil) != tt.wantErr {
				t.Errorf("getLatestVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
