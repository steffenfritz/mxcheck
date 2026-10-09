package main

import (
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_getA(t *testing.T) {
	type args struct {
		targetHostName string
		dnsServer      string
	}

	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"getA", args{dns.Fqdn("fritz.wtf"), "8.8.8.8"}, "159.69.212.31", false},
	}
	for _, tt := range tests {
		println(tt.args.targetHostName)
		t.Run(tt.name, func(t *testing.T) {
			got, err := getA(tt.args.targetHostName, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getA() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDKIM(t *testing.T) {
	type args struct {
		selector       string
		targetHostName string
		dnsServer      string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"DKIM", args{selector: "default", targetHostName: "mail.fritz.wtf", dnsServer: "8.8.8.8"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getDKIM(tt.args.selector, tt.args.targetHostName, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDKIM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_getDMARC(t *testing.T) {
	type args struct {
		targetHostName string
		dnsServer      string
	}
	tests := []struct {
		name    string
		args    args
		want    dmarc
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getDMARC(tt.args.targetHostName, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDMARC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getDMARC() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getMTASTS(t *testing.T) {
	type args struct {
		targetHostName string
		dnsServer      string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"MTASTS", args{"fritz.wtf", "8.8.8.8"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getMTASTS(tt.args.targetHostName, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getMTASTS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getMTASTS() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getMX(t *testing.T) {
	type args struct {
		targetHostName *string
		dnsServer      string
	}

	host := "fritz.wtf"

	tests := []struct {
		name    string
		args    args
		want    []string
		want1   bool
		wantErr bool
	}{
		{"getMX", args{&host, "8.8.8.8"}, []string{"mail.fritz.wtf."}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getMX(tt.args.targetHostName, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getMX() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getMX() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getMX() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_getPTR(t *testing.T) {
	type args struct {
		ipaddr    string
		dnsServer string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"PTR", args{"159.69.212.31", "8.8.8.8"}, "mail.fritz.wtf.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPTR(tt.args.ipaddr, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPTR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getPTR() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDANE(t *testing.T) {
	type args struct {
		mxhost    string
		dnsServer string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"DANE no record", args{"mail.fritz.wtf.", "8.8.8.8"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getDANE(tt.args.mxhost, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDANE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getSPF(t *testing.T) {
	type args struct {
		targetHostName string
		dnsServer      string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"SPF", args{"fritz.wtf", "8.8.8.8"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := getSPF(tt.args.targetHostName, tt.args.dnsServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSPF() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getSPF() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// startDropServer starts a local UDP DNS server that silently drops the first
// drop queries and answers all later ones. It returns the server address and
// a counter of received queries.
func startDropServer(t *testing.T, drop int32) (string, *int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	var count int32
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			if atomic.AddInt32(&count, 1) <= drop {
				return
			}
			m := new(dns.Msg)
			m.SetReply(r)
			w.WriteMsg(m)
		}),
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String(), &count
}

func Test_exchangeWithRetry(t *testing.T) {
	tests := []struct {
		name      string
		drop      int32
		wantErr   bool
		wantCount int32
	}{
		{"answer on first try", 0, false, 1},
		{"answer after one timeout", 1, false, 2},
		{"all attempts time out", dnsRetries, true, dnsRetries},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, count := startDropServer(t, tt.drop)
			m := new(dns.Msg)
			m.SetQuestion("example.org.", dns.TypeA)
			c := &dns.Client{Timeout: 200 * time.Millisecond}

			_, _, err := exchangeWithRetry(c, m, addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("exchangeWithRetry() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := atomic.LoadInt32(count); got != tt.wantCount {
				t.Errorf("exchangeWithRetry() queries = %d, want %d", got, tt.wantCount)
			}
		})
	}
}
