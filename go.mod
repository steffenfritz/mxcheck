module github.com/steffenfritz/mxcheck

go 1.23.0

toolchain go1.23.4

require (
	github.com/jamesog/iptoasn v0.1.0
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/miekg/dns v1.1.66
	github.com/spf13/pflag v1.0.6
)

require golang.org/x/sync v0.14.0 // indirect

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/net v0.40.0 // indirect; manual update due to a security issue in older versions
	// golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
)
