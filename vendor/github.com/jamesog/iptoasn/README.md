# IP to ASN [![GoDoc](https://godoc.org/github.com/jamesog/iptoasn?status.svg)](https://godoc.org/github.com/jamesog/iptoasn)

Package `iptoasn` uses [Team Cymru](https://www.team-cymru.com/)'s [IP to ASN](https://www.team-cymru.com/IP-ASN-mapping.html) mapping service for querying BGP origin information about a given IP address. It supports both IPv4 and IPv6 (of course, this isn't 1982).

This uses the DNS interface to the IP to ASN service rather than the WHOIS interface.

## Usage

```go
ip, err := iptoasn.LookupIP("2001:db8::1")
```

```go
as, err := iptoasn.LookupASN("as20712")
```

## Command-line tool

A `whoisip` command is provided as a simple tool for performing IP or AS lookups using the library.

## License

MIT
