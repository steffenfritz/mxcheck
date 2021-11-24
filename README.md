# mxcheck

mxcheck is an info scanner for mail servers

It checks 
  1. DNS records: A, MX, PTR, SPF
  2. for support of StartTLS
  3. open ports: 25, 465, 587
  4. and if the server is an open relay

# Version

v1.1.1

[![Go Report Card](https://goreportcard.com/badge/github.com/steffenfritz/mxcheck)](https://goreportcard.com/report/github.com/steffenfritz/mxcheck) 


# Installation

    go get github.com/steffenfritz/mxcheck

# Usage Example

    ./mxcheck -t 2600.com
    ./mxcheck -t 2600.com -v
    ./mxcheck -t 2600.com -v -d 8.8.8.8

