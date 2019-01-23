# mxcheck

mxcheck is a info scanner for mail servers

It checks 
  1. DNS records: A, MX, PTR, SPF
  2. support of StartTLS
  3. Portscan: 25, 465, 587
  4. Open Relay

# Version

v1.1.0

[![Go Report Card](https://goreportcard.com/badge/github.com/steffenfritz/mxcheck)](https://goreportcard.com/report/github.com/steffenfritz/mxcheck) [![Build Status](https://travis-ci.org/steffenfritz/mxcheck.svg?branch=master)](https://travis-ci.org/steffenfritz/mxcheck)


# Installation

    go get github.com/steffenfritz/mxcheck

# Usage Example

    ./mxcheck -t 2600.com

    All people like vidoes nowadays: 

    [![asciicast](https://asciinema.org/a/tapqMW8iRngAjnJJWeTkHAoSp<Paste>)](https://asciinema.org/a/tapqMW8iRngAjnJJWeTkHAoSp)
