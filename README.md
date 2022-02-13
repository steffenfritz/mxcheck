# mxcheck

mxcheck is an info scanner for mail servers

It checks 
  1. DNS records: A, MX, PTR, SPF, MTA-STS
  2. for support of StartTLS and the certificate
  3. open ports: 25, 465, 587
  4. and if the server is an open relay

You can set mailFrom, mailTo, the DNS server and output a report in tsv format.


    -d, --dnsserver string   The dns server to consult (default "8.8.8.8")
    -f, --mailfrom string    Set the mailFrom address (default "info@foo.wtf")
    -t, --mailto string      Set the mailTo address (default "info@baz.wtf")
    -n, --no-prompt          Answer yes to all questions
    -s, --service string     The service host to check (default "localhost")
    -v, --version            Version and license
    -w, --write-tsv          Write tsv formated report to file


# Version

v1.2.1-RC1

[![Go Report Card](https://goreportcard.com/badge/github.com/steffenfritz/mxcheck)](https://goreportcard.com/report/github.com/steffenfritz/mxcheck) 


# Installation

    
    go get github.com/steffenfritz/mxcheck (deprecated since go 1.17)
    
or 

    go install github.com/steffenfritz/mxcheck
    
or

    download a pre-compiled binary.

# Usage Example

    ./mxcheck -s 2600.com
    ./mxcheck -s 2600.com -v
    ./mxcheck -s 2600.com -v -d 8.8.8.8
    ./mxcheck -s 2600.com -v -n -f info@baz.com -t boss@foo.org -w

There is no check whether the server needs authentication. However, you can do two runs:

The first one uses a from and to address outside the mail server's scope, e.g.:

    ./mxcheck -s example.com -f info@baz.com -t boss@foo.org

The second one uses a from and a to address from the mail server's scope, e.g.:

    ./mxcheck -s example.com -f info@example.com -t boss@example.com

If the first one returns ``Server is not an open relay`` and the second one returns `Server is probably an open relay` the server is not an open relay, but you can send mails from local to local addresses.

