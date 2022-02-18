ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

BINARY=mxcheck
VERSION=1.2.2
BUILD=`git rev-parse --short HEAD`
PLATFORMS=darwin linux windows freebsd
ARCHITECTURES=amd64

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD} -w -s" 
BLDFLAGS=-buildmode=pie

all: clean build_all

build:
	go build ${BLDFLAGS} ${LDFLAGS} -o ${BINARY}

build_all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); go build $(BLDFLAGS) $(LDFLAGS) -v -o $(BINARY)-$(GOOS))))
	mv mxcheck-darwin mxcheck && tar cvfz mxcheck_macos_$(VERSION).tar.gz mxcheck
	rm mxcheck
	mv mxcheck-linux mxcheck && tar cvfz mxcheck_linux_$(VERSION).tar.gz mxcheck
	rm mxcheck
	mv mxcheck-windows mxcheck && tar cvfz mxcheck_win_$(VERSION).tar.gz mxcheck
	rm mxcheck


clean:
	rm -f '${BINARY}-linux'
	rm -f '${BINARY}-darwin'
	rm -f '${BINARY}-windows'

.PHONY: clean build build_all all
