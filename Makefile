ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

BINARY=mxcheck
VERSION=v1.5.2-1

BUILD=`git rev-parse --short HEAD`
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64 arm64

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD} -w -s"
BLDFLAGS=-buildmode=pie

all: clean build_all

build:
	go build ${BLDFLAGS} ${LDFLAGS} -o ${BINARY}

build_all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); go build $(BLDFLAGS) $(LDFLAGS) -v -o $(BINARY)-$(GOOS)-$(GOARCH))))
	mv mxcheck-darwin-amd64 mxcheck && tar cvfz mxcheck_macos_amd64_$(VERSION).tar.gz mxcheck
	rm mxcheck
	mv mxcheck-darwin-arm64 mxcheck && tar cvfz mxcheck_macos_arm64_$(VERSION).tar.gz mxcheck
	rm mxcheck
	mv mxcheck-linux-amd64 mxcheck && tar cvfz mxcheck_linux_amd64_$(VERSION).tar.gz mxcheck
	rm mxcheck
	mv mxcheck-linux-arm64 mxcheck && tar cvfz mxcheck_linux_arm64_$(VERSION).tar.gz mxcheck
	rm mxcheck
	mv mxcheck-windows-amd64 mxcheck.exe && tar cvfz mxcheck_win_amd64_$(VERSION).tar.gz mxcheck.exe
	rm mxcheck.exe
	mv mxcheck-windows-arm64 mxcheck.exe && tar cvfz mxcheck_win_arm64_$(VERSION).tar.gz mxcheck.exe
	rm mxcheck.exe

clean:
	rm -f '${BINARY}-linux'
	rm -f '${BINARY}-darwin'
	rm -f '${BINARY}-windows'

.PHONY: clean build build_all all
