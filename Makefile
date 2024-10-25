ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
BINARY=mxcheck
VERSION=v1.6.1

BUILD=$(shell git rev-parse --short HEAD)
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64 arm64

LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Build=${BUILD} -w -s"
BLDFLAGS=-buildmode=pie

all: clean build_all

build:
	go build ${BLDFLAGS} ${LDFLAGS} -o ${BINARY}

build_all: $(foreach GOOS,$(PLATFORMS),$(foreach GOARCH,$(ARCHITECTURES),build_$(GOOS)_$(GOARCH)))

define build_template
build_$(1)_$(2):
	GOOS=$(1) GOARCH=$(2) go build $(BLDFLAGS) $(LDFLAGS) -o $(BINARY)-$(1)-$(2)
	tar cvfz $(BINARY)_$(1)_$(2)_$(VERSION).tar.gz $(if $(findstring windows,$(1)),$(BINARY)-$(1)-$(2).exe,$(BINARY)-$(1)-$(2))
	rm $(if $(findstring windows,$(1)),$(BINARY)-$(1)-$(2).exe,$(BINARY)-$(1)-$(2))
endef

$(foreach GOOS,$(PLATFORMS),$(foreach GOARCH,$(ARCHITECTURES),$(eval $(call build_template,$(GOOS),$(GOARCH)))))

clean:
	rm -f ${BINARY}-*
	rm -f *.tar.gz

.PHONY: clean build build_all $(foreach GOOS,$(PLATFORMS),$(foreach GOARCH,$(ARCHITECTURES),build_$(GOOS)_$(GOARCH)))

