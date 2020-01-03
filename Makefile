GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt test build

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -mod vendor -o vault-plugin-secrets-ejson cmd/vault-plugin-secrets-ejson/main.go

clean:
	rm -f ./vault-plugin-secrets-ejson

deps:
	go mod tidy

fmt:
	go fmt $$(go list ./...)

test:
	go vet $$(go list ./...)
	GOOS=$(OS) GOARCH="$(GOARCH)" go test -v -cover $$(go list ./...)

.PHONY: all build clean deps fmt test
