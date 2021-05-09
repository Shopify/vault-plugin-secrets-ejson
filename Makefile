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
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -mod vendor -o vault/plugins/secrets-ejson cmd/vault-plugin-secrets-ejson/main.go

clean:
	rm -f ./vault-plugin-secrets-ejson
	rm -rf ./vault/plugins/

deps:
	go mod tidy

fmt:
	go fmt $$(go list ./...)

test:
	go vet $$(go list ./...)
	GOOS=$(OS) GOARCH="$(GOARCH)" go test -v -cover $$(go list ./...)

server:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

loadPlugin:
	export VAULT_ADDR='http://127.0.0.1:8200'
	vault secrets enable -path=ejson secrets-ejson

.PHONY: all build clean deps fmt test
