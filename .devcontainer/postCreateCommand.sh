#!/bin/sh

go get -u github.com/jteeuwen/go-bindata/...
go get -u github.com/golang/dep/cmd/dep
dep ensure -v -vendor-only
