#!/usr/bin/env bash

sudo apt-get install -y \
    make \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

sudo add-apt-repository ppa:gophers/archive

sudo apt-get update && sudo apt-get install -y golang-1.10-go docker-ce clang llvm go-bindata

sudo cp /usr/lib/go-1.10/bin/go /usr/bin/go
echo "GOPATH=/opt/stackstate-go" > /etc/environment
