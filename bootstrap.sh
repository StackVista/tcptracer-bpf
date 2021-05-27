#!/usr/bin/env bash

sudo apt-get install -y \
    make \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common \
    linux-headers-$(uname -r)

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

sudo apt-get update && sudo apt-get install -y golang-go docker-ce clang llvm go-bindata

# for bpftool
sudo apt-get install linux-tools-common linux-tools-generic -y

echo "GOPATH=/opt/stackstate-go" | sudo tee --append /etc/environment
