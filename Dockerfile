FROM fedora:28

ENV GOPATH /go

# vim-common is needed for xxd
# vim-minimal needs to be updated first to avoid an RPM conflict on man1/vim.1.gz
RUN dnf update -y vim-minimal && \
	dnf install -y -b llvm clang rpm findutils perl-interpreter

RUN dnf install -y -b kernel-devel-4.16.3-301.fc28

RUN dnf update -y vim-minimal && \
    	dnf install -y make binutils vim-common ShellCheck git file sudo

RUN curl https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz > /tmp/go.tar.gz
RUN cd /tmp/ && tar -zxf go.tar.gz
RUN mv /tmp/go /usr/local/

ENV GOROOT /usr/local/go
ENV PATH "$GOPATH/bin:$GOROOT/bin:$PATH"

RUN curl -fsSLo shfmt https://github.com/mvdan/sh/releases/download/v1.3.0/shfmt_v1.3.0_linux_amd64 && \
	echo "b1925c2c405458811f0c227266402cf1868b4de529f114722c2e3a5af4ac7bb2  shfmt" | sha256sum -c && \
	chmod +x shfmt && \
	mv shfmt /usr/bin

RUN mkdir -p /src /go
