FROM golang:1.13.6-buster
WORKDIR /app
RUN apt-get update \
    && apt-get -y install --no-install-recommends apt-utils dialog npm 2>&1 \
    && apt-get -y install git iproute2 procps lsb-release python3-pip \
    && pip3 install sphinx \
    && mkdir /go/tools \
    && ln -s /go/bin /go/tools/bin \
    && mkdir /tmp/goinstall \
    && cd /tmp/goinstall \
    && go mod init goinstall \
    && GOPATH=/go/tools go get golang.org/x/tools/gopls@latest \
    && GOPATH=/go/tools go get -v \
    github.com/ramya-rao-a/go-outline \
    github.com/acroca/go-symbols \
    github.com/uudashr/gopkgs/... \
    golang.org/x/tools/cmd/guru \
    golang.org/x/tools/cmd/gorename \
    github.com/cweill/gotests/... \
    github.com/josharian/impl \
    golang.org/x/lint/golint \
    github.com/cweill/gotests \
    github.com/go-delve/delve/cmd/dlv \
    github.com/mattn/goveralls \
    github.com/golang/mock/mockgen \
    && rm -rf /tmp/goinstall
# COPY go.mod /app/go.mod
# COPY go.sum /app/go.sum
# RUN go mod download