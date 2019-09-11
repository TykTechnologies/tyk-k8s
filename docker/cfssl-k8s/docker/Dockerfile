FROM ubuntu
RUN apt-get update
RUN apt-get install -y ca-certificates curl git gcc

RUN curl -O https://storage.googleapis.com/golang/go1.12.9.linux-amd64.tar.gz
RUN tar -xvf go1.12.9.linux-amd64.tar.gz
RUN mv go /usr/local
ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

RUN go get -u github.com/cloudflare/cfssl/cmd/cfssl
RUN go get -u github.com/cloudflare/cfssl/cmd/cfssljson


CMD ["/go/bin/cfssl", "serve", "-address", "0.0.0.0", "-ca-key", "/cfssl/ca-key.pem", "-ca", "/cfssl/ca.pem", "-config", "/cfssl/config_ca.json"]