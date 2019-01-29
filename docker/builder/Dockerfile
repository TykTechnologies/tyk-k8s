FROM golang:1.10.0-alpine as build

ENV TYKVERSION v2.7.5

LABEL Description="Tyk Gateway docker image" Vendor="Tyk" Version="$TYKVERSION GRPC custom micro build"

RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh && \
    go get github.com/TykTechnologies/tyk && \
    cd /go/src/github.com/TykTechnologies/tyk && git checkout --force $TYKVERSION && \
    go install -ldflags="-s -w" -tags 'coprocess grpc' .

FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /opt/tyk-gateway
COPY --from=build /go/bin/tyk /opt/tyk-gateway/tyk
COPY --from=build /go/src/github.com/TykTechnologies/tyk/templates /opt/tyk-gateway/templates
COPY files/tyk-smesh.conf /opt/tyk-gateway/tyk.conf

CMD ["./tyk"]