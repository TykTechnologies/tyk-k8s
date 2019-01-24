FROM        alpine:3.6
MAINTAINER  Martin Buhr <martin@tyk.io>

# Borrowed with thanks from https://github.com/4km3/docker-alpine-set-iptables

LABEL Description="iptables configurator" \
      Vendor="Tyk Technologies"     	  \
      Version="1.0"

COPY entrypoint /

ENTRYPOINT [ "/entrypoint" ]

RUN	set -ex;			\
	apk add --no-cache iptables