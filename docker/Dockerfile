FROM centos

RUN mkdir -p /opt/tyk-k8s
COPY files/build/tyk-k8s /opt/tyk-k8s/tyk-k8s

WORKDIR /opt/tyk-k8s

CMD ["/opt/goproxy/tyk-k8s", "start", "injector"]