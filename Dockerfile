FROM golang:1.10 AS BUILD

#doing dependency build separated from source build optimizes time for developer, but is not required
#install external dependencies first
ADD /main.go $GOPATH/src/dockerwall/main.go
RUN go get -v dockerwall

#now build source code
ADD dockerwall $GOPATH/src/dockerwall
RUN go get -v dockerwall
#RUN go test -v dockerwall


# FROM ubuntu:18.04
# FROM scratch
# FROM docker:18.09
FROM golang:1.10

# RUN apt-get update && \
#     apt-get install -y apt-transport-https ca-certificates curl software-properties-common && \
#     curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - && \
#     add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

RUN apt-get update && \
    apt-get install -y iptables ipset dnsutils

ENV LOG_LEVEL 'info'

COPY --from=BUILD /go/bin/* /bin/
ADD startup.sh /

ENV GATEWAY_NETWORKS ""

VOLUME [ "/var/run/docker.sock" ]
EXPOSE 50000

# ENTRYPOINT [ "/bin/sh" ]
CMD [ "/startup.sh" ]
