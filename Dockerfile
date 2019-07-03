FROM golang:1.12.3 AS BUILD

RUN mkdir /dockerwall
WORKDIR /dockerwall

ADD go.mod .
ADD go.sum .
RUN go mod download

#now build source code
ADD . ./
RUN go build -o /go/bin/dockerwall



FROM golang:1.12.3

RUN apt-get update && \
    apt-get install -y iptables ipset dnsutils

ENV LOG_LEVEL 'info'

COPY --from=BUILD /go/bin/* /bin/
ADD startup.sh /

ENV GATEWAY_NETWORKS ""
ENV DEFAULT_OUTBOUND "_dns_"
ENV DRY_RUN false

VOLUME [ "/var/run/docker.sock" ]
EXPOSE 50000

CMD [ "/startup.sh" ]
