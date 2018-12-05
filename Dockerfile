FROM golang:1.10 AS BUILD

#doing dependency build separated from source build optimizes time for developer, but is not required
#install external dependencies first
ADD /main.go $GOPATH/src/dockerwall/main.go
RUN go get -v dockerwall

#now build source code
ADD dockerwall $GOPATH/src/dockerwall
RUN go get -v dockerwall
#RUN go test -v dockerwall


#FROM scratch
FROM docker:18.09

ENV LOG_LEVEL 'info'

COPY --from=BUILD /go/bin/* /bin/
ADD startup.sh /startup.sh

VOLUME [ "/var/run/docker.sock" ]
CMD [ "/startup.sh" ]
