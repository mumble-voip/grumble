FROM golang:1.9 as builder

COPY . /go/src/mumble.info/grumble

WORKDIR /go/src/mumble.info/grumble

RUN go get -v -t ./... \
  && go build mumble.info/grumble/cmd/grumble \
  && go test -v ./...

FROM golang:1.9

COPY --from=builder /go/bin /go/bin

ENV DATADIR /data

RUN mkdir /data

WORKDIR /data

VOLUME /data

ENTRYPOINT [ "/go/bin/grumble", "--datadir", "/data", "--log", "/data/grumble.log" ]
