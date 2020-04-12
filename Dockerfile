FROM golang:1.14-alpine as builder

COPY . /go/src/mumble.info/grumble

WORKDIR /go/src/mumble.info/grumble

RUN apk add --no-cache git build-base

RUN go get -v -t ./... \
  && go build mumble.info/grumble/cmd/grumble \
  && go test -v ./...

FROM alpine:edge

COPY --from=builder /go/bin/grumble /usr/bin/grumble

ENV DATADIR /data

RUN mkdir /data

WORKDIR /data

VOLUME /data

EXPOSE 64738/tcp
EXPOSE 64738/udp

ENTRYPOINT [ "/usr/bin/grumble", "--datadir", "/data", "--log", "/data/grumble.log" ]
