FROM golang:1.16 as builder

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

FROM registry.access.redhat.com/ubi8-micro:latest

COPY --from=builder /go/bin/* /bin/
