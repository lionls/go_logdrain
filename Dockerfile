FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o go_logdrain .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl
COPY --from=builder /app/go_logdrain /usr/local/bin/

RUN adduser -D -h /home/app app
USER app
WORKDIR /home/app

ENV PORT=4000
ENV LANG=C.UTF-8
ENV GOMEMLIMIT=128MiB

EXPOSE 4000
CMD ["go_logdrain"]
