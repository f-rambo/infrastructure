FROM golang:1.22 AS builder

COPY . /src
WORKDIR /src

ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn
ENV GOPRIVATE=github.com/f-rambo/

RUN make build && mkdir -p /app && cp -r bin /app/ && cp -r configs /app/

FROM debian:stable-slim

COPY --from=builder /app /app

WORKDIR /app

EXPOSE 9002
VOLUME /data/conf

CMD ["./bin/infrastructure", "-conf", "./configs/config.yaml"]
