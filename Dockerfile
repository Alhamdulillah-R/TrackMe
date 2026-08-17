# syntax=docker/dockerfile:1.18

FROM golang:1.24-alpine AS build
RUN apk add --no-cache build-base libpcap-dev
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd ./cmd
COPY pkg ./pkg
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/trackme ./cmd/main.go

FROM alpine:3.22
RUN apk add --no-cache libpcap \
    && addgroup -S -g 101 trackme \
    && adduser -S -D -H -u 65532 -G trackme trackme
WORKDIR /app

COPY --from=build --chown=65532:101 /out/trackme /app/trackme
COPY --chown=65532:101 static /app/static
COPY --chown=65532:101 blockedIPs /app/blockedIPs

USER 65532:101
EXPOSE 443/tcp 443/udp 18082/tcp
ENTRYPOINT ["/app/trackme"]
