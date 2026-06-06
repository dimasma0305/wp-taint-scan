# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/taint-web ./cmd/taint-web

# ---- run ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 app \
 && mkdir -p /data && chown app /data
COPY --from=build /out/taint-web /usr/local/bin/taint-web
USER app
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["taint-web"]
CMD ["-addr", "0.0.0.0:8080", "-cache-dir", "/data"]
