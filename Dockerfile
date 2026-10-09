# syntax=docker/dockerfile:1

# Build stage: compile the ContainerSSH server binary for the target platform.
FROM golang:1.25-alpine AS build
WORKDIR /src

# Download dependencies first to leverage layer caching.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/containerssh ./cmd/containerssh

# Runtime stage: mirrors the conventions of the upstream containerssh image
# (Alpine base, binary at /containerssh, unprivileged user 1022, config under
# /etc/containerssh).
FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/containerssh /containerssh
USER 1022:1022
EXPOSE 2222
ENTRYPOINT ["/containerssh", "--config", "/etc/containerssh/config.yaml"]
