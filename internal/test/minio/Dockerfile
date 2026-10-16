FROM golang:1.25.3-alpine3.22 AS build

# Official prebuilt community images are no longer publicly available.
# Pin RELEASE.2025-10-15T17-29-55Z instead of depending on a moving tag.
RUN CGO_ENABLED=0 go install github.com/minio/minio@9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a

FROM alpine:3.23
COPY --from=build /go/bin/minio /usr/local/bin/minio
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/minio"]
