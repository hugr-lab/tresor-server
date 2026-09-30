# syntax=docker/dockerfile:1
# tresor-server (spec 002): one static binary (no cgo) in a distroless image, as a non-root user. Built for the
# target platform from the build's own (docker buildx: linux/amd64, linux/arm64).
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/tresor-server ./cmd/tresor-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tresor-server /tresor-server
USER nonroot:nonroot
# the configuration comes from TRESOR_* variables (or -config <file>); /healthz and /readyz for the probes
EXPOSE 8080
ENTRYPOINT ["/tresor-server"]
