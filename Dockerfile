# contelys/identity: Identity's binary alone, FROM scratch, under a user that is not root (Identity
# ADR 0009). The image holds no certificate bundle, because Identity trusts only the installation's
# certificate authority, which reaches it as a file (ADR 0039), and the binary embeds its time-zone
# data. Each instance mounts its configuration at /etc/identity/config.yaml.

# The build stage: the Go of go.mod, pinned by the index digest of golang:1.27.0-alpine.
FROM golang:1.27.0-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
ENV GOWORK=off CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags='-s -w' -o /out/identity ./cmd/identity

FROM scratch
COPY --from=build /out/identity /identity
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/identity"]
CMD ["-config", "/etc/identity/config.yaml"]
# Identity's own subcommand checks readiness, because the image has no shell.
HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=3 \
    CMD ["/identity", "health", "-config", "/etc/identity/config.yaml"]
