FROM golang:1.25.8-alpine3.23@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa AS builder
WORKDIR /app
COPY . .
RUN go build -o /secure-sbom-action ./cmd

FROM alpine:3.23
COPY --from=builder /secure-sbom-action /usr/local/bin/secure-sbom-action
ENTRYPOINT ["/usr/local/bin/secure-sbom-action"]
