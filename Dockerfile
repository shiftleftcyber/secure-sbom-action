FROM golang:1.25.10-alpine3.23@sha256:8d22e29d960bc50cd025d93d5b7c7d220b1ee9aa7a239b3c8f55a57e987e8d45 AS builder
WORKDIR /app
COPY . .
RUN go build -o /secure-sbom-action ./cmd

FROM alpine:3.23.4
COPY --from=builder /secure-sbom-action /usr/local/bin/secure-sbom-action
ENTRYPOINT ["/usr/local/bin/secure-sbom-action"]
