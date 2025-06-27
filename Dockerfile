FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o /secure-sbom-action ./cmd/main.go

FROM alpine:3.18
COPY --from=builder /secure-sbom-action /usr/local/bin/secure-sbom-action
ENTRYPOINT ["/usr/local/bin/secure-sbom-action"]
