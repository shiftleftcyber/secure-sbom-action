FROM golang:1.25.11-alpine3.23@sha256:60e626bbde32def8694687d03536ea4341b19e5f068e9a630225a1dfbd0505c9 AS builder
WORKDIR /app
COPY . .
RUN go build -o /secure-sbom-action ./cmd

FROM alpine:3.23
COPY --from=builder /secure-sbom-action /usr/local/bin/secure-sbom-action
ENTRYPOINT ["/usr/local/bin/secure-sbom-action"]
