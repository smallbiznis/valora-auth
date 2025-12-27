FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /workspace/auth ./cmd/auth

FROM gcr.io/distroless/static-debian12 AS runtime
COPY --from=builder /workspace/auth /usr/local/bin/auth

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/auth"]
