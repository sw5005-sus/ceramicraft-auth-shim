# Builder stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth-shim .

# Final stage
FROM alpine:3.19

WORKDIR /app

# Install certificates for HTTPS outgoing calls (to ZITADEL)
RUN apk --no-cache add ca-certificates

COPY --from=builder /app/auth-shim /app/auth-shim

EXPOSE 8080

CMD ["/app/auth-shim"]

