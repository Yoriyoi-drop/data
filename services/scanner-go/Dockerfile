# Use the official Golang image to build the scanner binary
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o scanner .

# Minimal runtime image
FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/scanner .
EXPOSE 8002
CMD ["./scanner"]
