# Use the official Golang image as a builder
FROM golang:1.23 AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire server directory
COPY . .

# Build the server binary
RUN GOOS=linux GOARCH=amd64 go build -o server server.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/server .

# Copy the .env file
COPY .env .

# Ensure the binary has execute permissions
RUN chmod +x ./server

# Run the server application
CMD ["./server"]
