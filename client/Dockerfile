FROM golang:1.23 AS builder

WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire client directory
COPY . .

# Build the client binary
RUN GOOS=linux GOARCH=amd64 go build -o client client.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/client .

# Copy the .env file
COPY .env .

# Ensure the binary has execute permissions
RUN chmod +x ./client

# Run the client application
CMD ["./client"]
