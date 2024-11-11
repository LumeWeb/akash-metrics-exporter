# Use the official Golang image as the base image
FROM golang:1.23-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code into the container
COPY main.go .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o metrics-exporter

# Use a minimal alpine image for the final stage
FROM alpine:latest

# Install necessary system dependencies
RUN apk --no-cache add ca-certificates

# Set the working directory
WORKDIR /root/

# Copy the built executable from the builder stage
COPY --from=builder /app/metrics-exporter /usr/bin/metrics-exporter

# Expose the default metrics port
EXPOSE 9104

# Set a default environment variable for the metrics port
ENV METRICS_PORT=9104

# Command to run the executable
ENTRYPOINT ["metrics-exporter"]
