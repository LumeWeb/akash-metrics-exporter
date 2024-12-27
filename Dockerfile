# Use a minimal alpine image for the final stage
FROM alpine:latest

# Install necessary system dependencies
RUN apk --no-cache add ca-certificates

# Copy the built executable from the builder stage
COPY ./metrics-exporter /usr/bin/metrics-exporter

# Command to run the executable
ENTRYPOINT ["metrics-exporter"]
