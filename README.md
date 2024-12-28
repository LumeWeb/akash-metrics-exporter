# Akash Metrics Exporter

## Overview

A Prometheus metrics exporter designed for Akash Network nodes that provides comprehensive system-level metrics. Built with modern Linux cgroups v2 support, it offers detailed resource utilization monitoring and seamless integration with etcd for service discovery. The metrics endpoint is protected by basic authentication to ensure secure access.

## Features

- **cgroups v2 Integration**: Accurate system resource monitoring using modern Linux cgroups
- **Real-time Network Monitoring**: Per-interface network statistics with rate calculations
- **Service Discovery**: Optional etcd integration for automatic service registration
- **Container-Ready**: Full Docker support with automated builds
- **Automatic Node Identification**: Extracts unique node IDs from Akash ingress hostnames
- **Registration Health Monitoring**: Tracks node registration status and errors
- **Version Tracking**: Built-in version information with Git commit tracking

## Metrics

### System Resources
- **CPU**: `system_cpu_usage_percent` - CPU utilization percentage
- **Memory**: `system_memory_usage_bytes` - Current memory consumption

### I/O Performance
- **Read Operations**: 
  - `system_io_read_bytes` - Total bytes read
  - `system_io_read_operations` - Count of read operations
- **Write Operations**:
  - `system_io_write_bytes` - Total bytes written
  - `system_io_write_operations` - Count of write operations

### Network Statistics (per interface)
- **Receive (RX)**:
  - `system_network_rx_bytes_per_second` - Incoming bandwidth usage
  - `system_network_rx_packets_per_second` - Packet receive rate
- **Transmit (TX)**:
  - `system_network_tx_bytes_per_second` - Outgoing bandwidth usage
  - `system_network_tx_packets_per_second` - Packet transmit rate

### Registration Metrics
- **Status**: `node_registration_status` - Current registration status (0=down, 1=up)
- **Errors**: `node_registration_errors_total` - Total number of registration errors
- **Last Success**: `node_last_registration_timestamp` - Unix timestamp of last successful registration
- **Deployment Info**: `node_deployment_info` - Node deployment information with hash_id and deployment_id labels

## Configuration

### Environment Variables
- `ETCD_ENDPOINTS` - Comma-separated etcd server addresses
- `ETCD_PREFIX` - Key prefix for etcd registration
- `ETCD_USERNAME` - etcd authentication username
- `ETCD_PASSWORD` - etcd authentication password
- `METRICS_PORT` - Port for the metrics endpoint to listen on (default: 8080)
- `AKASH_EXTERNAL_PORT_X` - Optional Akash deployment port mapping (where X matches your METRICS_PORT value)
- `AKASH_INGRESS_HOST` - Akash ingress hostname (used for node identification)
- `AKASH_DEPLOYMENT_SEQUENCE` - Akash blockchain deployment ID
- `METRICS_PASSWORD` - Required password for basic auth protection of metrics endpoint
- `METRICS_SERVICE_NAME` - Required service name for registration with etcd

### Port & Network Configuration
The exporter uses a flexible configuration system:
1. Set `METRICS_PORT` to specify which port the metrics endpoint should listen on (defaults to 8080)
2. For Akash deployments, the corresponding `AKASH_EXTERNAL_PORT_X` variable (where X is your METRICS_PORT value) will be automatically detected and used for etcd registration
3. The exporter automatically detects and monitors all network interfaces, providing per-interface metrics

### Service Registration Details
When etcd integration is enabled, the following information is registered:
- Node name (extracted from Akash ingress hostname)
- Full metrics endpoint URL (constructed from ingress host and port)
- Basic auth password (for automated service discovery)
- Port configuration (internal and external mappings)
- Version information (version, git commit hash)
- Build details (timestamp, Go version, OS/arch)

This enables automated service discovery while maintaining security through basic authentication and provides version tracking for deployment verification.

## Development

### Prerequisites
- Go 1.23.2 or later
- Linux system with cgroups v2 enabled

### Testing
```bash
go test -v ./...
```

### Local Build
```bash
# Build with version information
go build -ldflags "-X go.lumeweb.com/akash-metrics-exporter/pkg/build.Version=dev \
                  -X go.lumeweb.com/akash-metrics-exporter/pkg/build.GitCommit=$(git rev-parse HEAD) \
                  -X go.lumeweb.com/akash-metrics-exporter/pkg/build.BuildTime=$(date -u '+%Y-%m-%d_%H:%M:%S')" \
         ./cmd/metrics-exporter
```

### Docker Build
```bash
docker build -t akash-metrics-exporter .
```

### Version Information
The exporter includes built-in version tracking that is set at build time:
- Version number (from git tag or manual setting)
- Git commit hash
- Build timestamp
- Go version
- OS/Architecture

This information is:
- Included in etcd registration
- Available in metrics labels
- Used for deployment verification

## Service Registration

The exporter automatically registers itself with etcd when configured, using the node ID extracted from the Akash ingress hostname. This enables automatic service discovery in distributed environments.
