# Akash Metrics Exporter

## Overview

A Prometheus metrics exporter designed for Akash Network nodes that provides comprehensive system-level metrics. Built with modern Linux cgroups v2 support, it offers detailed resource utilization monitoring and seamless integration with etcd for service discovery. The metrics endpoint is protected by basic authentication to ensure secure access.

## Features

- **cgroups v2 Integration**: Accurate system resource monitoring using modern Linux cgroups
- **Real-time Network Monitoring**: Per-interface network statistics with rate calculations
- **Service Discovery**: Optional etcd integration for automatic service registration
- **Container-Ready**: Full Docker support with automated builds
- **Automatic Node Identification**: Extracts unique node IDs from Akash ingress hostnames

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

## Configuration

### Environment Variables
- `ETCD_ENDPOINTS` - Comma-separated etcd server addresses
- `ETCD_PREFIX` - Key prefix for etcd registration
- `ETCD_USERNAME` - etcd authentication username
- `ETCD_PASSWORD` - etcd authentication password
- `METRICS_PORT` - Port for the metrics endpoint to listen on (default: 8080)
- `AKASH_EXTERNAL_PORT_X` - Optional Akash deployment port mapping (where X matches your METRICS_PORT value)
- `AKASH_INGRESS_HOST` - Akash ingress hostname (used for node identification)
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

This enables automated service discovery while maintaining security through basic authentication.

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
go build
```

### Docker Build
```bash
docker build -t akash-metrics-exporter .
```

## Service Registration

The exporter automatically registers itself with etcd when configured, using the node ID extracted from the Akash ingress hostname. This enables automatic service discovery in distributed environments.
