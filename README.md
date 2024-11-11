# Akash Metrics Exporter

## Overview

A Prometheus metrics exporter for system-level metrics, designed to provide comprehensive insights into system performance and resource utilization. This exporter collects and exposes metrics about CPU, memory, load average, network, disk usage, and host uptime.

## Features

- Prometheus-compatible metrics
- Lightweight and efficient
- Dockerized deployment
- Configurable metrics port
- Supports multiple system metrics:
  - CPU Usage
  - Memory Utilization
  - System Load Average
  - Network I/O
  - Disk Space and Usage

## Metrics Exposed

- `system_cpu_usage_percent`: CPU usage percentage
- `system_memory_total_bytes`: Total system memory
- `system_memory_available_bytes`: Available system memory
- `system_memory_used_bytes`: Used system memory
- `system_load_average_1m`: System load average (1 minute)
- `system_load_average_5m`: System load average (5 minutes)
- `system_load_average_15m`: System load average (15 minutes)
- `system_uptime_seconds`: System uptime
- `system_network_bytes_received`: Network bytes received per interface
- `system_network_bytes_sent`: Network bytes sent per interface
- `system_disk_total_bytes`: Total disk space
- `system_disk_free_bytes`: Free disk space
- `system_disk_used_bytes`: Used disk space
- `system_disk_used_percent`: Percentage of disk space used
