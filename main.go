package main

import (
	"fmt"
	"github.com/shirou/gopsutil/v4/disk"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

type SystemMetrics struct {
	cpuUsage         *prometheus.Desc
	memTotal         *prometheus.Desc
	memAvailable     *prometheus.Desc
	memUsed          *prometheus.Desc
	loadAvg1         *prometheus.Desc
	loadAvg5         *prometheus.Desc
	loadAvg15        *prometheus.Desc
	hostUptime       *prometheus.Desc
	netBytesReceived *prometheus.Desc
	netBytesSent     *prometheus.Desc
	diskTotal        *prometheus.Desc
	diskFree         *prometheus.Desc
	diskUsed         *prometheus.Desc
	diskUsedPercent  *prometheus.Desc
}

func NewSystemMetrics() *SystemMetrics {
	return &SystemMetrics{
		cpuUsage: prometheus.NewDesc(
			"system_cpu_usage_percent",
			"CPU usage percentage",
			nil, nil,
		),
		memTotal: prometheus.NewDesc(
			"system_memory_total_bytes",
			"Total system memory",
			nil, nil,
		),
		memAvailable: prometheus.NewDesc(
			"system_memory_available_bytes",
			"Available system memory",
			nil, nil,
		),
		memUsed: prometheus.NewDesc(
			"system_memory_used_bytes",
			"Used system memory",
			nil, nil,
		),
		loadAvg1: prometheus.NewDesc(
			"system_load_average_1m",
			"System load average (1 minute)",
			nil, nil,
		),
		loadAvg5: prometheus.NewDesc(
			"system_load_average_5m",
			"System load average (5 minutes)",
			nil, nil,
		),
		loadAvg15: prometheus.NewDesc(
			"system_load_average_15m",
			"System load average (15 minutes)",
			nil, nil,
		),
		hostUptime: prometheus.NewDesc(
			"system_uptime_seconds",
			"System uptime in seconds",
			nil, nil,
		),
		netBytesReceived: prometheus.NewDesc(
			"system_network_bytes_received",
			"Total network bytes received",
			[]string{"interface"}, nil,
		),
		netBytesSent: prometheus.NewDesc(
			"system_network_bytes_sent",
			"Total network bytes sent",
			[]string{"interface"}, nil,
		),
		diskTotal: prometheus.NewDesc(
			"system_disk_total_bytes",
			"Total disk space",
			[]string{"path", "device", "fstype"}, nil,
		),
		diskFree: prometheus.NewDesc(
			"system_disk_free_bytes",
			"Free disk space",
			[]string{"path", "device", "fstype"}, nil,
		),
		diskUsed: prometheus.NewDesc(
			"system_disk_used_bytes",
			"Used disk space",
			[]string{"path", "device", "fstype"}, nil,
		),
		diskUsedPercent: prometheus.NewDesc(
			"system_disk_used_percent",
			"Percentage of disk space used",
			[]string{"path", "device", "fstype"}, nil,
		),
	}
}

func (m *SystemMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.cpuUsage
	ch <- m.memTotal
	ch <- m.memAvailable
	ch <- m.memUsed
	ch <- m.loadAvg1
	ch <- m.loadAvg5
	ch <- m.loadAvg15
	ch <- m.hostUptime
	ch <- m.netBytesReceived
	ch <- m.netBytesSent
}

func (m *SystemMetrics) Collect(ch chan<- prometheus.Metric) {
	// CPU Usage
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err == nil && len(cpuPercent) > 0 {
		ch <- prometheus.MustNewConstMetric(
			m.cpuUsage,
			prometheus.GaugeValue,
			cpuPercent[0],
		)
	}

	// Memory
	vmStat, err := mem.VirtualMemory()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			m.memTotal,
			prometheus.GaugeValue,
			float64(vmStat.Total),
		)
		ch <- prometheus.MustNewConstMetric(
			m.memAvailable,
			prometheus.GaugeValue,
			float64(vmStat.Available),
		)
		ch <- prometheus.MustNewConstMetric(
			m.memUsed,
			prometheus.GaugeValue,
			float64(vmStat.Used),
		)
	}

	// Load Average
	loadAvg, err := load.Avg()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			m.loadAvg1,
			prometheus.GaugeValue,
			loadAvg.Load1,
		)
		ch <- prometheus.MustNewConstMetric(
			m.loadAvg5,
			prometheus.GaugeValue,
			loadAvg.Load5,
		)
		ch <- prometheus.MustNewConstMetric(
			m.loadAvg15,
			prometheus.GaugeValue,
			loadAvg.Load15,
		)
	}

	// Host Uptime
	hostInfo, err := host.Uptime()
	if err == nil {
		ch <- prometheus.MustNewConstMetric(
			m.hostUptime,
			prometheus.GaugeValue,
			float64(hostInfo),
		)
	}

	// Network
	netStats, err := net.IOCounters(true)
	if err == nil {
		for _, stat := range netStats {
			ch <- prometheus.MustNewConstMetric(
				m.netBytesReceived,
				prometheus.CounterValue,
				float64(stat.BytesRecv),
				stat.Name,
			)
			ch <- prometheus.MustNewConstMetric(
				m.netBytesSent,
				prometheus.CounterValue,
				float64(stat.BytesSent),
				stat.Name,
			)
		}
	}

	// Disk Metrics
	partitions, err := disk.Partitions(false)
	if err == nil {
		for _, partition := range partitions {
			usage, err := disk.Usage(partition.Mountpoint)
			if err == nil {
				ch <- prometheus.MustNewConstMetric(
					m.diskTotal,
					prometheus.GaugeValue,
					float64(usage.Total),
					partition.Mountpoint, partition.Device, partition.Fstype,
				)
				ch <- prometheus.MustNewConstMetric(
					m.diskFree,
					prometheus.GaugeValue,
					float64(usage.Free),
					partition.Mountpoint, partition.Device, partition.Fstype,
				)
				ch <- prometheus.MustNewConstMetric(
					m.diskUsed,
					prometheus.GaugeValue,
					float64(usage.Used),
					partition.Mountpoint, partition.Device, partition.Fstype,
				)
				ch <- prometheus.MustNewConstMetric(
					m.diskUsedPercent,
					prometheus.GaugeValue,
					usage.UsedPercent,
					partition.Mountpoint, partition.Device, partition.Fstype,
				)
			}
		}
	}
}

func main() {
	metrics := NewSystemMetrics()
	prometheus.MustRegister(metrics)

	// Get port from environment variable, default to 9104
	port := os.Getenv("METRICS_PORT")
	if port == "" {
		port = "9104"
	}

	// Validate port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		log.Fatalf("Invalid port number: %s", port)
	}

	listenAddr := fmt.Sprintf(":%s", port)
	log.Printf("Starting metrics server on %s", listenAddr)

	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
