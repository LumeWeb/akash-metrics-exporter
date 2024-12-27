package metrics

import (
	"bufio"
	"fmt"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/prometheus/client_golang/prometheus"
	"go.lumeweb.com/akash-metrics-exporter/pkg/metrics/validation"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type SystemMetrics struct {
	cpuUsage          *prometheus.Desc
	memUsage          *prometheus.Desc
	ioReadBytes       *prometheus.Desc
	ioWriteBytes      *prometheus.Desc
	ioReadOperations  *prometheus.Desc
	ioWriteOperations *prometheus.Desc
	rxBytesPerSec     *prometheus.Desc
	txBytesPerSec     *prometheus.Desc
	rxPacketsPerSec   *prometheus.Desc
	txPacketsPerSec   *prometheus.Desc
	networkMonitor    *NetworkMonitor
}

func NewSystemMetrics() *SystemMetrics {
	return &SystemMetrics{
		cpuUsage: prometheus.NewDesc(
			"system_cpu_usage_percent",
			"CPU usage percentage",
			nil, nil,
		),
		memUsage: prometheus.NewDesc(
			"system_memory_usage_bytes",
			"Memory usage in bytes",
			nil, nil,
		),
		ioReadBytes: prometheus.NewDesc(
			"system_io_read_bytes",
			"Total I/O read bytes",
			nil, nil,
		),
		ioWriteBytes: prometheus.NewDesc(
			"system_io_write_bytes",
			"Total I/O write bytes",
			nil, nil,
		),
		ioReadOperations: prometheus.NewDesc(
			"system_io_read_operations",
			"Total I/O read operations",
			nil, nil,
		),
		ioWriteOperations: prometheus.NewDesc(
			"system_io_write_operations",
			"Total I/O write operations",
			nil, nil,
		),
		rxBytesPerSec: prometheus.NewDesc(
			"system_network_rx_bytes_per_second",
			"Network receive bytes per second",
			[]string{"interface"}, nil,
		),
		txBytesPerSec: prometheus.NewDesc(
			"system_network_tx_bytes_per_second",
			"Network transmit bytes per second",
			[]string{"interface"}, nil,
		),
		rxPacketsPerSec: prometheus.NewDesc(
			"system_network_rx_packets_per_second",
			"Network receive packets per second",
			[]string{"interface"}, nil,
		),
		txPacketsPerSec: prometheus.NewDesc(
			"system_network_tx_packets_per_second",
			"Network transmit packets per second",
			[]string{"interface"}, nil,
		),
		networkMonitor: NewNetworkMonitor(1 * time.Second),
	}
}

// ProcStats holds metrics read from /proc filesystem
type ProcStats struct {
	CPUUsage    uint64
	MemoryUsage uint64
}

// readProcStats reads basic system metrics from /proc filesystem
func readProcStats() (*ProcStats, error) {
	stats := &ProcStats{}

	procStat := "/proc/stat"
	if envPath := os.Getenv("PROC_STAT_PATH"); envPath != "" {
		procStat = envPath
	}

	// Read CPU usage from proc stat
	statContent, err := os.ReadFile(procStat)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/stat: %w", err)
	}
	cpuLine := strings.Split(string(statContent), "\n")[0]
	fields := strings.Fields(cpuLine)
	if len(fields) < 8 {
		return nil, fmt.Errorf("invalid /proc/stat format")
	}

	var total uint64
	for _, field := range fields[1:8] {
		val, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CPU value: %w", err)
		}
		total += val
	}
	stats.CPUUsage = total

	// Read memory usage from proc meminfo
	procMem := "/proc/meminfo"
	if envPath := os.Getenv("PROC_MEMINFO_PATH"); envPath != "" {
		procMem = envPath
	}

	memContent, err := os.ReadFile(procMem)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/meminfo: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(memContent)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		if fields[0] == "MemTotal:" {
			val, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse memory value: %w", err)
			}
			stats.MemoryUsage = val * 1024 // Convert from KB to bytes
			break
		}
	}

	return stats, nil
}

func (m *SystemMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.cpuUsage
	ch <- m.memUsage
	ch <- m.ioReadBytes
	ch <- m.ioWriteBytes
	ch <- m.ioReadOperations
	ch <- m.ioWriteOperations
	ch <- m.rxBytesPerSec
	ch <- m.txBytesPerSec
	ch <- m.rxPacketsPerSec
	ch <- m.txPacketsPerSec
}

func (m *SystemMetrics) Collect(ch chan<- prometheus.Metric) {
	// Validate cgroups setup with fallback strategies
	_validation := validation.ValidateCgroups()
	if !_validation.Available {
		log.Printf("Cgroups validation failed:")
		for _, err := range _validation.Errors {
			log.Printf("  - %s", err)
		}
		log.Printf("Cgroups stats:")
		for k, v := range _validation.Stats {
			log.Printf("  %s: %s", k, v)
		}

		// Check permissions and mount points
		log.Printf("Permissions:")
		for k, v := range _validation.Permissions {
			log.Printf("  %s: %v", k, v)
		}
		log.Printf("Mount points:")
		for k, v := range _validation.MountPoints {
			log.Printf("  %s: %s", k, v)
		}

		// Try alternative metric sources if cgroups unavailable
		if _validation.Version == 0 {
			log.Printf("Attempting to read metrics from /proc filesystem")
			if stats, err := readProcStats(); err == nil {
				// Use proc stats as fallback
				ch <- prometheus.MustNewConstMetric(
					m.cpuUsage,
					prometheus.GaugeValue,
					float64(stats.CPUUsage),
				)
				ch <- prometheus.MustNewConstMetric(
					m.memUsage,
					prometheus.GaugeValue,
					float64(stats.MemoryUsage),
				)
			} else {
				log.Printf("Failed to read proc stats: %v", err)
			}
		}
	}

	// Load cgroup controller
	log.Printf("Loading cgroup2 controller from /sys/fs/cgroup")
	cg, err := cgroup2.Load("/sys/fs/cgroup", nil)
	if err != nil {
		log.Printf("Error loading cgroup: %v", err)
		// Don't return - continue with other metrics
	} else {
		log.Printf("Successfully loaded cgroup controller")
		stats, err := cg.Stat()
		if err != nil {
			log.Printf("Error getting cgroup stats: %v", err)
		} else {
			log.Printf("Got cgroup stats: CPU=%v, Memory=%v, IO=%v",
				stats != nil && stats.CPU != nil,
				stats != nil && stats.Memory != nil,
				stats != nil && stats.Io != nil)

			// Validate CPU stats against raw file
			if rawCPU, ok := _validation.Stats["cpu.stat"]; ok {
				if parsedUsage, err := validation.ParseCPUStat(rawCPU); err == nil {
					log.Printf("Raw CPU usage: %d usec", parsedUsage)
				}
			}

			if stats != nil && stats.CPU != nil {
				log.Printf("Library CPU usage: %d usec", stats.CPU.UsageUsec)
				ch <- prometheus.MustNewConstMetric(
					m.cpuUsage,
					prometheus.GaugeValue,
					float64(stats.CPU.UsageUsec),
				)
			}

			if stats != nil && stats.Memory != nil {
				ch <- prometheus.MustNewConstMetric(
					m.memUsage,
					prometheus.GaugeValue,
					float64(stats.Memory.Usage),
				)
			}

			if stats != nil && stats.Io != nil {
				for _, entry := range stats.Io.Usage {
					ch <- prometheus.MustNewConstMetric(
						m.ioReadBytes,
						prometheus.CounterValue,
						float64(entry.Rbytes),
					)
					ch <- prometheus.MustNewConstMetric(
						m.ioWriteBytes,
						prometheus.CounterValue,
						float64(entry.Wbytes),
					)
					ch <- prometheus.MustNewConstMetric(
						m.ioReadOperations,
						prometheus.CounterValue,
						float64(entry.Rios),
					)
					ch <- prometheus.MustNewConstMetric(
						m.ioWriteOperations,
						prometheus.CounterValue,
						float64(entry.Wios),
					)
				}
			}

			usage, err := m.networkMonitor.GetUsage()
			if err != nil {
				log.Printf("Error getting network usage: %v", err)
				return
			}

			for _, u := range usage {
				ch <- prometheus.MustNewConstMetric(
					m.rxBytesPerSec,
					prometheus.GaugeValue,
					u.RxBytesPerSec,
					u.Interface,
				)
				ch <- prometheus.MustNewConstMetric(
					m.txBytesPerSec,
					prometheus.GaugeValue,
					u.TxBytesPerSec,
					u.Interface,
				)
				ch <- prometheus.MustNewConstMetric(
					m.rxPacketsPerSec,
					prometheus.GaugeValue,
					u.RxPacketsPerSec,
					u.Interface,
				)
				ch <- prometheus.MustNewConstMetric(
					m.txPacketsPerSec,
					prometheus.GaugeValue,
					u.TxPacketsPerSec,
					u.Interface,
				)
			}
		}
	}
}
