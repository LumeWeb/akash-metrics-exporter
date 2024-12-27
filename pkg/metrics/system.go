package metrics

import (
	"bufio"
	"fmt"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/prometheus/client_golang/prometheus"
	"go.lumeweb.com/akash-metrics-exporter/pkg/metrics/validation"
	"go.lumeweb.com/akash-metrics-exporter/pkg/logger"
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
		logger.Log.Warn("Cgroups validation failed:")
		for _, err := range _validation.Errors {
			logger.Log.Warnf("  - %s", err)
		}
		logger.Log.Info("Cgroups stats:")
		for k, v := range _validation.Stats {
			logger.Log.Infof("  %s: %s", k, v)
		}

		// Check permissions and mount points
		logger.Log.Info("Permissions:")
		for k, v := range _validation.Permissions {
			logger.Log.Infof("  %s: %v", k, v)
		}
		logger.Log.Info("Mount points:")
		for k, v := range _validation.MountPoints {
			logger.Log.Infof("  %s: %s", k, v)
		}

		// Try alternative metric sources if cgroups unavailable
		if _validation.Version == 0 {
			logger.Log.Info("Attempting to read metrics from /proc filesystem")
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
				logger.Log.Errorf("Failed to read proc stats: %v", err)
			}
		}
	}

	// Load cgroup controller with proper path and error handling
	logger.Log.Debug("Loading cgroup2 controller")
	
	// Get current cgroup path from /proc/self/cgroup
	selfCgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		logger.Log.Errorf("Error reading /proc/self/cgroup: %v", err)
		return
	}

	// Parse cgroup path, default to "/" if parsing fails
	cgroupPath := "/"
	if len(selfCgroup) > 0 {
		parts := strings.Split(strings.TrimSpace(string(selfCgroup)), ":")
		if len(parts) == 3 && len(parts[2]) > 0 {
			cgroupPath = parts[2]
		}
	}

	logger.Log.Debugf("Using cgroup path: %s", cgroupPath)
	cg, err := cgroup2.Load(cgroupPath, cgroup2.WithMountpoint("/sys/fs/cgroup"))
	if err != nil {
		logger.Log.Errorf("Error loading cgroup: %v", err)
		return
	}

	if cg == nil {
		logger.Log.Warn("Cgroup controller is nil after loading")
		return
	}

	logger.Log.Debug("Successfully loaded cgroup controller")
	stats, err := cg.Stat()
	if err != nil {
		logger.Log.Errorf("Error getting cgroup stats: %v", err)
		return
	}

	if stats == nil {
		logger.Log.Warn("Cgroup stats are nil")
		return
	}

	logger.Log.Debugf("Got cgroup stats: CPU=%v, Memory=%v, IO=%v",
		stats.CPU != nil,
		stats.Memory != nil,
		stats.Io != nil)

	if stats.CPU != nil {
		logger.Log.Debugf("Library CPU usage: %d usec", stats.CPU.UsageUsec)
		ch <- prometheus.MustNewConstMetric(
			m.cpuUsage,
			prometheus.GaugeValue,
			float64(stats.CPU.UsageUsec),
		)
	} else {
		logger.Log.Debug("CPU stats are nil")
	}

	if stats.Memory != nil {
		ch <- prometheus.MustNewConstMetric(
			m.memUsage,
			prometheus.GaugeValue,
			float64(stats.Memory.Usage),
		)
	} else {
		logger.Log.Debug("Memory stats are nil")
	}

	if stats.Io != nil && len(stats.Io.Usage) > 0 {
		for _, entry := range stats.Io.Usage {
			if entry == nil {
				continue
			}
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
		logger.Log.Errorf("Error getting network usage: %v", err)
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
