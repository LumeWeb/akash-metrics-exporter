package metrics

import (
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/prometheus/client_golang/prometheus"
	"log"
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
	cg, err := cgroup2.Load("/", nil)
	if err != nil {
		log.Printf("Error loading cgroup: %v", err)
		return
	}

	stats, err := cg.Stat()
	if err != nil {
		log.Printf("Error getting cgroup stats: %v", err)
		return
	}

	if stats.CPU != nil {
		ch <- prometheus.MustNewConstMetric(
			m.cpuUsage,
			prometheus.GaugeValue,
			float64(stats.CPU.UsageUsec),
		)
	}

	if stats.Memory != nil {
		ch <- prometheus.MustNewConstMetric(
			m.memUsage,
			prometheus.GaugeValue,
			float64(stats.Memory.Usage),
		)
	}

	if stats.Io != nil {
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
