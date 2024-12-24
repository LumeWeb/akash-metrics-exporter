package metrics

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type NetStats struct {
	Interface string
	RxBytes   uint64
	RxPackets uint64
	TxBytes   uint64
	TxPackets uint64
}

func getNetworkStats() ([]NetStats, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("Error closing file: %v", err)
		}
	}(file)

	var stats []NetStats
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(strings.Replace(line, ":", " ", 1))

		if len(fields) < 17 {
			continue
		}

		rxBytes, _ := strconv.ParseUint(fields[1], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[2], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[9], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[10], 10, 64)

		stats = append(stats, NetStats{
			Interface: fields[0],
			RxBytes:   rxBytes,
			RxPackets: rxPackets,
			TxBytes:   txBytes,
			TxPackets: txPackets,
		})
	}

	return stats, scanner.Err()
}

type NetworkMonitor struct {
	prevStats map[string]NetStats
	interval  time.Duration
}

type NetworkUsage struct {
	Interface       string
	RxBytesPerSec   float64
	TxBytesPerSec   float64
	RxPacketsPerSec float64
	TxPacketsPerSec float64
}

func NewNetworkMonitor(interval time.Duration) *NetworkMonitor {
	if interval == 0 {
		interval = time.Second
	}
	return &NetworkMonitor{
		prevStats: make(map[string]NetStats),
		interval:  interval,
	}
}

func (nm *NetworkMonitor) GetUsage() ([]NetworkUsage, error) {
	currentStats, err := getNetworkStats()
	if err != nil {
		return nil, err
	}

	var usage []NetworkUsage

	for _, curr := range currentStats {
		if prev, exists := nm.prevStats[curr.Interface]; exists {
			deltaTime := float64(nm.interval.Seconds())
			usage = append(usage, NetworkUsage{
				Interface:       curr.Interface,
				RxBytesPerSec:   float64(curr.RxBytes-prev.RxBytes) / deltaTime,
				TxBytesPerSec:   float64(curr.TxBytes-prev.TxBytes) / deltaTime,
				RxPacketsPerSec: float64(curr.RxPackets-prev.RxPackets) / deltaTime,
				TxPacketsPerSec: float64(curr.TxPackets-prev.TxPackets) / deltaTime,
			})
		}
		nm.prevStats[curr.Interface] = curr
	}

	return usage, nil
}
