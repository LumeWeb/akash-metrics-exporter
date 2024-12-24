package metrics

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNewNetworkMonitor(t *testing.T) {
	monitor := NewNetworkMonitor(1 * time.Second)
	assert.NotNil(t, monitor.prevStats)
	assert.NotNil(t, monitor.interval)
	assert.Equal(t, 1*time.Second, monitor.interval)
}

func TestNewNetworkMonitorZeroInterval(t *testing.T) {
	monitor := NewNetworkMonitor(0)
	assert.Equal(t, 1*time.Second, monitor.interval, "Should default to 1 second for zero interval")
}

func TestGetUsage(t *testing.T) {
	monitor := NewNetworkMonitor(1 * time.Second)
	
	// First call should return empty usage
	usage, err := monitor.GetUsage()
	assert.NoError(t, err)
	assert.Empty(t, usage, "First call should return empty usage")

	// Second call should return actual usage
	time.Sleep(1 * time.Second)
	usage, err = monitor.GetUsage()
	assert.NoError(t, err)
	assert.NotEmpty(t, usage)

	// Verify usage fields
	for _, u := range usage {
		assert.NotEmpty(t, u.Interface)
		assert.GreaterOrEqual(t, u.RxBytesPerSec, float64(0))
		assert.GreaterOrEqual(t, u.TxBytesPerSec, float64(0))
		assert.GreaterOrEqual(t, u.RxPacketsPerSec, float64(0))
		assert.GreaterOrEqual(t, u.TxPacketsPerSec, float64(0))
	}
}

func TestGetNetworkStats(t *testing.T) {
	stats, err := getNetworkStats()
	assert.NoError(t, err)
	assert.NotNil(t, stats)

	// Verify stats fields
	for _, stat := range stats {
		assert.NotEmpty(t, stat.Interface)
		assert.GreaterOrEqual(t, stat.RxBytes, uint64(0))
		assert.GreaterOrEqual(t, stat.TxBytes, uint64(0))
		assert.GreaterOrEqual(t, stat.RxPackets, uint64(0))
		assert.GreaterOrEqual(t, stat.TxPackets, uint64(0))
	}
}

func TestInterfaceChanges(t *testing.T) {
	monitor := NewNetworkMonitor(1 * time.Second)
	
	// First call to initialize prevStats
	_, err := monitor.GetUsage()
	assert.NoError(t, err)

	// Get first real usage reading
	time.Sleep(1 * time.Second)
	usage1, err := monitor.GetUsage()
	assert.NoError(t, err)
	assert.NotEmpty(t, usage1, "Should have network usage data")

	// Get second usage reading
	time.Sleep(1 * time.Second)
	usage2, err := monitor.GetUsage()
	assert.NoError(t, err)
	assert.NotEmpty(t, usage2, "Should have network usage data")

	// Verify interfaces match between calls
	interfaces1 := make(map[string]bool)
	for _, u := range usage1 {
		interfaces1[u.Interface] = true
	}

	for _, u := range usage2 {
		assert.True(t, interfaces1[u.Interface], "Interface should exist in both readings")
	}
}
