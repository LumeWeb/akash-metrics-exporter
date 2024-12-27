package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestNewSystemMetrics(t *testing.T) {
	metrics := NewSystemMetrics()
	assert.NotNil(t, metrics.cpuUsage)
	assert.NotNil(t, metrics.memUsage)
	assert.NotNil(t, metrics.ioReadBytes)
	assert.NotNil(t, metrics.ioWriteBytes)
	assert.NotNil(t, metrics.ioReadOperations)
	assert.NotNil(t, metrics.ioWriteOperations)
	assert.NotNil(t, metrics.rxBytesPerSec)
	assert.NotNil(t, metrics.txBytesPerSec)
	assert.NotNil(t, metrics.rxPacketsPerSec)
	assert.NotNil(t, metrics.txPacketsPerSec)
	assert.NotNil(t, metrics.networkMonitor)
}

func TestDescribe(t *testing.T) {
	metrics := NewSystemMetrics()
	ch := make(chan *prometheus.Desc)
	go func() {
		metrics.Describe(ch)
		close(ch)
	}()
	for _, expected := range []*prometheus.Desc{
		metrics.cpuUsage,
		metrics.memUsage,
		metrics.ioReadBytes,
		metrics.ioWriteBytes,
		metrics.ioReadOperations,
		metrics.ioWriteOperations,
		metrics.rxBytesPerSec,
		metrics.txBytesPerSec,
		metrics.rxPacketsPerSec,
		metrics.txPacketsPerSec,
	} {
		actual := <-ch
		assert.Equal(t, expected, actual)
	}
}

func TestCollect(t *testing.T) {
	metrics := NewSystemMetrics()
	ch := make(chan prometheus.Metric)
	go func() {
		metrics.Collect(ch)
		close(ch)
	}()
	for range ch {
		// Just check that we get some metrics
	}
}

func TestReadProcStats(t *testing.T) {
	// Create temporary test files
	tmpDir := t.TempDir()

	// Test successful case
	err := os.WriteFile(tmpDir+"/stat", []byte("cpu  1234 2345 3456 4567 5678 6789 7890 8901\n"), 0644)
	assert.NoError(t, err)

	err = os.WriteFile(tmpDir+"/meminfo", []byte("MemTotal:     1024 kB\n"), 0644)
	assert.NoError(t, err)

	// Mock the file paths temporarily
	os.Setenv("PROC_STAT_PATH", tmpDir+"/stat")
	os.Setenv("PROC_MEMINFO_PATH", tmpDir+"/meminfo")
	defer func() {
		os.Unsetenv("PROC_STAT_PATH")
		os.Unsetenv("PROC_MEMINFO_PATH")
	}()

	// Test successful read
	stats, err := readProcStats()
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, uint64(40860), stats.CPUUsage)        // Sum of all CPU fields
	assert.Equal(t, uint64(1024*1024), stats.MemoryUsage) // 1024 KB converted to bytes

	// Test error cases
	// Invalid CPU format
	err = os.WriteFile(tmpDir+"/stat", []byte("invalid"), 0644)
	assert.NoError(t, err)
	stats, err = readProcStats()
	assert.Error(t, err)
	assert.Nil(t, stats)

	// Invalid memory format
	err = os.WriteFile(tmpDir+"/meminfo", []byte("invalid"), 0644)
	assert.NoError(t, err)
	stats, err = readProcStats()
	assert.Error(t, err)
	assert.Nil(t, stats)

	// Missing files
	os.Remove(tmpDir + "/stat")
	os.Remove(tmpDir + "/meminfo")
	stats, err = readProcStats()
	assert.Error(t, err)
	assert.Nil(t, stats)
}
