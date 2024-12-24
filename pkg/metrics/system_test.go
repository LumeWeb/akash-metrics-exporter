package metrics

import (
	"testing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
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
