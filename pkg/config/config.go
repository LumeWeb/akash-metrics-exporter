package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Target configuration
	TargetHost   string
	TargetPort   int
	TargetPath   string
	TargetScheme string // http or https

	// Registration configuration
	MetricsPort     int
	ExternalPort    int
	Password        string
	ServiceName     string
	ExporterType    string
	CustomLabels    map[string]string
	RegistrationTTL time.Duration
	RetryInterval   time.Duration

	// Optional settings
	RetryAttempts int
	RetryDelay    time.Duration

	// Network monitoring
	NetworkMonitorInterval time.Duration
}

// NewConfig creates a new configuration from environment variables
func NewConfig() (*Config, error) {
	cfg := &Config{
		TargetPath:             "/metrics",
		MetricsPort:            8080,
		RegistrationTTL:        15 * time.Minute,
		RetryInterval:          30 * time.Second,
		ExporterType:           "node_exporter",
		CustomLabels:           make(map[string]string),
		RetryAttempts:          3,
		RetryDelay:             5 * time.Second,
		TargetScheme:           "http",
		NetworkMonitorInterval: 1 * time.Second,
	}

	// Load from environment
	if port := os.Getenv("METRICS_PORT"); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid METRICS_PORT: %w", err)
		}
		cfg.MetricsPort = p
	}

	// Handle Akash port mapping
	akashPortVar := fmt.Sprintf("AKASH_EXTERNAL_PORT_%d", cfg.MetricsPort)
	if akashPort := os.Getenv(akashPortVar); akashPort != "" {
		p, err := strconv.Atoi(akashPort)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", akashPortVar, err)
		}
		cfg.ExternalPort = p
	}

	cfg.Password = os.Getenv("METRICS_PASSWORD")
	cfg.ServiceName = os.Getenv("METRICS_SERVICE_NAME")
	cfg.TargetHost = os.Getenv("AKASH_INGRESS_HOST")

	return cfg, nil
}

// GetEffectivePort returns the external port if set, otherwise the metrics port
func (c *Config) GetEffectivePort() int {
	if c.ExternalPort > 0 {
		return c.ExternalPort
	}
	return c.MetricsPort
}

// GetTargetURL constructs the full target URL using target port
func (c *Config) GetTargetURL() string {
	scheme := c.TargetScheme
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, c.TargetHost, c.TargetPort, c.TargetPath)
}

// GetAddress returns host:port using effective port
func (c *Config) GetAddress() string {
	return fmt.Sprintf("%s:%d", c.TargetHost, c.GetEffectivePort())
}
