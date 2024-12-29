package config

import (
    "fmt"
    "os"
    "strconv"
)

type Config struct {
    // Target configuration
    TargetHost string
    TargetPort int
    TargetPath string

    // Registration configuration 
    MetricsPort   int
    ExternalPort  int
    Password      string
    ServiceName   string
}

// NewConfig creates a new configuration from environment variables
func NewConfig() (*Config, error) {
    cfg := &Config{
        TargetPath:  "/metrics",
        MetricsPort: 8080,
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

// GetTargetURL constructs the full target URL
func (c *Config) GetTargetURL() string {
    return fmt.Sprintf("http://%s:%d%s", c.TargetHost, c.GetEffectivePort(), c.TargetPath)
}
