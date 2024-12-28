package util

import (
	"context"
	"github.com/cenkalti/backoff/v5"
	"time"
)

// RetryConfig provides standard retry configurations
type RetryConfig struct {
	InitialInterval     time.Duration
	MaxInterval         time.Duration
	MaxElapsedTime      time.Duration
	RandomizationFactor float64
}

var (
	// ConnectionRetry is configured for etcd connection attempts
	ConnectionRetry = RetryConfig{
		InitialInterval:     2 * time.Second,
		MaxInterval:         30 * time.Second,
		RandomizationFactor: 0.2,
	}

	// GroupRetry is configured for etcd group operations
	GroupRetry = RetryConfig{
		InitialInterval:     2 * time.Second,
		MaxInterval:         30 * time.Second,
		RandomizationFactor: 0.2,
	}

	// StatusRetry is configured for node status updates
	StatusRetry = RetryConfig{
		InitialInterval:     1 * time.Second,
		MaxInterval:         15 * time.Second,
		RandomizationFactor: 0.2,
	}

	// RegistrationRetry is configured for service registration
	RegistrationRetry = RetryConfig{
		InitialInterval:     2 * time.Second,
		MaxInterval:         2 * time.Minute,
		RandomizationFactor: 0.2,
	}
)

// RetryOperation executes an operation with retry logic
func RetryOperation[T any](operation func() (T, error), config RetryConfig, maxRetries uint) (T, error) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = config.InitialInterval
	b.MaxInterval = config.MaxInterval
	b.RandomizationFactor = config.RandomizationFactor

	var result T
	ctx := context.Background()

	result, err := backoff.Retry(
		ctx,
		operation,
		backoff.WithMaxTries(maxRetries),
		backoff.WithBackOff(b),
	)

	return result, err
}
