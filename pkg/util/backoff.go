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
		InitialInterval:     5 * time.Second,
		MaxInterval:         2 * time.Minute,
		RandomizationFactor: 0.1,
	}

	// GroupRetry is configured for etcd group operations
	GroupRetry = RetryConfig{
		InitialInterval:     5 * time.Second,
		MaxInterval:         2 * time.Minute,
		RandomizationFactor: 0.1,
	}

	// StatusRetry is configured for node status updates
	StatusRetry = RetryConfig{
		InitialInterval:     5 * time.Second,
		MaxInterval:         1 * time.Minute,
		RandomizationFactor: 0.1,
	}

	// RegistrationRetry is configured for service registration
	RegistrationRetry = RetryConfig{
		InitialInterval:     10 * time.Second,
		MaxInterval:         5 * time.Minute,
		RandomizationFactor: 0.1,
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
