package main

import (
	"context"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.lumeweb.com/akash-metrics-exporter/pkg/metrics"
	etcdregistry "go.lumeweb.com/etcd-registry"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultPort          = 8080
	defaultEtcdTimeout   = 30 * time.Second
	registrationTTL      = 30 * time.Second
	shutdownTimeout      = 10 * time.Second
	registrationAttempts = 3
)

func basicAuthMiddleware(password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, providedPassword, ok := r.BasicAuth()
		if !ok || providedPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// Read environment variables
	etcdEndpoints := os.Getenv("ETCD_ENDPOINTS")
	etcdPrefix := os.Getenv("ETCD_PREFIX")
	etcdUsername := os.Getenv("ETCD_USERNAME")
	etcdPassword := os.Getenv("ETCD_PASSWORD")
	akashIngressHost := os.Getenv("AKASH_INGRESS_HOST")
	metricsPassword := os.Getenv("METRICS_PASSWORD")

	if metricsPassword == "" {
		log.Fatal("METRICS_PASSWORD environment variable must be set")
	}

	// Create waitgroup for graceful shutdown
	var wg sync.WaitGroup

	// Setup etcd registry if enabled
	var etcdRegistry *etcdregistry.EtcdRegistry
	if etcdEndpoints != "" {
		var err error
		etcdRegistry, err = etcdregistry.NewEtcdRegistry(
			strings.Split(etcdEndpoints, ","),
			etcdPrefix,
			etcdUsername,
			etcdPassword,
			defaultEtcdTimeout,
		)
		if err != nil {
			log.Fatalf("Failed to create etcd registry: %v", err)
		}
		defer func() {
			if err := etcdRegistry.Close(); err != nil {
				log.Printf("Error closing etcd registry: %v", err)
			}
		}()

		// Get configured metrics port and registration details
		metricsPort := os.Getenv("METRICS_PORT")
		if metricsPort == "" {
			metricsPort = strconv.Itoa(defaultPort)
		}

		registrationPort := metricsPort
		akashPortVar := fmt.Sprintf("AKASH_EXTERNAL_PORT_%s", metricsPort)
		if akashPort := os.Getenv(akashPortVar); akashPort != "" {
			log.Printf("Found Akash external port mapping: %s - will use for etcd registration", akashPort)
			registrationPort = akashPort
		}

		// Get service name
		serviceName := os.Getenv("METRICS_SERVICE_NAME")
		if serviceName == "" {
			log.Fatal("METRICS_SERVICE_NAME environment variable must be set")
		}

		// Create registration node
		address := fmt.Sprintf("http://%s:%s/metrics", akashIngressHost, registrationPort)
		node := etcdregistry.Node{
			Name: getSelfNodeName(akashIngressHost),
			Info: map[string]string{
				"port":     registrationPort,
				"address":  address,
				"password": metricsPassword,
			},
		}

		// Start registration in background
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := registerNode(ctx, etcdRegistry, serviceName, node); err != nil {
				log.Printf("Final registration error: %v", err)
			}
		}()
	} else {
		log.Println("ETCD support is disabled")
	}

	// Configure Prometheus metrics
	systemMetrics := metrics.NewSystemMetrics()
	prometheus.MustRegister(systemMetrics)

	// Configure HTTP server
	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = strconv.Itoa(defaultPort)
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", metricsPort),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Setup routes
	http.Handle("/metrics", basicAuthMiddleware(metricsPassword, promhttp.Handler()))

	// Start server in background
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("Starting server on port %s", metricsPort)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-signals
	log.Println("Shutdown signal received")

	// Create shutdown context
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Initiate graceful shutdown
	cancel() // Cancel main context
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("Shutdown complete")
}

// registerNode handles node registration with retry logic
func registerNode(ctx context.Context, registry *etcdregistry.EtcdRegistry, serviceName string, node etcdregistry.Node) error {
	done, errChan, err := registry.RegisterNode(ctx, serviceName, node, registrationTTL)
	if err != nil {
		return fmt.Errorf("failed to start registration: %w", err)
	}

	// Wait for initial registration
	select {
	case <-done:
		log.Println("Initial registration complete")
	case err := <-errChan:
		log.Printf("Initial registration error: %v", err)
	case <-ctx.Done():
		return ctx.Err()
	}

	// Monitor registration errors
	for {
		select {
		case err, ok := <-errChan:
			if !ok {
				return nil
			}
			log.Printf("Registration error: %v", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func getSelfNodeName(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return host
}
