package main

import (
	"context"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.lumeweb.com/akash-metrics-exporter/pkg/metrics"
	etcdregistry "go.lumeweb.com/etcd-registry"
	"go.lumeweb.com/akash-metrics-exporter/pkg/logger"
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
	defaultPort        = 8080
	defaultEtcdTimeout = 30 * time.Second
	registrationTTL    = 30 * time.Second
	shutdownTimeout    = 10 * time.Second
)

type App struct {
	registry    *etcdregistry.EtcdRegistry
	httpServer  *http.Server
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	regDone     <-chan struct{}
	regErrChan  <-chan error
}

func NewApp() *App {
	ctx, cancel := context.WithCancel(context.Background())
	return &App{
		ctx:    ctx,
		cancel: cancel,
	}
}

func (a *App) setupEtcd() error {
	etcdEndpoints := os.Getenv("ETCD_ENDPOINTS")
	if etcdEndpoints == "" {
		logger.Log.Info("ETCD support is disabled")
		return nil
	}

	var err error
	a.registry, err = etcdregistry.NewEtcdRegistry(
		strings.Split(etcdEndpoints, ","),
		os.Getenv("ETCD_PREFIX"),
		os.Getenv("ETCD_USERNAME"),
		os.Getenv("ETCD_PASSWORD"),
		defaultEtcdTimeout,
	)
	if err != nil {
		return fmt.Errorf("failed to create etcd registry: %w", err)
	}

	return nil
}

func (a *App) validateNodeInfo(node etcdregistry.Node) error {
	if node.Name == "" {
		return fmt.Errorf("node name is required")
	}
	
	required := []string{"port", "address", "password"}
	for _, field := range required {
		if _, ok := node.Info[field]; !ok {
			return fmt.Errorf("missing required node info field: %s", field)
		}
	}
	
	return nil
}

func (a *App) startRegistration(serviceName string, node etcdregistry.Node) error {
	if err := a.validateNodeInfo(node); err != nil {
		return fmt.Errorf("invalid node info: %w", err)
	}

	// Create registration context with timeout
	regCtx, regCancel := context.WithTimeout(a.ctx, defaultEtcdTimeout)
	defer regCancel()

	done, errChan, err := a.registry.RegisterNode(regCtx, serviceName, node, registrationTTL)
	if err != nil {
		return fmt.Errorf("failed to start registration: %w", err)
	}

	// Store channels for cleanup
	a.regDone = done
	a.regErrChan = errChan

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer logger.Log.Info("Registration goroutine stopped")

		// Wait for initial registration with timeout
		select {
		case <-done:
			logger.Log.Info("Initial registration complete")
		case err := <-errChan:
			logger.Log.Errorf("Initial registration error: %v", err)
		case <-regCtx.Done():
			logger.Log.Error("Initial registration timed out")
			return
		case <-a.ctx.Done():
			return
		}

		// Monitor registration errors
		for {
			select {
			case err, ok := <-errChan:
				if !ok {
					logger.Log.Info("Registration error channel closed")
					return
				}
				logger.Log.Errorf("Registration error: %v", err)
			case <-done:
				logger.Log.Info("Registration completed")
				return
			case <-a.ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (a *App) setupHTTP(metricsPassword string) error {
	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = strconv.Itoa(defaultPort)
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", basicAuthMiddleware(metricsPassword, promhttp.Handler()))

	a.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%s", metricsPort),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		logger.Log.Infof("Starting server on port %s", metricsPort)
		if err := a.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Log.Errorf("HTTP server error: %v", err)
		}
	}()

	return nil
}

func (a *App) shutdown() {
	logger.Log.Info("Starting graceful shutdown")

	// Cancel context to stop registration
	a.cancel()

	// Create shutdown context
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Shutdown HTTP server
	if a.httpServer != nil {
		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Log.Errorf("HTTP server shutdown error: %v", err)
		}
	}

	// Clean up registration
	if a.regDone != nil || a.regErrChan != nil {
		cleanupTimer := time.NewTimer(5 * time.Second)
		defer cleanupTimer.Stop()

		// Wait for registration to complete or timeout
		if a.regDone != nil {
			select {
			case <-a.regDone:
				logger.Log.Debug("Registration completed during shutdown")
			case <-cleanupTimer.C:
				logger.Log.Warn("Timeout waiting for registration completion")
			}
		}

		// Drain error channel
		if a.regErrChan != nil {
			for {
				select {
				case err, ok := <-a.regErrChan:
					if !ok {
						logger.Log.Debug("Registration error channel closed")
						goto cleanup
					}
					logger.Log.Debugf("Registration error during shutdown: %v", err)
				case <-cleanupTimer.C:
					logger.Log.Warn("Timeout draining registration error channel")
					goto cleanup
				}
			}
		}
	}

cleanup:
	// Close etcd registry
	if a.registry != nil {
		if err := a.registry.Close(); err != nil {
			logger.Log.Errorf("Error closing etcd registry: %v", err)
		}
	}

	// Wait for all goroutines
	a.wg.Wait()
	logger.Log.Info("Shutdown complete")
}

func main() {
	app := NewApp()

	// Setup signal handling
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// Validate required env vars
	metricsPassword := os.Getenv("METRICS_PASSWORD")
	if metricsPassword == "" {
		logger.Log.Fatal("METRICS_PASSWORD environment variable must be set")
	}

	// Setup etcd if enabled
	if err := app.setupEtcd(); err != nil {
		logger.Log.Fatal(err)
	}

	// Configure Prometheus metrics
	systemMetrics := metrics.NewSystemMetrics()
	prometheus.MustRegister(systemMetrics)

	// Start HTTP server
	if err := app.setupHTTP(metricsPassword); err != nil {
		logger.Log.Fatal(err)
	}

	// Start registration if etcd is enabled
	if app.registry != nil {
		serviceName := os.Getenv("METRICS_SERVICE_NAME")
		if serviceName == "" {
			logger.Log.Fatal("METRICS_SERVICE_NAME environment variable must be set")
		}

		metricsPort := os.Getenv("METRICS_PORT")
		if metricsPort == "" {
			metricsPort = strconv.Itoa(defaultPort)
		}

		// Handle Akash port mapping
		registrationPort := metricsPort
		akashPortVar := fmt.Sprintf("AKASH_EXTERNAL_PORT_%s", metricsPort)
		if akashPort := os.Getenv(akashPortVar); akashPort != "" {
			logger.Log.Infof("Found Akash external port mapping: %s - will use for etcd registration", akashPort)
			registrationPort = akashPort
		}

		akashIngressHost := os.Getenv("AKASH_INGRESS_HOST")
		address := fmt.Sprintf("http://%s:%s/metrics", akashIngressHost, registrationPort)

		node := etcdregistry.Node{
			Name: getSelfNodeName(akashIngressHost),
			Info: map[string]string{
				"port":     registrationPort,
				"address":  address,
				"password": metricsPassword,
			},
		}

		if err := app.startRegistration(serviceName, node); err != nil {
			logger.Log.Fatal(err)
		}
	}

	// Wait for shutdown signal
	<-signals
	app.shutdown()
}

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

func getSelfNodeName(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return host
}
