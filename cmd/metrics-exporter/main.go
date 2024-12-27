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
	defaultPort        = 8080
	defaultEtcdTimeout = 30 * time.Second
	registrationTTL    = 30 * time.Second
	shutdownTimeout    = 10 * time.Second
)

type App struct {
	registry   *etcdregistry.EtcdRegistry
	httpServer *http.Server
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
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
		log.Println("ETCD support is disabled")
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

func (a *App) startRegistration(serviceName string, node etcdregistry.Node) error {
	done, errChan, err := a.registry.RegisterNode(a.ctx, serviceName, node, registrationTTL)
	if err != nil {
		return fmt.Errorf("failed to start registration: %w", err)
	}

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer log.Println("Registration goroutine stopped")

		// Wait for initial registration
		select {
		case <-done:
			log.Println("Initial registration complete")
		case err := <-errChan:
			log.Printf("Initial registration error: %v", err)
		case <-a.ctx.Done():
			return
		}

		// Monitor registration errors
		for {
			select {
			case err, ok := <-errChan:
				if !ok {
					return
				}
				log.Printf("Registration error: %v", err)
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
		log.Printf("Starting server on port %s", metricsPort)
		if err := a.httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	return nil
}

func (a *App) shutdown() {
	log.Println("Starting graceful shutdown")

	// Cancel context to stop registration
	a.cancel()

	// Create shutdown context
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Shutdown HTTP server
	if a.httpServer != nil {
		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}

	// Close etcd registry
	if a.registry != nil {
		if err := a.registry.Close(); err != nil {
			log.Printf("Error closing etcd registry: %v", err)
		}
	}

	// Wait for all goroutines
	a.wg.Wait()
	log.Println("Shutdown complete")
}

func main() {
	app := NewApp()

	// Setup signal handling
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// Validate required env vars
	metricsPassword := os.Getenv("METRICS_PASSWORD")
	if metricsPassword == "" {
		log.Fatal("METRICS_PASSWORD environment variable must be set")
	}

	// Setup etcd if enabled
	if err := app.setupEtcd(); err != nil {
		log.Fatal(err)
	}

	// Configure Prometheus metrics
	systemMetrics := metrics.NewSystemMetrics()
	prometheus.MustRegister(systemMetrics)

	// Start HTTP server
	if err := app.setupHTTP(metricsPassword); err != nil {
		log.Fatal(err)
	}

	// Start registration if etcd is enabled
	if app.registry != nil {
		serviceName := os.Getenv("METRICS_SERVICE_NAME")
		if serviceName == "" {
			log.Fatal("METRICS_SERVICE_NAME environment variable must be set")
		}

		metricsPort := os.Getenv("METRICS_PORT")
		if metricsPort == "" {
			metricsPort = strconv.Itoa(defaultPort)
		}

		// Handle Akash port mapping
		registrationPort := metricsPort
		akashPortVar := fmt.Sprintf("AKASH_EXTERNAL_PORT_%s", metricsPort)
		if akashPort := os.Getenv(akashPortVar); akashPort != "" {
			log.Printf("Found Akash external port mapping: %s - will use for etcd registration", akashPort)
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
			log.Fatal(err)
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
