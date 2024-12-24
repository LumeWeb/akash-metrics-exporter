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
	"strconv"
	"strings"
	"time"
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

const (
	defaultPort = 8080
)

func main() {
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

	// Check if etcd is enabled
	var etcdRegistry *etcdregistry.EtcdRegistry
	
	if etcdEndpoints == "" {
		log.Println("ETCD support is disabled")
	} else {
		// Create an EtcdRegistry instance
		var err error
		etcdRegistry, err = etcdregistry.NewEtcdRegistry(strings.Split(etcdEndpoints, ","), etcdPrefix, etcdUsername, etcdPassword, 10*time.Second)
		if err != nil {
			log.Fatal(err)
		}

		// Register the Prometheus instance with etcd
		node := etcdregistry.Node{
			Name: getSelfNodeName(akashIngressHost),
		}

		// Create a cancellable context for registration
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Get service name from environment variable
		serviceName := os.Getenv("METRICS_SERVICE_NAME")
		if serviceName == "" {
			log.Fatal("METRICS_SERVICE_NAME environment variable must be set")
		}

		// Register node with new API
		done, errChan, err := etcdRegistry.RegisterNode(ctx, serviceName, node, 10*time.Second)
		if err != nil {
			log.Fatal(err)
		}

		// Wait for initial registration
		select {
		case <-done:
			log.Println("Initial registration complete")
		case err := <-errChan:
			log.Printf("Registration error: %v", err)
			// Continue running even if registration fails
		}

		// Monitor registration errors in background
		go func() {
			for err := range errChan {
				log.Printf("Registration error: %v", err)
			}
		}()
	}

	// Configure Prometheus
	systemMetrics := metrics.NewSystemMetrics()
	prometheus.MustRegister(systemMetrics)

	// Get configured metrics port
	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = strconv.Itoa(defaultPort)
	}

	// Get external port for registration if running in Akash
	registrationPort := metricsPort
	akashPortVar := fmt.Sprintf("AKASH_EXTERNAL_PORT_%s", metricsPort)
	if akashPort := os.Getenv(akashPortVar); akashPort != "" {
		log.Printf("Found Akash external port mapping: %s - will use for etcd registration", akashPort)
		registrationPort = akashPort
	}

	if etcdEndpoints != "" {
		// Initialize node for etcd registration
		// Build base HTTP address with metrics path
		address := fmt.Sprintf("http://%s:%s/metrics", akashIngressHost, registrationPort)
		
		node := etcdregistry.Node{
			Name: getSelfNodeName(akashIngressHost),
			Info: map[string]string{
				"port": registrationPort,
				"address": address,
				"password": metricsPassword,
			},
		}

		// Create a cancellable context for registration
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Get service name from environment variable
		serviceName := os.Getenv("METRICS_SERVICE_NAME")
		if serviceName == "" {
			log.Fatal("METRICS_SERVICE_NAME environment variable must be set")
		}

		// Register node with new API
		done, errChan, err := etcdRegistry.RegisterNode(ctx, serviceName, node, 10*time.Second)
		if err != nil {
			log.Fatal(err)
		}

		// Wait for initial registration
		select {
		case <-done:
			log.Println("Initial registration complete")
		case err := <-errChan:
			log.Printf("Registration error: %v", err)
			// Continue running even if registration fails
		}

		// Monitor registration errors in background
		go func() {
			for err := range errChan {
				log.Printf("Registration error: %v", err)
			}
		}()
	}

	// Start HTTP server with basic auth on configured metrics port
	http.Handle("/metrics", basicAuthMiddleware(metricsPassword, promhttp.Handler()))
	log.Printf("Starting server on port %s", metricsPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", metricsPort), nil))
}

func getSelfNodeName(host string) string {
	// Extract the ID from the ingress host (everything before first dot)
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return host
}
