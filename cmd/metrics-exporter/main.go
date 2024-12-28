package main

import (
	"context"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.lumeweb.com/akash-metrics-exporter/pkg/metrics"
	etcdregistry "go.lumeweb.com/etcd-registry"
	"go.lumeweb.com/etcd-registry/types"
	"go.lumeweb.com/akash-metrics-exporter/pkg/logger"
	"go.lumeweb.com/akash-metrics-exporter/pkg/build"
	"net/http"
	"os"
	"os/signal"
	"runtime"
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
	healthCheckInterval = registrationTTL / 2

	// Metric names
	metricRegistrationStatus = "node_registration_status"
	metricRegistrationErrors = "node_registration_errors_total"
	metricLastRegistration   = "node_last_registration_timestamp"

	// Node status constants
	StatusStarting  = "starting"
	StatusHealthy   = "healthy"
	StatusDegraded  = "degraded"
	StatusShutdown  = "shutdown"
)

type App struct {
	registry    *etcdregistry.EtcdRegistry
	group       *types.ServiceGroup
	currentNode types.Node
	httpServer  *http.Server
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	regDone     <-chan struct{}
	regErrChan  <-chan error

	// Metrics
	regStatus      prometheus.Gauge
	regErrors      prometheus.Counter
	lastRegTime    prometheus.Gauge
}

func NewApp() *App {
	ctx, cancel := context.WithCancel(context.Background())
	
	app := &App{
		ctx:    ctx,
		cancel: cancel,
		
		// Initialize metrics
		regStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricRegistrationStatus,
			Help: "Current registration status (0=down, 1=up)",
		}),
		regErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricRegistrationErrors,
			Help: "Total number of registration errors",
		}),
		lastRegTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricLastRegistration,
			Help: "Timestamp of last successful registration",
		}),
	}

	// Register metrics
	prometheus.MustRegister(app.regStatus)
	prometheus.MustRegister(app.regErrors)
	prometheus.MustRegister(app.lastRegTime)

	return app
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
		3, // maxRetries for connection attempts
	)
	if err != nil {
		return fmt.Errorf("failed to create etcd registry: %w", err)
	}

	return nil
}

func (a *App) validateNodeInfo(node types.Node) error {
	if node.ID == "" {
		return fmt.Errorf("node ID is required")
	}
	if node.ExporterType == "" {
		return fmt.Errorf("exporter type is required") 
	}
	if node.Port <= 0 {
		return fmt.Errorf("port must be > 0")
	}
	if node.MetricsPath == "" {
		return fmt.Errorf("metrics path is required")
	}
	
	return nil
}

func (a *App) validateStatus(status string) bool {
	validStatuses := []string{
		StatusStarting,
		StatusHealthy,
		StatusDegraded,
		StatusShutdown,
	}
	for _, s := range validStatuses {
		if s == status {
			return true
		}
	}
	return false
}

func (a *App) updateNodeStatus(status string) error {
	if a.group == nil {
		return fmt.Errorf("no active service group")
	}

	if !a.validateStatus(status) {
		return fmt.Errorf("invalid status: %s", status)
	}
	
	a.currentNode.Status = status
	a.currentNode.LastSeen = time.Now()

	// Update metrics based on status
	if status == StatusHealthy {
		a.regStatus.Set(1)
		a.lastRegTime.Set(float64(time.Now().Unix()))
	} else if status == StatusDegraded || status == StatusShutdown {
		a.regStatus.Set(0)
	}
	
	done, errChan, err := a.group.RegisterNode(a.ctx, a.currentNode, registrationTTL)
	if err != nil {
		return fmt.Errorf("failed to update node status: %w", err)
	}
	
	a.regDone = done
	a.regErrChan = errChan
	return nil
}

func (a *App) startHealthCheck() {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(healthCheckInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				if err := a.updateNodeStatus(StatusHealthy); err != nil {
					logger.Log.Errorf("Health check failed: %v", err)
				}
			case <-a.ctx.Done():
				_ = a.updateNodeStatus(StatusShutdown)
				return
			}
		}
	}()
}

func (a *App) handleRegistrationFailure() error {
	logger.Log.Warn("Attempting registration recovery")
	
	if err := a.setupEtcdGroup(a.currentNode.Labels["service"]); err != nil {
		a.regErrors.Inc()
		return fmt.Errorf("recovery failed - group setup: %w", err)
	}
	
	a.currentNode.Status = StatusDegraded
	done, errChan, err := a.group.RegisterNode(a.ctx, a.currentNode, registrationTTL)
	if err != nil {
		return fmt.Errorf("recovery failed - registration: %w", err)
	}
	
	a.regDone = done
	a.regErrChan = errChan
	return nil
}

func (a *App) monitorRegistration() {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer logger.Log.Info("Registration monitor stopped")

		retryCount := 0
		maxRetries := 3

		for {
			select {
			case <-a.regDone:
				logger.Log.Info("Registration successful")
				retryCount = 0
				
			case err, ok := <-a.regErrChan:
				if !ok {
					return
				}
				if err != nil {
					retryCount++
					a.regErrors.Inc()
					logger.Log.Errorf("Registration error (attempt %d/%d): %v", 
						retryCount, maxRetries, err)
					
					if retryCount >= maxRetries {
						if err := a.handleRegistrationFailure(); err != nil {
							logger.Log.Errorf("Recovery failed: %v", err)
							return
						}
						retryCount = 0
					}
				}
				
			case <-a.ctx.Done():
				return
			}
		}
	}()
}

func (a *App) setupEtcdGroup(serviceName string) error {
	group, err := a.registry.CreateOrJoinServiceGroup(a.ctx, serviceName)
	if err != nil {
		return fmt.Errorf("failed to create/join service group: %w", err)
	}

	spec := types.ServiceGroupSpec{
		CommonLabels: map[string]string{
			"exporter_type": "node_exporter",
			"service":       serviceName,
			"os":           runtime.GOOS,
			"arch":         runtime.GOARCH,
		},
	}

	if err := group.Configure(spec); err != nil {
		return fmt.Errorf("failed to configure service group: %w", err)
	}

	a.group = group
	return nil
}

func (a *App) startRegistration(serviceName string, node types.Node) error {
	if err := a.validateNodeInfo(node); err != nil {
		return fmt.Errorf("invalid node info: %w", err)
	}

	a.currentNode = node

	if err := a.setupEtcdGroup(serviceName); err != nil {
		return fmt.Errorf("failed to setup etcd group: %w", err)
	}

	done, errChan, err := a.group.RegisterNode(a.ctx, node, registrationTTL)
	if err != nil {
		return fmt.Errorf("failed to start registration: %w", err)
	}

	a.regDone = done
	a.regErrChan = errChan

	// Start monitoring and health checks
	a.monitorRegistration()
	a.startHealthCheck()

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
    if a.cancel != nil {
        a.cancel()
    }

    // Create shutdown context
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
    defer shutdownCancel()

    // Shutdown HTTP server
    if a.httpServer != nil {
        if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
            logger.Log.Errorf("HTTP server shutdown error: %v", err)
        }
    }

    // Close etcd registry
    if a.registry != nil {
        if err := a.registry.Close(); err != nil {
            logger.Log.Errorf("Error closing etcd registry: %v", err)
        }
    }

    // Wait for all goroutines with timeout
    done := make(chan struct{})
    go func() {
        a.wg.Wait()
        close(done)
    }()

    select {
    case <-done:
        logger.Log.Info("All goroutines completed")
    case <-shutdownCtx.Done():
        logger.Log.Warn("Shutdown timed out waiting for goroutines")
    }

    logger.Log.Info("Shutdown complete")
}

func main() {
    maxStartupRetries := 5
    startupBackoff := time.Second * 5
    var lastErr error

    for attempt := 1; attempt <= maxStartupRetries; attempt++ {
        if err := runApp(); err != nil {
            lastErr = err
            logger.Log.Errorf("Startup attempt %d/%d failed: %v", 
                attempt, maxStartupRetries, err)
            
            if attempt < maxStartupRetries {
                logger.Log.Infof("Waiting %v before retry...", startupBackoff)
                time.Sleep(startupBackoff)
                // Exponential backoff
                startupBackoff *= 2
                continue
            }
            logger.Log.Fatalf("Failed to start after %d attempts. Last error: %v",
                maxStartupRetries, lastErr)
        }
        // If we get here, startup was successful
        return
    }
}

func runApp() error {
    app := NewApp()
    
    // Setup signal handling
    signals := make(chan os.Signal, 1)
    signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

    // Defer cleanup in case of error
    defer func() {
        signal.Stop(signals)
        app.shutdown()
    }()

    // Validate required env vars
    metricsPassword := os.Getenv("METRICS_PASSWORD")
    if metricsPassword == "" {
        return fmt.Errorf("METRICS_PASSWORD environment variable must be set")
    }

    // Setup etcd if enabled
    if err := app.setupEtcd(); err != nil {
        if app.registry != nil {
            if closeErr := app.registry.Close(); closeErr != nil {
                logger.Log.Errorf("Failed to close registry after setup error: %v", closeErr)
            }
            app.registry = nil
        }
        return fmt.Errorf("etcd setup failed: %w", err)
    }

    // Configure Prometheus metrics
    systemMetrics := metrics.NewSystemMetrics()
    prometheus.MustRegister(systemMetrics)

    // Start HTTP server
    if err := app.setupHTTP(metricsPassword); err != nil {
        return fmt.Errorf("HTTP server setup failed: %w", err)
    }

    // Start registration if etcd is enabled
    if app.registry != nil {
        serviceName := os.Getenv("METRICS_SERVICE_NAME")
        if serviceName == "" {
            return fmt.Errorf("METRICS_SERVICE_NAME environment variable must be set")
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

        node := types.Node{
            ID:           getSelfNodeName(akashIngressHost),
            ExporterType: "node_exporter",
            Port:         mustParseInt(registrationPort),
            MetricsPath:  "/metrics",
            Labels: map[string]string{
                "password":    metricsPassword,
                "address":     address,
                "version":     build.Version,
                "git_commit":  build.GitCommit,
            },
            Status:    StatusStarting,
            LastSeen:  time.Now(),
        }

        if err := app.startRegistration(serviceName, node); err != nil {
            return fmt.Errorf("registration failed: %w", err)
        }
    }

    // Wait for shutdown signal
    <-signals
    return nil
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

// Add helper function for port parsing
func mustParseInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		logger.Log.Fatalf("Failed to parse port number: %v", err)
	}
	return i
}

func getSelfNodeName(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return host
}
