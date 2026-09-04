package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"k-guard/internal/alert"
	"k-guard/internal/config"
	"k-guard/internal/dashboard"
	"k-guard/internal/dashboard/httpauth"
	kebpf "k-guard/internal/ebpf"
	k8s "k-guard/internal/k8s"
	"k-guard/internal/metrics"
	"k-guard/internal/processor"
	"k-guard/internal/safety"
)

// statusAdapter lets internal/dashboard depend on a small interface instead
// of importing internal/ebpf directly.
type statusAdapter struct{ mgr *kebpf.Manager }

type healthState struct {
	mu          sync.RWMutex
	lastEventAt time.Time
	lsmEnabled  bool
	sensors     []string
	started     time.Time
}

func (s statusAdapter) ActiveSensors() []string { return s.mgr.ActiveSensors() }
func (s statusAdapter) LSMEnabled() bool        { return s.mgr.LSMEnabled }

func buildInfo() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown (not built as a module)"
	}
	var commit, dirty, buildTime string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		case "vcs.time":
			buildTime = s.Value
		}
	}
	if commit == "" {
		return fmt.Sprintf("unknown revision (go %s)", bi.GoVersion)
	}
	short := commit
	if len(short) > 12 {
		short = short[:12]
	}
	return fmt.Sprintf("%s%s (built %s, go %s)", short, dirty, buildTime, bi.GoVersion)
}

func (h *healthState) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		resp := map[string]interface{}{
			"status":         "ok",
			"build":          buildInfo(),
			"uptime_seconds": int(time.Since(h.started).Seconds()),
			"lsm_enabled":    h.lsmEnabled,
			"active_sensors": h.sensors,
			"last_event_ago_seconds": func() interface{} {
				if h.lastEventAt.IsZero() {
					return nil
				}
				return int(time.Since(h.lastEventAt).Seconds())
			}(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func (h *healthState) touch() {
	h.mu.Lock()
	h.lastEventAt = time.Now()
	h.mu.Unlock()
}

func resolveToken(envVar, cfgVal string) string {
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return cfgVal
}

func main() {
	configPath := flag.String("config", "configs/rules.json", "path to the JSON rule/policy config file")
	checkOnly := flag.Bool("check", false, "validate the config file and exit (0 = valid, 1 = invalid), no eBPF/kernel interaction")
	showVersion := flag.Bool("version", false, "print version info and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("k-guard %s\n", buildInfo())
		os.Exit(0)
	}

	if *checkOnly {
		c, err := config.Load(*configPath)
		if err != nil {
			log.Printf("INVALID: %v", err)
			os.Exit(1)
		}
		log.Printf("OK: %s is valid (%d rules, %d allowlist entries, enforcement=%v)",
			*configPath, len(c.Rules), len(c.Allowlist), c.EnforcementEnabled)
		os.Exit(0)
	}

	log.Println("Initializing K-Guard...")

	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config %s: %v", *configPath, err)
	}
	stopWatch := make(chan struct{})
	cfgMgr.WatchPoll(5*time.Second, stopWatch)
	defer close(stopWatch)

	mgr, err := kebpf.NewManager()
	if err != nil {
		log.Fatalf("Failed to initialize eBPF: %v", err)
	}
	defer mgr.Close()

	health := &healthState{started: time.Now(), lsmEnabled: mgr.LSMEnabled, sensors: mgr.ActiveSensors()}

	guard := safety.NewGuard()

	metricsRegistry := metrics.NewRegistry()
	metricsRegistry.SetBuildInfo(buildInfo())
	dispatcher := alert.NewDispatcher()
	// We set a callback function if a sink Drops a Send
	dispatcher.OnDrop(metricsRegistry.IncSinkDrop)

	// Wire up alert sinks based on config
	cfg := cfgMgr.Current()

	// Wire up thek8s resolver
	k8sResolver := k8s.NewResolver(cfg.ProcPath, cfg.CgroupPath, cfg.KubeletURL, cfg.KubeletInsecure, cfg.KubeletCertFile, cfg.KubeletKeyFile)
	defer k8sResolver.Close()

	k8sResolver.SetOnContainerDiscovered(func(cgroupID uint64) {
		if err := mgr.AddContainerCgroup(cgroupID); err != nil {
			log.Printf("[main] failed to sync container cgroup %d to eBPF map: %v", cgroupID, err)
		}
	})

	if cfg.Sinks.Stdout {
		dispatcher.Register(alert.StdoutSink{})
	}
	if cfg.Sinks.Syslog {
		if s, err := alert.NewSyslogSink(); err != nil {
			log.Printf("[main] syslog sink disabled: %v", err)
		} else {
			dispatcher.Register(s)
		}
	}
	if cfg.Sinks.WebhookURL != "" {
		dispatcher.Register(alert.NewWebhookSink(cfg.Sinks.WebhookURL))
	}
	var store *alert.Store
	if cfg.Sinks.StorePath != "" {
		store, err = alert.NewStore(cfg.Sinks.StorePath)
		if err != nil {
			log.Printf("[main] persistent store disabled: %v", err)
		} else {
			dispatcher.Register(store)
			defer store.Close()
		}
	}

	var metricsSrv *http.Server
	if cfg.Sinks.MetricsListenAddr != "" {
		metricsToken := resolveToken("KGUARD_METRICS_TOKEN", cfg.Sinks.MetricsAuthToken)
		if metricsToken == "" {
			log.Printf("[metrics] WARNING: no auth token configured, metrics on %s are unauthenticated. "+
				"Set sinks.metrics_auth_token (or KGUARD_METRICS_TOKEN) or restrict %s to loopback/a trusted network.",
				cfg.Sinks.MetricsListenAddr, cfg.Sinks.MetricsListenAddr)
		}

		mux := http.NewServeMux()
		mux.Handle("/metrics", metricsRegistry.Handler())

		topMux := http.NewServeMux()
		topMux.HandleFunc("/healthz", health.Handler())
		topMux.Handle("/", httpauth.RequireBearer(metricsToken, mux))

		metricsSrv = &http.Server{
			Addr:              cfg.Sinks.MetricsListenAddr,
			Handler:           topMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			log.Printf("[metrics] listening on %s/metrics", cfg.Sinks.MetricsListenAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[metrics] server stopped: %v", err)
			}
		}()
	}

	var dashboardSrv *dashboard.Server
	if cfg.Sinks.DashboardListenAddr != "" {
		if store == nil {
			log.Printf("[main] dashboard requested but sinks.store_path is not set, dashboard needs the persistent store to show history, skipping dashboard")
		} else {
			dashboardToken := resolveToken("KGUARD_DASHBOARD_TOKEN", cfg.Sinks.DashboardAuthToken)
			dashboardSrv = dashboard.NewServer(cfg.Sinks.DashboardListenAddr, store, statusAdapter{mgr}, dashboardToken)
			dashboardSrv.Start()
		}
	}

	engine := processor.NewEngine(cfgMgr, guard, dispatcher, metricsRegistry, mgr, k8sResolver)
	router := processor.NewRouter(engine, metricsRegistry, cfgMgr)

	quit := make(chan bool)
	var wg sync.WaitGroup

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	reloadChan := make(chan os.Signal, 1)
	signal.Notify(reloadChan, syscall.SIGHUP)

	// GoRoutine to handle the reload of the config
	go func() {
		for range reloadChan {
			log.Println("[main] SIGHUP received, reloading config immediately")
			if err := cfgMgr.ReloadNow(); err != nil {
				log.Printf("[main] SIGHUP reload failed, keeping previous config: %v", err)
			}
		}
	}()

	log.Println("K-Guard is online. Press Ctrl+C to exit")
	if mgr.LSMEnabled {
		log.Println("Mode: PREVENTION (LSM pre-exec blocking active)")
	} else {
		log.Println("Mode: DETECTION ONLY (see startup warnings above for why blocked execs will still run to completion before K-Guard can react)")
	}

	// Main GoRoutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-quit:
				return
			default:
				record, err := mgr.Reader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) || strings.Contains(err.Error(), "file already closed") {
						return
					}
					metricsRegistry.IncRingbufDrop()
					log.Printf("Error reading ringbuf: %v", err)
					continue
				}
				health.touch()
				router.ProcessRawRecord(record.RawSample)
			}
		}
	}()

	<-stopChan
	log.Println("Shutting down K-Guard")

	close(quit)
	mgr.Reader.Close()
	wg.Wait()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("[metrics] graceful shutdown failed: %v", err)
		}
	}
	if dashboardSrv != nil {
		if err := dashboardSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("[dashboard] graceful shutdown failed: %v", err)
		}
	}

	dispatcher.Close()
}
