package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"k-guard/internal/alert"
	"k-guard/internal/audit"
	"k-guard/internal/config"
	"k-guard/internal/dashboard"
	"k-guard/internal/dashboard/httpauth"
	"k-guard/internal/dataset"
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
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
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

func runSupervisor(configPath string) {
	slog.Info("starting K-Guard supervisor process", "component", "supervisor")

	const maxRestarts = 5
	const windowDuration = 5 * time.Minute
	var restartTimestamps []time.Time

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		// Purge timestamps older than the 5 minute window
		now := time.Now()
		var validTimestamps []time.Time
		for _, t := range restartTimestamps {
			if now.Sub(t) < windowDuration {
				validTimestamps = append(validTimestamps, t)
			}
		}
		restartTimestamps = validTimestamps

		// Rate-limit check: Fail Open if crashing repeatedly
		if len(restartTimestamps) >= maxRestarts {
			slog.Error("EMERGENCY: worker crashed repeatedly within rate-limit window; failing open to preserve host stability",
				"component", "supervisor",
				"max_restarts", maxRestarts,
				"window", windowDuration,
			)
		}

		args := []string{"-config", configPath, "-child-worker"}
		cmd := exec.Command(os.Args[0], args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		if err := cmd.Start(); err != nil {
			slog.Error("failed to start child worker process", "component", "supervisor", "error", err)
			os.Exit(1)
		}

		slog.Info("spawned worker process", "component", "supervisor", "pid", cmd.Process.Pid)

		childDone := make(chan error, 1)
		go func() {
			childDone <- cmd.Wait()
		}()

		select {
		case sig := <-sigCh:
			slog.Info("forwarding signal to child worker", "component", "supervisor", "signal", sig, "pid", cmd.Process.Pid)
			if sig == syscall.SIGHUP {
				// Forward SIGHUP for hot-reload without restarting process
				_ = cmd.Process.Signal(syscall.SIGHUP)
				continue
			}
			// Graceful exit: forward signal and wait for child to unhook eBPF
			_ = cmd.Process.Signal(sig)
			<-childDone
			slog.Info("child process exited cleanly; supervisor shutting down", "component", "supervisor")
			return

		case err := <-childDone:
			restartTimestamps = append(restartTimestamps, time.Now())
			if err != nil {
				slog.Warn("worker process exited unexpectedly", "component", "supervisor", "pid", cmd.Process.Pid, "error", err)
			} else {
				slog.Info("worker process exited cleanly", "component", "supervisor", "pid", cmd.Process.Pid)
				return
			}
		}

		time.Sleep(1 * time.Second)
		slog.Info("restarting worker process...", "component", "supervisor")
	}
}

func processRecordSafely(r *processor.Router, raw []byte) {
	defer func() {
		if err := recover(); err != nil {
			slog.Error("EMERGENCY: recovered from event processing panic", "component", "main", "panic", err)
		}
	}()
	r.ProcessRawRecord(raw)
}

func main() {
	configPath := flag.String("config", "configs/rules.json", "path to the JSON rule/policy config file")
	checkOnly := flag.Bool("check", false, "validate the config file and exit (0 = valid, 1 = invalid), no eBPF/kernel interaction")
	showVersion := flag.Bool("version", false, "print version info and exit")
	testRuleExpr := flag.String("test-rule", "", "test a CEL expression against a mock JSON event")
	testRuleEvent := flag.String("test-event", "", "optional JSON string or path to JSON file containing mock event data")
	supervisorMode := flag.Bool("supervisor", false, "run in supervisor mode with automatic restart and crash-loop protection")
	childWorker := flag.Bool("child-worker", false, "internal flag: run as supervised worker process")
	convertSigmaPath := flag.String("convert-sigma", "", "path to a Sigma rule YAML file to transpile to K-Guard CEL rule format")
	flag.Parse()

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))

	if *convertSigmaPath != "" {
		rule, err := config.ConvertSigmaFile(*convertSigmaPath)
		if err != nil {
			slog.Error("Sigma conversion error", "error", err)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(rule); err != nil {
			slog.Error("failed to encode rule", "error", err)
		}
		os.Exit(0)
	}

	if *supervisorMode {
		runSupervisor(*configPath)
		return
	}

	if *childWorker {
		slog.Info("running under K-Guard supervisor protection", "mode", "worker")
	} else {
		slog.Info("running in standalone mode", "mode", "standalone")
	}

	if *showVersion {
		fmt.Printf("k-guard %s\n", buildInfo())
		os.Exit(0)
	}

	if *checkOnly {
		c, err := config.Load(*configPath)
		if err != nil {
			slog.Error("config validation failed", "path", *configPath, "error", err)
			os.Exit(1)
		}
		slog.Info("config is valid",
			"path", *configPath,
			"rules_count", len(c.Rules),
			"allowlist_count", len(c.Allowlist),
			"enforcement_enabled", c.EnforcementEnabled,
		)
		os.Exit(0)
	}

	if *testRuleExpr != "" {
		celEnv, err := config.GetCELEnvironment()
		if err != nil {
			slog.Error("failed to initialize CEL env", "error", err)
			os.Exit(1)
		}

		var mockData map[string]any
		if *testRuleEvent != "" {
			var rawBytes []byte
			if strings.HasPrefix(*testRuleEvent, "{") {
				rawBytes = []byte(*testRuleEvent)
			} else {
				rawBytes, err = os.ReadFile(*testRuleEvent)
				if err != nil {
					slog.Error("failed to read test-event file", "error", err)
					os.Exit(1)
				}
			}

			if err := json.Unmarshal(rawBytes, &mockData); err != nil {
				slog.Error("failed to parse test-event JSON", "error", err)
				os.Exit(1)
			}
		} else {
			mockData = processor.DefaultMockEvent()
		}

		res := processor.TestExpression(celEnv, *testRuleExpr, mockData)

		if !res.Valid {
			fmt.Printf("Compilation Error:\n%s\n", res.CompilationErr)
			os.Exit(1)
		}
		if res.EvalErr != "" {
			fmt.Printf("Evaluation Error:\n%s\n", res.EvalErr)
			os.Exit(1)
		}
		if res.Result {
			fmt.Println("Match: TRUE")
		} else {
			fmt.Println("No Match: FALSE")
		}
		os.Exit(0)
	}

	slog.Info("initializing K-Guard daemon...")

	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}
	stopWatch := make(chan struct{})
	cfgMgr.WatchPoll(5*time.Second, stopWatch)
	defer close(stopWatch)

	mgr, err := kebpf.NewManager()
	if err != nil {
		slog.Error("failed to initialize eBPF manager", "error", err)
		os.Exit(1)
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
			slog.Error("failed to sync container cgroup to eBPF map", "cgroup_id", cgroupID, "error", err)
		}
	})

	if cfg.Sinks.Stdout {
		dispatcher.Register(alert.StdoutSink{})
	}
	if cfg.Sinks.Syslog {
		if s, err := alert.NewSyslogSink(); err != nil {
			slog.Warn("syslog sink disabled", "error", err)
		} else {
			dispatcher.Register(s)
		}
	}
	if cfg.Sinks.WebhookURL != "" {
		dispatcher.Register(alert.NewWebhookSink(cfg.Sinks.WebhookURL))
	}
	if cfg.Sinks.SlackWebhookURL != "" {
		dispatcher.Register(alert.NewSlackSink(cfg.Sinks.SlackWebhookURL))
	}
	var store *alert.Store
	if cfg.Sinks.StorePath != "" {
		store, err = alert.NewStore(cfg.Sinks.StorePath)
		if err != nil {
			slog.Warn("persistent store disabled", "error", err)
		} else {
			dispatcher.Register(store)
			defer func() { _ = store.Close() }()
		}
	}

	var metricsSrv *http.Server
	if cfg.Sinks.MetricsListenAddr != "" {
		metricsToken := resolveToken("KGUARD_METRICS_TOKEN", cfg.Sinks.MetricsAuthToken)
		if metricsToken == "" {
			slog.Warn("unauthenticated metrics endpoint enabled", "listen_addr", cfg.Sinks.MetricsListenAddr)
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
			slog.Info("metrics HTTP listener started", "path", "/metrics", "listen_addr", cfg.Sinks.MetricsListenAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server stopped unexpectedly", "error", err)
			}
		}()
	}

	var dashboardSrv *dashboard.Server
	if cfg.Sinks.DashboardListenAddr != "" {
		if store == nil {
			slog.Warn("dashboard requested but sinks.store_path is not set; skipping dashboard startup")
		} else {
			dashboardToken := resolveToken("KGUARD_DASHBOARD_TOKEN", cfg.Sinks.DashboardAuthToken)
			dashboardSrv = dashboard.NewServer(cfg.Sinks.DashboardListenAddr, store, statusAdapter{mgr}, dashboardToken)
			dashboardSrv.Start()
		}
	}

	telemetryChan := make(chan processor.MLRecord, 10000)
	datasetPath := "/var/lib/kguard/telemetry.bin"
	if col, err := dataset.NewCollector(datasetPath); err != nil {
		slog.Warn("telemetry collector disabled", "error", err)
	} else {
		col.Start(telemetryChan)
		slog.Info("recording ML telemetry", "path", datasetPath)
	}

	var auditLogger *audit.Logger
	if cfg.Sinks.AuditLogPath != "" {
		al, err := audit.NewLogger(cfg.Sinks.AuditLogPath)
		if err != nil {
			slog.Warn("audit logger disabled", "error", err)
		} else {
			auditLogger = al
			defer func() { _ = auditLogger.Close() }()
			slog.Info("recording NDJSON audit trail", "path", cfg.Sinks.AuditLogPath)
		}
	}

	engine := processor.NewEngine(cfgMgr, guard, dispatcher, metricsRegistry, mgr, k8sResolver, auditLogger)
	router := processor.NewRouter(engine, metricsRegistry, cfgMgr, telemetryChan)

	quit := make(chan bool)
	var wg sync.WaitGroup

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	reloadChan := make(chan os.Signal, 1)
	signal.Notify(reloadChan, syscall.SIGHUP)

	// GoRoutine to handle the reload of the config
	go func() {
		for range reloadChan {
			slog.Info("SIGHUP received, triggering config reload")
			if err := cfgMgr.ReloadNow(); err != nil {
				slog.Error("SIGHUP reload failed, keeping active config", "error", err)
			}
		}
	}()

	// Background Memory Safety Valve Goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopWatch:
				return
			case <-ticker.C:
				currentCfg := cfgMgr.Current()
				if currentCfg.MaxMemoryMB == 0 {
					continue
				}
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				maxBytes := currentCfg.MaxMemoryMB * 1024 * 1024
				if m.Alloc > maxBytes {
					slog.Warn("memory safety limit exceeded, triggering GC",
						"current_mb", m.Alloc/(1024*1024),
						"max_mb", currentCfg.MaxMemoryMB,
					)
					runtime.GC()
				}
			}
		}
	}()

	slog.Info("K-Guard is online", "lsm_enabled", mgr.LSMEnabled)

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
					slog.Error("error reading eBPF ringbuffer sample", "error", err)
					continue
				}
				health.touch()
				processRecordSafely(router, record.RawSample)
			}
		}
	}()

	<-stopChan
	slog.Info("shutting down K-Guard daemon...")

	close(quit)
	_ = mgr.Reader.Close()
	wg.Wait()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful metrics server shutdown failed", "error", err)
		}
	}
	if dashboardSrv != nil {
		if err := dashboardSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("graceful dashboard server shutdown failed", "error", err)
		}
	}

	dispatcher.Close()
}
