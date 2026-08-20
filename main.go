package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"k-guard/internal/alert"
	"k-guard/internal/config"
	"k-guard/internal/dashboard"
	kebpf "k-guard/internal/ebpf"
	k8s "k-guard/internal/k8s"
	"k-guard/internal/metrics"
	"k-guard/internal/processor"
	"k-guard/internal/safety"
)

// statusAdapter lets internal/dashboard depend on a small interface instead
// of importing internal/ebpf directly.
type statusAdapter struct{ mgr *kebpf.Manager }

func (s statusAdapter) ActiveSensors() []string { return s.mgr.ActiveSensors() }
func (s statusAdapter) LSMEnabled() bool        { return s.mgr.LSMEnabled }

func main() {
	configPath := flag.String("config", "configs/rules.json", "path to the JSON rule/policy config file")
	flag.Parse()

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

	guard := safety.NewGuard()

	metricsRegistry := metrics.NewRegistry()
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

	if cfg.Sinks.MetricsListenAddr != "" {
		go func() {
			log.Printf("[metrics] listening on %s/metrics", cfg.Sinks.MetricsListenAddr)
			mux := http.NewServeMux()
			mux.Handle("/metrics", metricsRegistry.Handler())
			if err := http.ListenAndServe(cfg.Sinks.MetricsListenAddr, mux); err != nil {
				log.Printf("[metrics] server stopped: %v", err)
			}
		}()
	}

	if cfg.Sinks.DashboardListenAddr != "" {
		if store == nil {
			log.Printf("[main] dashboard requested but sinks.store_path is not set, dashboard needs the persistent store to show history, skipping dashboard")
		} else {
			dashboard.NewServer(cfg.Sinks.DashboardListenAddr, store, statusAdapter{mgr}).Start()
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
				router.ProcessRawRecord(record.RawSample)
			}
		}
	}()

	<-stopChan
	log.Println("Shutting down K-Guard")

	close(quit)
	mgr.Reader.Close()
	wg.Wait()
	dispatcher.Close()
}
