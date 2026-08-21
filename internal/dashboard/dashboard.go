// Package dashboard serves a minimal read-only web UI for browsing recent
// alerts and sensor health, using only stdlib (net/http + html/template)
// no frontend framework/build step needed for something this simple.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"k-guard/internal/alert"
	"k-guard/internal/dashboard/httpauth"
)

// templatesFS embeds the dashboard's HTML template so it ships inside the
// compiled binary
//
//go:embed index.html.tmpl
var templatesFS embed.FS

var pageTmpl = template.Must(template.New("index.html.tmpl").Funcs(template.FuncMap{
	"fmtTime": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
}).ParseFS(templatesFS, "index.html.tmpl"))

// StatusProvider is implemented by whatever owns runtime sensor state
type StatusProvider interface {
	ActiveSensors() []string
	LSMEnabled() bool
}

type Server struct {
	store     *alert.Store
	status    StatusProvider
	addr      string
	authToken string
	httpSrv   *http.Server
}

func NewServer(addr string, store *alert.Store, status StatusProvider, authToken string) *Server {
	if authToken == "" {
		log.Printf("[dashboard] WARNING: no auth token configured, dashboard on %s is unauthenticated. "+
			"Set sinks.dashboard_auth_token (or KGUARD_DASHBOARD_TOKEN) or restrict %s to loopback/a trusted network.", addr, addr)
	}
	return &Server{addr: addr, store: store, status: status, authToken: authToken}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/alerts", s.handleAlertsJSON)

	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           httpauth.RequireBearer(s.authToken, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("[dashboard] listening on %s", s.addr)
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[dashboard] stopped: %v", err)
		}
	}()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

type pageData struct {
	Alerts     []alert.Alert
	Sensors    []string
	LSMEnabled bool
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.store.Recent(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// newest first for display
	for i, j := 0, len(alerts)-1; i < j; i, j = i+1, j-1 {
		alerts[i], alerts[j] = alerts[j], alerts[i]
	}

	data := pageData{Alerts: alerts}
	if s.status != nil {
		data.Sensors = s.status.ActiveSensors()
		data.LSMEnabled = s.status.LSMEnabled()
	}

	if err := pageTmpl.Execute(w, data); err != nil {
		log.Printf("[dashboard] template error: %v", err)
	}
}

func (s *Server) handleAlertsJSON(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.store.Recent(500)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(alerts)
}
