// Package dashboard serves a minimal read-only web UI for browsing recent
// alerts and sensor health, using only stdlib (net/http + html/template)
// no frontend framework/build step needed for something this simple.
package dashboard

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"time"

	"k-guard/internal/alert"
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
	store  *alert.Store
	status StatusProvider
	addr   string
}

func NewServer(addr string, store *alert.Store, status StatusProvider) *Server {
	return &Server{addr: addr, store: store, status: status}
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/alerts", s.handleAlertsJSON)

	go func() {
		log.Printf("[dashboard] listening on %s", s.addr)
		if err := http.ListenAndServe(s.addr, mux); err != nil {
			log.Printf("[dashboard] stopped: %v", err)
		}
	}()
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
