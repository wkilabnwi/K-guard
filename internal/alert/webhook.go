package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// WebhookSink POSTs a JSON body to a configured URL for every alert, works
// as-is against generic JSON accepting receivers; for Slack/Discord
// specifically you'd typically want to reshape the payload into their
// "blocks" format
type WebhookSink struct {
	url    string
	client *http.Client
}

func NewWebhookSink(url string) *WebhookSink {
	return &WebhookSink{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (WebhookSink) Name() string { return "webhook" }

type webhookPayload struct {
	Text  string `json:"text"`
	Alert Alert  `json:"alert"`
}

func (w *WebhookSink) Send(a Alert) {
	summary := fmt.Sprintf("[K-Guard] %s severity=%s action=%s comm=%s pid=%d path=%s",
		a.EventType, a.Severity, a.Action, a.Comm, a.Pid, a.Filename)

	if a.AncestorSuspicious {
		summary += fmt.Sprintf(" ancestor=%s", a.AncestorFilename)
	}

	body, err := json.Marshal(webhookPayload{Text: summary, Alert: a})
	if err != nil {
		log.Printf("[webhook] marshal error: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[webhook] request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		log.Printf("[webhook] delivery failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("[webhook] endpoint returned status %d", resp.StatusCode)
	}
}

// SlackSink sends formatted markdown alerts to Slack or Discord webhooks
type SlackSink struct {
	url    string
	client *http.Client
}

func NewSlackSink(url string) *SlackSink {
	return &SlackSink{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (SlackSink) Name() string { return "slack" }

type slackPayload struct {
	Text string `json:"text"`
}

func (s *SlackSink) Send(a Alert) {
	msg := fmt.Sprintf("*[K-Guard Alert]* `%s` | Severity: *%s* | Action: *%s*\n"+
		"> *Comm:* `%s` (PID: %d, UID: %d)\n"+
		"> *Path:* `%s`",
		a.EventType, a.Severity, a.Action, a.Comm, a.Pid, a.Uid, a.Filename)

	if a.PodName != "" {
		msg += fmt.Sprintf("\n> *K8s:* `%s/%s` (Container: `%s`)", a.Namespace, a.PodName, a.ContainerID)
	}

	body, err := json.Marshal(slackPayload{Text: msg})
	if err != nil {
		log.Printf("[slack] marshal error: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[slack] request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[slack] delivery failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("[slack] endpoint returned status %d", resp.StatusCode)
	}
}
