package k8s

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// podList represents the JSON returned by /pods
type podList struct {
	Items []struct {
		Metadata struct {
			UID       string `json:"uid"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	} `json:"items"`
}

// KubeletClient provides access to the local Kubelet API for
// syncing and looking up Kubernetes Pod metadata
type KubeletClient struct {
	client     *http.Client
	baseURL    string
	mu         sync.RWMutex
	podMetaMap map[string]struct{ Name, Namespace string }
}

// NewKubeletClient initializes client for the local Kubelet API
func NewKubeletClient(baseURL string, insecureSkipTLS bool) *KubeletClient {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:10255"
	}

	tr := &http.Transport{}
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: insecureSkipTLS,
		}
	}

	return &KubeletClient{
		client:     &http.Client{Timeout: 5 * time.Second, Transport: tr},
		baseURL:    baseURL,
		podMetaMap: make(map[string]struct{ Name, Namespace string }),
	}
}

// SyncPods fetches current pod list from local Kubelet API
func (k *KubeletClient) SyncPods(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", k.baseURL+"/pods", nil)
	if err != nil {
		return err
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kubelet api returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var pods podList
	if err := json.Unmarshal(body, &pods); err != nil {
		return err
	}

	newMap := make(map[string]struct{ Name, Namespace string })
	for _, p := range pods.Items {
		newMap[p.Metadata.UID] = struct{ Name, Namespace string }{
			Name:      p.Metadata.Name,
			Namespace: p.Metadata.Namespace,
		}
	}

	k.mu.Lock()
	k.podMetaMap = newMap
	k.mu.Unlock()

	return nil
}

func (k *KubeletClient) Lookup(podUID string) (string, string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	meta, ok := k.podMetaMap[podUID]
	if !ok {
		return "", "", false
	}
	return meta.Name, meta.Namespace, true
}
