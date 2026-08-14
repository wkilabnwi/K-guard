package k8s

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"k-guard/internal/config"
	"log"
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
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"containerStatuses"`
			InitContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"initContainerStatuses"`
			EphemeralContainerStatuses []struct {
				ContainerID string `json:"containerID"`
			} `json:"ephemeralContainerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// KubeletClient provides access to the local Kubelet API for
// syncing and looking up Kubernetes Pod metadata
type KubeletClient struct {
	client            *http.Client
	baseURL           string
	certFile          string
	keyFile           string
	mu                sync.RWMutex
	podMetaMap        map[string]struct{ Name, Namespace string }
	containerToPodMap map[string]struct{ Name, Namespace, PodUID, Runtime string }
}

// NewKubeletClient initializes client for the local Kubelet API
func NewKubeletClient(baseURL string, insecureSkipTLS bool, certFile, keyFile string) *KubeletClient {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:10255"
	}

	tr := &http.Transport{}
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: insecureSkipTLS,
		}

		if certFile != "" && keyFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				log.Printf("k8s: failed to load kubelet client cert (%s, %s): %v; "+
					"proceeding without client cert, kubelet requests may be rejected", certFile, keyFile, err)
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		tr.TLSClientConfig = tlsConfig
	}

	return &KubeletClient{
		client:            &http.Client{Timeout: 5 * time.Second, Transport: tr},
		baseURL:           baseURL,
		podMetaMap:        make(map[string]struct{ Name, Namespace string }),
		containerToPodMap: make(map[string]struct{ Name, Namespace, PodUID, Runtime string }),
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

	newPodMap := make(map[string]struct{ Name, Namespace string })
	newContainerMap := make(map[string]struct{ Name, Namespace, PodUID, Runtime string })

	for _, p := range pods.Items {
		podUID := p.Metadata.UID
		podInfo := struct{ Name, Namespace string }{
			Name:      p.Metadata.Name,
			Namespace: p.Metadata.Namespace,
		}
		newPodMap[podUID] = podInfo

		indexContainer := func(rawID string) {
			if rawID == "" {
				return
			}
			cleanID := rawID
			runtime := "unknown"
			if idx := strings.Index(rawID, "://"); idx != -1 {
				runtime = rawID[:idx]
				cleanID = rawID[idx+3:]
			}
			newContainerMap[cleanID] = struct{ Name, Namespace, PodUID, Runtime string }{
				Name:      p.Metadata.Name,
				Namespace: p.Metadata.Namespace,
				PodUID:    podUID,
				Runtime:   runtime,
			}
		}

		for _, c := range p.Status.ContainerStatuses {
			indexContainer(c.ContainerID)
		}
		for _, c := range p.Status.InitContainerStatuses {
			indexContainer(c.ContainerID)
		}
		for _, c := range p.Status.EphemeralContainerStatuses {
			indexContainer(c.ContainerID)
		}
	}

	k.mu.Lock()
	k.podMetaMap = newPodMap
	k.containerToPodMap = newContainerMap
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

func (k *KubeletClient) LookupByContainerID(containerID string) (string, string, string, string, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	meta, ok := k.containerToPodMap[containerID]
	if !ok {
		return "", "", "", "", false
	}
	return meta.Name, meta.Namespace, meta.PodUID, meta.Runtime, true
}

func (k *KubeletClient) UpdateConfig(c *config.Config) {
	baseURL := c.KubeletURL
	if baseURL == "" {
		baseURL = "http://127.0.0.1:10255"
	}

	tr := &http.Transport{}
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.KubeletInsecure,
		}

		if c.KubeletCertFile != "" && c.KubeletKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(c.KubeletCertFile, c.KubeletKeyFile)
			if err != nil {
				log.Printf("k8s: failed to load kubelet client cert on reload (%s, %s): %v; "+
					"proceeding without client cert", c.KubeletCertFile, c.KubeletKeyFile, err)
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}

		tr.TLSClientConfig = tlsConfig
	}

	k.mu.Lock()
	k.baseURL = baseURL
	k.client.Transport = tr
	k.mu.Unlock()
}
