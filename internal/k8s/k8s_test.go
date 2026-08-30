package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseCgroupPath(t *testing.T) {
	tests := []struct {
		name          string
		cgroupPath    string
		wantOK        bool
		wantContainer string
		wantPodUID    string
		wantRuntime   string
	}{
		{
			name:          "systemd containerd scope",
			cgroupPath:    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_9abc_def0_1234_56789abcdef0.slice/cri-containerd-a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e.scope",
			wantOK:        true,
			wantContainer: "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
			wantPodUID:    "12345678-9abc-def0-1234-56789abcdef0",
			wantRuntime:   "containerd",
		},
		{
			name:          "systemd crio scope",
			cgroupPath:    "/kubepods.slice/pod12345678-9abc-def0-1234-56789abcdef0/crio-11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff.scope",
			wantOK:        true,
			wantContainer: "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
			wantPodUID:    "12345678-9abc-def0-1234-56789abcdef0",
			wantRuntime:   "cri-o",
		},
		{
			name:          "raw cgroupfs hex container ID",
			cgroupPath:    "/docker/a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
			wantOK:        true,
			wantContainer: "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
			wantPodUID:    "",
			wantRuntime:   "docker",
		},
		{
			name:       "non-container host path",
			cgroupPath: "/user.slice/user-1000.slice/session-1.scope",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, ok := ParseCgroupPath(tt.cgroupPath)
			if ok != tt.wantOK {
				t.Fatalf("expected ok=%v, got %v", tt.wantOK, ok)
			}
			if !ok {
				return
			}
			if ctx.ContainerID != tt.wantContainer {
				t.Errorf("expected containerID %q, got %q", tt.wantContainer, ctx.ContainerID)
			}
			if ctx.PodUID != tt.wantPodUID {
				t.Errorf("expected podUID %q, got %q", tt.wantPodUID, ctx.PodUID)
			}
			if ctx.Runtime != tt.wantRuntime {
				t.Errorf("expected runtime %q, got %q", tt.wantRuntime, ctx.Runtime)
			}
		})
	}
}

func TestKubeletClient_SyncPodsAndLookup(t *testing.T) {
	mockPods := podList{
		Items: []struct {
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
		}{
			{
				Metadata: struct {
					UID       string `json:"uid"`
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				}{
					UID:       "pod-uid-1234",
					Name:      "nginx-pod",
					Namespace: "default",
				},
				Status: struct {
					ContainerStatuses []struct {
						ContainerID string `json:"containerID"`
					} `json:"containerStatuses"`
					InitContainerStatuses []struct {
						ContainerID string `json:"containerID"`
					} `json:"initContainerStatuses"`
					EphemeralContainerStatuses []struct {
						ContainerID string `json:"containerID"`
					} `json:"ephemeralContainerStatuses"`
				}{
					ContainerStatuses: []struct {
						ContainerID string `json:"containerID"`
					}{
						{ContainerID: "containerd://c1c2c3c4c5c6"},
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pods" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mockPods)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewKubeletClient(server.URL, true, "", "")
	err := client.SyncPods(context.Background())
	if err != nil {
		t.Fatalf("SyncPods failed: %v", err)
	}

	// Test Lookup by Pod UID
	name, ns, ok := client.Lookup("pod-uid-1234")
	if !ok || name != "nginx-pod" || ns != "default" {
		t.Errorf("pod UID lookup failed: got (%q, %q, %v)", name, ns, ok)
	}

	// Test Lookup by Container ID
	name, ns, podUID, runtime, ok := client.LookupByContainerID("c1c2c3c4c5c6")
	if !ok || name != "nginx-pod" || ns != "default" || podUID != "pod-uid-1234" || runtime != "containerd" {
		t.Errorf("container ID lookup failed: got (%q, %q, %q, %q, %v)", name, ns, podUID, runtime, ok)
	}
}

func TestResolver_ResolveFromProc(t *testing.T) {
	// Create temporary mock /proc structure
	tmpProc := t.TempDir()
	pid := uint32(9999)
	pidDir := filepath.Join(tmpProc, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatalf("failed to create temp pid dir: %v", err)
	}

	cgroupContent := "0::/kubepods.slice/kubepods-pod12345678_9abc_def0_1234_56789abcdef0.slice/cri-containerd-11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff.scope\n"
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0644); err != nil {
		t.Fatalf("failed to write mock cgroup file: %v", err)
	}

	// Mock Kubelet Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items": [{
				"metadata": {"uid": "12345678-9abc-def0-1234-56789abcdef0", "name": "api-server", "namespace": "prod"},
				"status": {
					"containerStatuses": [{"containerID": "containerd://11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"}]
				}
			}]
		}`))
	}))
	defer server.Close()

	resolver := NewResolver(tmpProc, t.TempDir(), server.URL, true, "", "")
	defer resolver.Close()

	ctx, ok := resolver.Resolve(1001, pid)
	if !ok {
		t.Fatalf("expected successful resolution")
	}

	if ctx.PodName != "api-server" || ctx.Namespace != "prod" {
		t.Errorf("unexpected enriched context: %+v", ctx)
	}
	if ctx.ContainerID != "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff" {
		t.Errorf("unexpected container ID: %s", ctx.ContainerID)
	}
}
