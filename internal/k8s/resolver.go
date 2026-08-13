package k8s

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// ContainerContext holds resolved container and Kubernetes metadata.
type ContainerContext struct {
	CgroupID    uint64    `json:"cgroup_id,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
	PodUID      string    `json:"pod_uid,omitempty"`
	PodName     string    `json:"pod_name,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Runtime     string    `json:"runtime,omitempty"`
	ResolvedAt  time.Time `json:"resolved_at,omitempty"`
}

type Resolver struct {
	procPath    string
	cgroupPath  string
	cgroupCache *lruCache[uint64, ContainerContext]
	pidCache    *lruCache[uint32, ContainerContext]
	kubelet     *KubeletClient
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	sf          singleflight.Group
}

func NewResolver(procPath string, sysCgroupPath string, kubeletURL string) *Resolver {
	if procPath == "" {
		procPath = "/proc"
	}
	if sysCgroupPath == "" {
		sysCgroupPath = "/sys/fs/cgroup"
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &Resolver{
		procPath:    procPath,
		cgroupPath:  sysCgroupPath,
		cgroupCache: newLRUCache[uint64, ContainerContext](10000),
		pidCache:    newLRUCache[uint32, ContainerContext](10000),
		kubelet:     NewKubeletClient(kubeletURL, false),
		ctx:         ctx,
		cancel:      cancel,
	}

	r.wg.Add(1)

	// Start background Kubelet sync worker
	go r.startKubeletSync(30 * time.Second)

	return r
}

func (r *Resolver) Close() {
	r.cancel()
	r.wg.Wait()
}

func (r *Resolver) startKubeletSync(interval time.Duration) {

	defer r.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial Sync
	syncCtx, syncCancel := context.WithTimeout(r.ctx, 5*time.Second)
	_ = r.kubelet.SyncPods(syncCtx)
	syncCancel()

	for {
		select {
		case <-ticker.C:
			syncCtx, syncCancel := context.WithTimeout(r.ctx, 5*time.Second)
			_ = r.kubelet.SyncPods(syncCtx)
			syncCancel()
		case <-r.ctx.Done():
			return
		}
	}
}

// Resolve fetches K8s container metadata
func (r *Resolver) Resolve(cgroupID uint64, pid uint32) (ContainerContext, bool) {
	// Check CGroupID LRU Cache
	if cgroupID != 0 {
		if ctx, ok := r.cgroupCache.Get(cgroupID); ok {
			return r.enrichContext(ctx), true
		}
	}

	// Check PID LRU Cache
	if pid != 0 {
		if ctx, ok := r.pidCache.Get(pid); ok {
			return r.enrichContext(ctx), true
		}
	}

	key := fmt.Sprintf("%d:%d", cgroupID, pid)
	v, err, _ := r.sf.Do(key, func() (interface{}, error) {
		ctx, ok := r.doResolve(cgroupID, pid)
		if !ok {
			return nil, fmt.Errorf("unresolved")
		}
		return ctx, nil
	})
	if err != nil {
		return ContainerContext{}, false
	}
	return v.(ContainerContext), true
}

func (r *Resolver) doResolve(cgroupID uint64, pid uint32) (ContainerContext, bool) {
	var rawCgroupPath string
	var err error

	if pid != 0 {
		rawCgroupPath, err = r.getCgroupPathFromProc(pid)
	}

	if (err != nil || rawCgroupPath == "") && cgroupID != 0 {
		rawCgroupPath = r.findPathByCgroupID(cgroupID)
	}

	if rawCgroupPath == "" {
		return ContainerContext{}, false
	}

	ctx, ok := ParseCgroupPath(rawCgroupPath)
	if !ok {
		return ContainerContext{}, false
	}

	ctx.CgroupID = cgroupID
	ctx.ResolvedAt = time.Now()
	ctx = r.enrichContext(ctx)

	if cgroupID != 0 {
		r.cgroupCache.Add(cgroupID, ctx)
	}
	if pid != 0 {
		r.pidCache.Add(pid, ctx)
	}

	return ctx, true
}

func (r *Resolver) enrichContext(ctx ContainerContext) ContainerContext {
	if ctx.PodUID != "" && (ctx.PodName == "" || ctx.Namespace == "") {
		if name, ns, ok := r.kubelet.Lookup(ctx.PodUID); ok {
			ctx.PodName = name
			ctx.Namespace = ns
		}
	}
	return ctx
}
