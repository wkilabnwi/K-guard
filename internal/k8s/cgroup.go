package k8s

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var (
	// systemd/cgroupfs pod UID patterns
	podRegex = regexp.MustCompile(`\bpod([0-9a-fA-F_\-]{32,36})`)

	// systemd scope container naming conv
	containerScopeRegex = regexp.MustCompile(`(cri-containerd|crio|docker|libpod)-([0-9a-fA-F]{64})\.scope`)

	// fallback regex for raw 64 char hex container IDs in cgroupfs paths
	containerHexRegex = regexp.MustCompile(`[0-9a-fA-F]{64}`)
)

func getInode(info os.FileInfo) (uint64, bool) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino, true
	}
	return 0, false
}

// Inode Fallback for CgroupID to get Path Resolution when PID is dead
func (r *Resolver) findPathByCgroupID(cgroupID uint64) string {
	var foundPath string
	_ = filepath.WalkDir(r.cgroupPath, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if inode, ok := getInode(info); ok && inode == cgroupID {
			foundPath = strings.TrimPrefix(path, r.cgroupPath)
			return filepath.SkipAll
		}
		return nil
	})

	return foundPath
}

// Cgroup parsing for v1,v2 and subsystem
func (r *Resolver) getCgroupPathFromProc(pid uint32) (string, error) {
	filePath := filepath.Join(r.procPath, fmt.Sprintf("%d", pid), "cgroup")
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var fallbackCandidate string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[2] == "" || parts[2] == "/" {
			continue
		}

		cPath := parts[2]

		if parts[0] == "0" {
			return cPath, nil
		}

		if strings.Contains(cPath, "kubepods") ||
			strings.Contains(cPath, "docker") ||
			strings.Contains(cPath, "containerd") ||
			strings.Contains(cPath, "crio") {
			return cPath, nil
		}

		if fallbackCandidate == "" {
			fallbackCandidate = cPath
		}
	}

	if fallbackCandidate != "" {
		return fallbackCandidate, nil
	}

	return "", fmt.Errorf("no valid cgroup path found for pid %d", pid)
}

// ParseCgroupPath extracts runtime, container ID, and Pod UID
func ParseCgroupPath(cgroupPath string) (ContainerContext, bool) {
	var ctx ContainerContext

	// extract Pod UID
	if podMatch := podRegex.FindStringSubmatch(cgroupPath); len(podMatch) > 1 {
		rawUID := podMatch[1]
		if strings.Contains(rawUID, "_") {
			rawUID = strings.ReplaceAll(rawUID, "_", "-")
		}
		ctx.PodUID = rawUID
	}

	// extract Container ID and Runtime
	if scopeMatch := containerScopeRegex.FindStringSubmatch(cgroupPath); len(scopeMatch) > 2 {
		switch scopeMatch[1] {
		case "cri-containerd":
			ctx.Runtime = "containerd"
		case "crio":
			ctx.Runtime = "cri-o"
		case "docker":
			ctx.Runtime = "docker"
		case "libpod":
			ctx.Runtime = "podman"
		default:
			ctx.Runtime = scopeMatch[1]
		}
		ctx.ContainerID = scopeMatch[2]
		return ctx, true
	}

	if hexMatch := containerHexRegex.FindString(cgroupPath); hexMatch != "" {
		ctx.ContainerID = hexMatch
		switch {
		case strings.Contains(cgroupPath, "docker"):
			ctx.Runtime = "docker"
		case strings.Contains(cgroupPath, "crio"):
			ctx.Runtime = "cri-o"
		case strings.Contains(cgroupPath, "containerd"):
			ctx.Runtime = "containerd"
		default:
			ctx.Runtime = "unknown"
		}
		return ctx, true
	}

	return ctx, ctx.PodUID != ""
}
