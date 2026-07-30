package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type execHash struct {
	pid      uint32
	hex      string
	err      error
	computed bool
}

// Get for this Struct returns a Hex String for the pid present,
// it might happen that a process ends way too fast for us to get the
// actual hash so we just end up returning an error detailing what happened
func (h *execHash) get() (string, error) {
	if !h.computed {
		h.computed = true
		data, err := os.ReadFile("/proc/" + strconv.Itoa(int(h.pid)) + "/exe")
		if err != nil {
			h.err = fmt.Errorf("reading /proc/%d/exe: %w", h.pid, err)
		} else {
			sum := sha256.Sum256(data)
			h.hex = hex.EncodeToString(sum[:])
		}
	}
	return h.hex, h.err
}

// matchesSHA256 returns if the hash we want to block matches the one of the binary is trying to run
func matchesSHA256(h *execHash, wantHex string) (bool, error) {
	got, err := h.get()
	if err != nil {
		return false, err
	}
	return got == strings.ToLower(wantHex), nil
}
