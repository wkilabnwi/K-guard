package dataset

import (
	"encoding/binary"
	"os"
	"sync"

	"k-guard/internal/processor"
)

type Collector struct {
	file *os.File
	mu   sync.Mutex
}

func NewCollector(filePath string) (*Collector, error) {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &Collector{file: f}, nil
}

func (c *Collector) Start(telemetryChan <-chan processor.MLRecord) {
	go func() {
		for record := range telemetryChan {
			c.mu.Lock()
			_ = binary.Write(c.file, binary.LittleEndian, record)
			c.mu.Unlock()
		}
	}()
}
