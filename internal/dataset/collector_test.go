package dataset

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k-guard/internal/processor"
)

func TestCollector_WriteAndReadMLRecords(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "telemetry.bin")

	collector, err := NewCollector(filePath)
	if err != nil {
		t.Fatalf("failed to create NewCollector: %v", err)
	}

	telemetryChan := make(chan processor.MLRecord, 10)
	collector.Start(telemetryChan)

	testRecords := []processor.MLRecord{
		{
			Timestamp: 10000001,
			ParentDev: 2049,
			ParentIno: 123456,
			ChildDev:  2049,
			ChildIno:  654321,
			CgroupID:  100,
			EventType: 1,
			UID:       1000,
		},
		{
			Timestamp: 10000002,
			ParentDev: 2049,
			ParentIno: 654321,
			ChildDev:  2049,
			ChildIno:  999999,
			CgroupID:  101,
			EventType: 1,
			UID:       0,
		},
	}

	for _, rec := range testRecords {
		telemetryChan <- rec
	}

	// Close channel to signal completion to background worker
	close(telemetryChan)

	// Wait briefly for the worker goroutine to finish flushing writes
	time.Sleep(50 * time.Millisecond)

	if err := collector.file.Close(); err != nil {
		t.Fatalf("failed to close collector file: %v", err)
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read binary dataset file: %v", err)
	}

	expectedSize := len(testRecords) * binary.Size(processor.MLRecord{})
	if len(content) != expectedSize {
		t.Fatalf("expected binary file size %d bytes, got %d", expectedSize, len(content))
	}

	reader := bytes.NewReader(content)
	for i, expected := range testRecords {
		var readRecord processor.MLRecord
		if err := binary.Read(reader, binary.LittleEndian, &readRecord); err != nil {
			t.Fatalf("failed to decode record #%d: %v", i, err)
		}

		if readRecord != expected {
			t.Errorf("record #%d mismatch:\nexpected: %+v\ngot:      %+v", i, expected, readRecord)
		}
	}
}

func TestNewCollector_InvalidPath(t *testing.T) {
	tmpDir := t.TempDir()
	invalidPath := filepath.Join(tmpDir, "nonexistent_dir", "sub", "telemetry.bin")

	_, err := NewCollector(invalidPath)
	if err == nil {
		t.Error("expected error creating collector in non-existent directory, got nil")
	}
}
