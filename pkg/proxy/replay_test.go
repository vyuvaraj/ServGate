package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReplayTraffic(t *testing.T) {
	// 1. Create a temporary log file containing requests
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "traffic.jsonl")

	requests := []ReplayRequest{
		{
			Method:     "POST",
			Path:       "/api/v1/orders",
			BodyBase64: base64.StdEncoding.EncodeToString([]byte("hello-wasm")),
		},
		{
			Method:     "GET",
			Path:       "/api/v1/limited",
			BodyBase64: base64.StdEncoding.EncodeToString([]byte("another-request")),
		},
	}

	file, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}

	for _, req := range requests {
		data, _ := json.Marshal(req)
		file.Write(data)
		file.Write([]byte("\n"))
	}
	file.Close()

	// 2. Static WASM bytecode with memory export, allocate() returning 0, and transform() incrementing each byte by 1
	wasmBytes := []byte{
		0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic & Version
		// Section 1: Type
		0x01, 0x0c, 0x02,
		0x60, 0x01, 0x7f, 0x01, 0x7f,       // Type 0: (i32) -> i32
		0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7e, // Type 1: (i32, i32) -> i64
		// Section 3: Function
		0x03, 0x03, 0x02, 0x00, 0x01,
		// Section 5: Memory
		0x05, 0x03, 0x01, 0x00, 0x01,
		// Section 7: Export
		0x07, 0x21, 0x03,
		0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
		0x08, 'a', 'l', 'l', 'o', 'c', 'a', 't', 'e', 0x00, 0x00,
		0x09, 't', 'r', 'a', 'n', 's', 'f', 'o', 'r', 'm', 0x00, 0x01,
		// Section 10: Code
		0x0a, 0x35, 0x02,
		// Body 0 (allocate)
		0x04, 0x00, 0x41, 0x00, 0x0b,
		// Body 1 (transform)
		46,
		0x01, 0x01, 0x7f,             // 1 local (i32)
		0x41, 0x00, 0x21, 0x02,       // i = 0
		0x02, 0x40,                   // block
		0x03, 0x40,                   // loop
		0x20, 0x02, 0x20, 0x01, 0x46, // i == size
		0x0d, 0x01,                   // br_if 1
		0x20, 0x02, 0x20, 0x02,       // address, address
		0x2d, 0x00, 0x00,             // i32.load8_u
		0x41, 0x01, 0x6a,             // + 1
		0x3a, 0x00, 0x00,             // i32.store8
		0x20, 0x02, 0x41, 0x01, 0x6a, 0x21, 0x02, // i++
		0x0c, 0x00,                   // br 0
		0x0b, 0x0b,                   // end loop, end block
		0x20, 0x01, 0xac, 0x0b,       // return size (as i64), end func
	}

	// 3. Run ReplayTraffic
	stats, err := ReplayTraffic(context.Background(), logPath, wasmBytes)
	if err != nil {
		t.Fatalf("ReplayTraffic failed: %v", err)
	}

	if stats.Total != 2 {
		t.Errorf("Expected total 2, got %d", stats.Total)
	}
	if stats.Successes != 2 {
		t.Errorf("Expected successes 2, got %d", stats.Successes)
	}
	if stats.Failures != 0 {
		t.Errorf("Expected failures 0, got %d", stats.Failures)
	}
}
