package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"servgate/pkg/wasm"
)

type ReplayRequest struct {
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
}

type ReplayStats struct {
	Total      int           `json:"total"`
	Successes  int           `json:"successes"`
	Failures   int           `json:"failures"`
	MinLatency time.Duration `json:"min_latency"`
	MaxLatency time.Duration `json:"max_latency"`
	AvgLatency time.Duration `json:"avg_latency"`
	P50Latency time.Duration `json:"p50_latency"`
	P90Latency time.Duration `json:"p90_latency"`
	P99Latency time.Duration `json:"p99_latency"`
}

func ReplayTraffic(ctx context.Context, logFilePath string, wasmBytes []byte) (*ReplayStats, error) {
	logFile, err := os.Open(logFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer logFile.Close()

	wasmManager, err := wasm.GetMiddlewareManager(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WASM manager: %w", err)
	}

	mwName := fmt.Sprintf("replay-temp-%d", time.Now().UnixNano())
	if err := wasmManager.Register(ctx, mwName, wasmBytes); err != nil {
		return nil, fmt.Errorf("failed to compile WASM: %w", err)
	}

	scanner := bufio.NewScanner(logFile)
	var latencies []time.Duration
	var successes, failures int

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req ReplayRequest
		if err := json.Unmarshal(line, &req); err != nil {
			failures++
			continue
		}

		body, err := base64.StdEncoding.DecodeString(req.BodyBase64)
		if err != nil {
			failures++
			continue
		}

		start := time.Now()
		_, err = wasmManager.Run(ctx, mwName, body)
		elapsed := time.Since(start)

		if err != nil {
			failures++
		} else {
			successes++
			latencies = append(latencies, elapsed)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading log file: %w", err)
	}

	total := successes + failures
	if total == 0 {
		return &ReplayStats{}, nil
	}

	stats := &ReplayStats{
		Total:     total,
		Successes: successes,
		Failures:  failures,
	}

	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		var sum time.Duration
		for _, lat := range latencies {
			sum += lat
		}

		stats.MinLatency = latencies[0]
		stats.MaxLatency = latencies[len(latencies)-1]
		stats.AvgLatency = sum / time.Duration(len(latencies))
		stats.P50Latency = latencies[len(latencies)*50/100]
		stats.P90Latency = latencies[len(latencies)*90/100]
		stats.P99Latency = latencies[len(latencies)*99/100]
	}

	return stats, nil
}
