package otel

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Span struct {
	TraceID    string                 `json:"traceId"`
	SpanID     string                 `json:"spanId"`
	ParentID   string                 `json:"parentSpanId,omitempty"`
	Name       string                 `json:"name"`
	Kind       int                    `json:"kind"` // 2=Server, 3=Client
	StartTime  int64                  `json:"startTimeUnixNano"`
	EndTime    int64                  `json:"endTimeUnixNano"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Status     int                    `json:"status"` // 1=ok, 2=error
}

var (
	otelEnabled       bool
	otelEndpoint      string
	otelServiceName   string
	spanBuffer        []Span
	spanBufferMu      sync.Mutex
	spanFlushInterval = 5 * time.Second
	maxBatchSize      = 100
)

func Init() {
	endpoint := getOtelEndpoint()
	if endpoint == "" {
		return
	}

	otelEndpoint = strings.TrimSuffix(endpoint, "/")
	otelEnabled = true

	otelServiceName = os.Getenv("OTEL_SERVICE_NAME")
	if otelServiceName == "" {
		otelServiceName = "servgate"
	}

	go flushLoop()
}

func getOtelEndpoint() string {
	if ep := os.Getenv("OTEL_ENDPOINT"); ep != "" {
		return ep
	}
	if ep := os.Getenv("SERV_OTLP_ENDPOINT"); ep != "" {
		return ep
	}
	if raw := os.Getenv("SERVVERSE_DISCOVERY"); raw != "" {
		var manifest struct {
			OTLPEndpoint string `json:"otlp_endpoint"`
		}
		if json.Unmarshal([]byte(raw), &manifest) == nil {
			if manifest.OTLPEndpoint != "" {
				return manifest.OTLPEndpoint
			}
		} else {
			if data, err := os.ReadFile(raw); err == nil {
				if json.Unmarshal(data, &manifest) == nil && manifest.OTLPEndpoint != "" {
					return manifest.OTLPEndpoint
				}
			}
		}
	}
	return ""
}

func GenerateTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func GenerateSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func StartSpan(name string, parentTrace string) *Span {
	if !otelEnabled {
		return nil
	}

	traceID := ""
	parentSpan := ""
	if parentTrace != "" {
		parts := strings.Split(parentTrace, "-")
		if len(parts) >= 4 {
			traceID = parts[1]
			parentSpan = parts[2]
		}
	}

	if traceID == "" {
		traceID = GenerateTraceID()
	}

	return &Span{
		TraceID:   traceID,
		SpanID:    GenerateSpanID(),
		ParentID:  parentSpan,
		Name:      name,
		Kind:      2, // Server span by default
		StartTime: time.Now().UnixNano(),
	}
}

func EndSpan(span *Span, err error, attributes map[string]interface{}) {
	if !otelEnabled || span == nil {
		return
	}

	span.EndTime = time.Now().UnixNano()
	span.Status = 1
	if err != nil {
		span.Status = 2
		if attributes == nil {
			attributes = make(map[string]interface{})
		}
		attributes["error.message"] = err.Error()
	}
	span.Attributes = attributes

	spanBufferMu.Lock()
	spanBuffer = append(spanBuffer, *span)
	if len(spanBuffer) >= maxBatchSize {
		batch := spanBuffer
		spanBuffer = nil
		spanBufferMu.Unlock()
		go exportSpans(batch)
	} else {
		spanBufferMu.Unlock()
	}
}

func flushLoop() {
	ticker := time.NewTicker(spanFlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		spanBufferMu.Lock()
		if len(spanBuffer) == 0 {
			spanBufferMu.Unlock()
			continue
		}
		batch := spanBuffer
		spanBuffer = nil
		spanBufferMu.Unlock()

		exportSpans(batch)
	}
}

func exportSpans(spans []Span) {
	payload := map[string]interface{}{
		"resourceSpans": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": []map[string]interface{}{
						{"key": "service.name", "value": map[string]interface{}{"stringValue": otelServiceName}},
					},
				},
				"scopeSpans": []map[string]interface{}{
					{
						"scope": map[string]interface{}{"name": "servgate-gateway"},
						"spans": buildSpanPayload(spans),
					},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	url := otelEndpoint + "/v1/traces"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func buildSpanPayload(spans []Span) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(spans))
	for _, s := range spans {
		span := map[string]interface{}{
			"traceId":            s.TraceID,
			"spanId":             s.SpanID,
			"name":              s.Name,
			"kind":              s.Kind,
			"startTimeUnixNano": fmt.Sprintf("%d", s.StartTime),
			"endTimeUnixNano":   fmt.Sprintf("%d", s.EndTime),
			"status":            map[string]interface{}{"code": s.Status},
		}
		if s.ParentID != "" {
			span["parentSpanId"] = s.ParentID
		}
		if len(s.Attributes) > 0 {
			attrs := make([]map[string]interface{}, 0)
			for k, v := range s.Attributes {
				attrs = append(attrs, map[string]interface{}{
					"key":   k,
					"value": map[string]interface{}{"stringValue": fmt.Sprint(v)},
				})
			}
			span["attributes"] = attrs
		}
		result = append(result, span)
	}
	return result
}
