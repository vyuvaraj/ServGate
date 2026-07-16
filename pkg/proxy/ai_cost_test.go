package proxy

import (
	"testing"
)

func TestEstimateAICost(t *testing.T) {
	prompt := "Hello, this is a test prompt." // 29 chars -> ~7.25 tokens
	
	// Test route-level cost override
	cost := EstimateAICost(prompt, 0.001)
	expected := (29.0 / 4.0) * 0.001
	if cost != expected {
		t.Errorf("expected cost %v, got %v", expected, cost)
	}

	// Test empty prompt
	if costEmpty := EstimateAICost("", 0.001); costEmpty != 0.0 {
		t.Errorf("expected 0 cost for empty prompt, got %v", costEmpty)
	}
}
