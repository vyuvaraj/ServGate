package proxy

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"sync"
)

// extractPrompt extracts prompt text from typical LLM JSON schemas
func extractPrompt(body []byte) string {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	// Case 1: Simple {"prompt": "..."}
	if prompt, ok := data["prompt"].(string); ok {
		return prompt
	}

	// Case 2: Chat format {"messages": [{"role": "user", "content": "..."}]}
	if messages, ok := data["messages"].([]interface{}); ok && len(messages) > 0 {
		if lastMsg, ok := messages[len(messages)-1].(map[string]interface{}); ok {
			if content, ok := lastMsg["content"].(string); ok {
				return content
			}
		}
	}

	return ""
}

// Prompt Guard Checker
var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore previous instructions`),
	regexp.MustCompile(`(?i)system prompt override`),
	regexp.MustCompile(`(?i)you are now in developer mode`),
	regexp.MustCompile(`(?i)jailbreak`),
}

func IsPromptInjection(prompt string) bool {
	for _, pattern := range injectionPatterns {
		if pattern.MatchString(prompt) {
			return true
		}
	}
	return false
}

// PII Redactor
var piiPatterns = map[string]*regexp.Regexp{
	"[REDACTED_EMAIL]": regexp.MustCompile(`(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	"[REDACTED_PHONE]": regexp.MustCompile(`\b(?:\+\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b`),
	"[REDACTED_SSN]":   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"[REDACTED_CARD]":  regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`),
}

func RedactPii(text string) string {
	for replacement, pattern := range piiPatterns {
		text = pattern.ReplaceAllString(text, replacement)
	}
	return text
}

// Semantic Cache Entry & Vector calculations
type CacheEntry struct {
	Prompt     string
	Response   []byte
	TermFreq   map[string]float64
	Magnitude  float64
}

type SemanticCache struct {
	mu        sync.RWMutex
	entries   []CacheEntry
	threshold float64
}

func NewSemanticCache(threshold float64) *SemanticCache {
	if threshold <= 0 {
		threshold = 0.85 // Default threshold
	}
	return &SemanticCache{
		threshold: threshold,
	}
}

func tokenize(text string) map[string]float64 {
	tf := make(map[string]float64)
	words := strings.Fields(strings.ToLower(text))
	for _, w := range words {
		w = strings.Trim(w, ".,!?;:()\"'")
		if len(w) > 0 {
			tf[w]++
		}
	}
	return tf
}

func getMagnitude(tf map[string]float64) float64 {
	var sum float64
	for _, v := range tf {
		sum += v * v
	}
	return math.Sqrt(sum)
}

func cosineSimilarity(tf1, tf2 map[string]float64, mag1, mag2 float64) float64 {
	if mag1 == 0 || mag2 == 0 {
		return 0
	}
	var dotProduct float64
	for k, v1 := range tf1 {
		if v2, ok := tf2[k]; ok {
			dotProduct += v1 * v2
		}
	}
	return dotProduct / (mag1 * mag2)
}

func (c *SemanticCache) Get(prompt string) ([]byte, bool) {
	tf := tokenize(prompt)
	mag := getMagnitude(tf)
	if mag == 0 {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, entry := range c.entries {
		sim := cosineSimilarity(tf, entry.TermFreq, mag, entry.Magnitude)
		if sim >= c.threshold {
			return entry.Response, true
		}
	}
	return nil, false
}

func (c *SemanticCache) Set(prompt string, response []byte) {
	tf := tokenize(prompt)
	mag := getMagnitude(tf)
	if mag == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = append(c.entries, CacheEntry{
		Prompt:    prompt,
		Response:  response,
		TermFreq:  tf,
		Magnitude: mag,
	})
}

type PromptABTest struct {
	PromptName string            `json:"prompt_name"`
	Versions   map[string]string `json:"versions"`
	Weights    map[string]int    `json:"weights"`
}

func SelectABPromptVersion(test PromptABTest, seed int) (string, string) {
	totalWeight := 0
	for _, w := range test.Weights {
		totalWeight += w
	}
	if totalWeight <= 0 {
		for v, tpl := range test.Versions {
			return v, tpl
		}
		return "", ""
	}

	val := seed % totalWeight
	current := 0
	for v, w := range test.Weights {
		current += w
		if val < current {
			return v, test.Versions[v]
		}
	}

	for v, tpl := range test.Versions {
		return v, tpl
	}
	return "", ""
}
