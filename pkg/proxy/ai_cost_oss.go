package proxy

import (
	"os"
	"strconv"
)

// EstimateAICost calculates estimated cost based on prompt length and configured price per token.
func EstimateAICost(prompt string, routeCostPerToken float64) float64 {
	if prompt == "" {
		return 0.0
	}

	// 1 token ~= 4 characters as a standard LLM heuristic.
	tokens := float64(len(prompt)) / 4.0
	if tokens < 1.0 {
		tokens = 1.0
	}

	price := routeCostPerToken
	if price <= 0.0 {
		// Fallback to environment variable
		if envVal := os.Getenv("SERV_AI_COST_PER_TOKEN"); envVal != "" {
			if parsed, err := strconv.ParseFloat(envVal, 64); err == nil {
				price = parsed
			}
		}
	}

	if price <= 0.0 {
		// Defacto fallback default (e.g. $0.000002 per token for gpt-3.5-turbo class)
		price = 0.000002
	}

	return tokens * price
}
