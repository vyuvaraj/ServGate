package proxy

import (
	"testing"
)

func BenchmarkRateLimiterAllow(b *testing.B) {
	h := &GatewayHandler{
		ratLimiters: make(map[string]*rateLimiter),
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = h.isRateLimited("127.0.0.1", "/api/resource", 1000000)
		}
	})
}
