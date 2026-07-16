package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayRouteChangelog(t *testing.T) {
	h := NewGatewayHandler([]Route{}, nil, "")

	// Inject routes to trigger changelog log entry
	routes1 := []Route{
		{Prefix: "/api/v1/users", Target: "http://backend-1"},
	}
	h.UpdateRoutes(routes1)

	routes2 := []Route{
		{Prefix: "/api/v1/users", Target: "http://backend-1"},
		{Prefix: "/api/v1/orders", Target: "http://backend-2"},
	}
	h.UpdateRoutes(routes2)

	routes3 := []Route{
		{Prefix: "/api/v1/orders", Target: "http://backend-2"},
	}
	h.UpdateRoutes(routes3)

	req := httptest.NewRequest("GET", "/api/v1/gateway/changelog", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var response struct {
		Changelog []string `json:"changelog"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(response.Changelog) < 3 {
		t.Fatalf("expected at least 3 changelog entries, got %d", len(response.Changelog))
	}
}
