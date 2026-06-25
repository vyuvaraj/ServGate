package proxy

import (
	"net/http"
	"sync"
)

// GoPlugin defines the interface that native Go middleware plugins must implement.
type GoPlugin interface {
	// OnRequest intercepts incoming requests. Returning a non-nil http.Response short-circuits the pipeline.
	OnRequest(r *http.Request) (*http.Response, error)
	// OnResponse intercepts or modifies outgoing responses before they are returned to the client.
	OnResponse(r *http.Request, w http.ResponseWriter, resp *http.Response) error
}

var (
	pluginsMu sync.RWMutex
	plugins   = make(map[string]GoPlugin)
)

// RegisterPlugin registers a native Go plugin under a specific name.
func RegisterPlugin(name string, p GoPlugin) {
	pluginsMu.Lock()
	defer pluginsMu.Unlock()
	plugins[name] = p
}

// GetPlugin retrieves a registered Go plugin by name.
func GetPlugin(name string) (GoPlugin, bool) {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}
