package runtime

import (
	"testing"

	"nodewall/internal/config"
)

func TestManagerHTTPURLUsesCurrentWebPort(t *testing.T) {
	got := managerHTTPURL(config.ServerConfig{
		ListenAddr: "192.168.201.17:8086",
		AgentURL:   "https://192.168.201.17:9080",
		TLSEnabled: true,
	})
	if got != "https://192.168.201.17:8086" {
		t.Fatalf("managerHTTPURL() = %q", got)
	}
}
