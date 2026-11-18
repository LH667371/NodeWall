package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"nodewall/internal/nodeauth"
	"nodewall/internal/securestore"
)

// ClamAV only reads the replicated registry. Opening a second writable
// registry here would rotate/rewrite snapshots and race enrollment or standby
// recovery in the management process.
func clamAVPeers(path string) func() ([]nodeauth.Credential, error) {
	return func() ([]nodeauth.Credential, error) {
		var credentials map[string]nodeauth.Credential
		_, _, _, err := securestore.ReadValid(path, func(data []byte) error {
			return json.Unmarshal(data, &credentials)
		})
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read ClamAV enrolled peers: %w", err)
		}
		peers := make([]nodeauth.Credential, 0, len(credentials))
		for id, credential := range credentials {
			if credential.NodeID == id && id != "" && len(credential.Token) >= 32 && credential.Certificate != "" {
				peers = append(peers, credential)
			}
		}
		sort.Slice(peers, func(i, j int) bool { return peers[i].NodeID < peers[j].NodeID })
		return peers, nil
	}
}
