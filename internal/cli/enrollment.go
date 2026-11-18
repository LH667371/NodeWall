package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"nodewall/internal/nodeauth"
	"nodewall/internal/transporttls"
)

func enrollNode(managerURL, caFile, ticket string, credential nodeauth.Credential) (nodeauth.Credential, error) {
	tlsConfig, err := transporttls.ClientConfig(caFile, "", false)
	if err != nil {
		return credential, err
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("enrollment redirects are not allowed")
	}}
	for attempt := 0; attempt < 2; attempt++ {
		data, err := json.Marshal(credential)
		if err != nil {
			return credential, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(managerURL, "/")+"/join/enroll", bytes.NewReader(data))
		if requestErr != nil {
			cancel()
			return credential, requestErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+ticket)
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			cancel()
			return credential, fmt.Errorf("enroll node: %w", requestErr)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			return credential, fmt.Errorf("read enrollment response: %w", readErr)
		}
		if resp.StatusCode == http.StatusCreated {
			return credential, nil
		}
		if resp.StatusCode == http.StatusConflict && attempt == 0 {
			var conflict struct {
				SuggestedNodeID string `json:"suggested_node_id"`
			}
			suggested := ""
			if json.Unmarshal(body, &conflict) == nil {
				suggested = strings.TrimSpace(conflict.SuggestedNodeID)
			}
			// Older managers returned only a plain-text 409. Keep those managers
			// compatible by deriving a deterministic host-specific replacement;
			// the enrollment ticket remains valid because the manager rejected the
			// first identity before consuming it.
			if suggested == "" {
				suggested = fallbackEnrollmentNodeID(credential.AgentURL)
			}
			if suggested != "" && suggested != strings.TrimSpace(credential.NodeID) {
				credential.NodeID = suggested
				continue
			}
		}
		return credential, fmt.Errorf("enroll node: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return credential, fmt.Errorf("enroll node: registration retry exhausted")
}

func fallbackEnrollmentNodeID(agentURL string) string {
	base := "node"
	if endpoint, err := url.Parse(strings.TrimSpace(agentURL)); err == nil && endpoint != nil {
		var builder strings.Builder
		for _, character := range strings.ToLower(endpoint.Hostname()) {
			switch {
			case character >= 'a' && character <= 'z', character >= '0' && character <= '9', character == '-', character == '_':
				builder.WriteRune(character)
			case builder.Len() > 0:
				builder.WriteByte('-')
			}
		}
		if value := strings.Trim(builder.String(), "-_"); value != "" {
			base = value
		}
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(agentURL)))
	return base + "-" + hex.EncodeToString(sum[:])[:8]
}
