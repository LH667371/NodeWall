package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"nodewall/internal/nodeauth"
	"nodewall/internal/transporttls"
)

func enrollNode(managerURL, caFile, ticket string, credential nodeauth.Credential) error {
	tlsConfig, err := transporttls.ClientConfig(caFile, "", false)
	if err != nil {
		return err
	}
	data, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(managerURL, "/")+"/join/enroll", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ticket)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}, Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("enrollment redirects are not allowed")
	}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("enroll node: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("enroll node: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
