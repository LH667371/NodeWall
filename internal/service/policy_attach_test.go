package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"nodewall/internal/models"
	"nodewall/internal/store"
)

func TestAttachUsesAgentsNegotiatedModeAndOriginalBaseline(t *testing.T) {
	for _, test := range []struct {
		name, response string
		attached       bool
	}{
		{"generic selected by agent", `{"attach_mode":"generic","previously_attached":false}`, false},
		{"existing native attachment", `{"attach_mode":"native","previously_attached":true}`, true},
		{"explicit legacy backend", `{"attach_mode":"iptables","previously_attached":false}`, false},
		{"older agent response", `{"attached":true}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/interfaces/eno3/attach" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				_, _ = io.WriteString(w, test.response)
			}))
			defer agent.Close()
			svc := NewPolicyService(store.New())
			attached, err := svc.attachInterface(t.Context(), models.Node{AgentURL: agent.URL}, "eno3")
			if err != nil || attached != test.attached || calls.Load() != 1 {
				t.Fatalf("attached=%t calls=%d error=%v", attached, calls.Load(), err)
			}
		})
	}
}

func TestAttachDoesNotReplayRejectedMutation(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"error":"agent attach failed"}`)
			}))
			defer agent.Close()
			svc := NewPolicyService(store.New())
			_, err := svc.attachInterface(t.Context(), models.Node{AgentURL: agent.URL}, "eno3")
			if err == nil || !strings.Contains(err.Error(), "agent attach failed") || calls.Load() != 1 {
				t.Fatalf("calls=%d error=%v", calls.Load(), err)
			}
		})
	}
}

type attachRoundTripper func(*http.Request) (*http.Response, error)

func (f attachRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAttachDoesNotReplayAfterUncertainTransportFailure(t *testing.T) {
	for _, failure := range []error{io.ErrUnexpectedEOF, context.DeadlineExceeded, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			var calls atomic.Int32
			svc := NewPolicyService(store.New())
			svc.SetHTTPClient(&http.Client{Transport: attachRoundTripper(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, failure
			})})
			_, err := svc.attachInterface(t.Context(), models.Node{AgentURL: "https://agent.invalid"}, "eno3")
			if !errors.Is(err, failure) || calls.Load() != 1 {
				t.Fatalf("calls=%d error=%v", calls.Load(), err)
			}
		})
	}
}
