package api

import (
	"strings"
	"testing"
	"time"
)

func TestEmailChallengeCooldownAndSingleUse(t *testing.T) {
	manager := &authManager{emailChallenges: make(map[string]emailChallenge)}
	requestID, code, err := manager.createEmailChallenge("admin", "admin@example.test", "password-reset")
	if err != nil {
		t.Fatalf("create email challenge: %v", err)
	}
	if _, _, err := manager.createEmailChallenge("admin", "admin@example.test", "password-reset"); err == nil || !strings.Contains(err.Error(), "temporarily") {
		t.Fatalf("expected per-user email cooldown, got %v", err)
	}
	if _, ok := manager.consumeEmailChallenge(" "+requestID+" ", "wrong", "password-reset"); ok {
		t.Fatal("wrong email code must not be accepted")
	}
	if challenge, ok := manager.consumeEmailChallenge(requestID, code, "password-reset", "other-user"); ok || challenge.Username != "" {
		t.Fatal("email challenge must not be consumable by another username")
	}
	challenge, ok := manager.consumeEmailChallenge(requestID, code, "password-reset", "admin")
	if !ok || challenge.Username != "admin" {
		t.Fatalf("expected correct email code to be accepted, got ok=%v challenge=%+v", ok, challenge)
	}
	if _, ok := manager.consumeEmailChallenge(requestID, code, "password-reset"); ok {
		t.Fatal("email challenge must be single-use")
	}
}

func TestEmailChallengeExpiredIsRejected(t *testing.T) {
	manager := &authManager{emailChallenges: map[string]emailChallenge{
		"expired": {Username: "admin", Purpose: "email-verify", CodeHash: "unused", ExpiresAt: time.Now().Add(-time.Second)},
	}}
	if _, ok := manager.consumeEmailChallenge("expired", "000000", "email-verify"); ok {
		t.Fatal("expired email challenge must be rejected")
	}
}
