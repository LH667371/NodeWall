package security

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	record, err := NewPasswordRecord("secret-123")
	if err != nil {
		t.Fatalf("new password record: %v", err)
	}
	if !VerifyPassword("secret-123", record) {
		t.Fatalf("expected password to verify")
	}
	if VerifyPassword("wrong", record) {
		t.Fatalf("expected wrong password to fail")
	}
}
