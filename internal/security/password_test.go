package security

import (
	"encoding/hex"
	"testing"
)

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
	if record.Algorithm != defaultAlgorithm || NeedsRehash(record) {
		t.Fatalf("new password record should use current Argon2id parameters: %+v", record)
	}
}

func TestLegacyPasswordRecordRemainsVerifiableAndNeedsUpgrade(t *testing.T) {
	legacy := PasswordRecord{
		Salt:       "00112233445566778899aabbccddeeff",
		Hash:       "",
		Iterations: legacyIterations,
	}
	legacy.Hash = stringHashHex("legacy-secret", legacy)
	if !VerifyPassword("legacy-secret", legacy) {
		t.Fatal("legacy password record should remain verifiable")
	}
	if !NeedsRehash(legacy) {
		t.Fatal("legacy password record should request an Argon2id upgrade")
	}
}

func stringHashHex(password string, record PasswordRecord) string {
	salt, _ := hex.DecodeString(record.Salt)
	return hex.EncodeToString(hashPassword(password, salt, record.Iterations))
}
