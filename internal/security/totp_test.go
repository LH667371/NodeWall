package security

import (
	"testing"
	"time"
)

func TestTOTPCodeAndRecoveryCode(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	at := time.Unix(0, 0).UTC()
	code, err := TOTPCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if code != "282760" {
		t.Fatalf("unexpected RFC 6238 code: %s", code)
	}
	if !VerifyTOTPCode(secret, code, at.Add(3*time.Second)) {
		t.Fatal("current code should verify")
	}
	if VerifyTOTPCode(secret, code, at.Add(2*time.Minute)) {
		t.Fatal("expired code should not verify")
	}

	codes, hashes, err := GenerateRecoveryCodes(2)
	if err != nil || len(codes) != 2 || len(hashes) != 2 {
		t.Fatalf("unexpected recovery code result: %v", err)
	}
	remaining, ok := ConsumeRecoveryCode(codes[0], hashes)
	if !ok || len(remaining) != 1 {
		t.Fatal("recovery code should be consumed once")
	}
	if _, ok := ConsumeRecoveryCode(codes[0], remaining); ok {
		t.Fatal("consumed recovery code should not be reusable")
	}
}
