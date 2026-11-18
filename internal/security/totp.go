package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpSecretBytes = 20
	totpPeriod      = 30 * time.Second
	totpDigits      = 6
)

// GenerateTOTPSecret returns an RFC 4648 base32 secret suitable for an
// authenticator application. The secret is generated with crypto/rand and is
// stored only inside the encrypted user store after verification.
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// TOTPCode calculates the six-digit RFC 6238 code for a timestamp.
func TOTPCode(secret string, at time.Time) (string, error) {
	decoded, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(at.Unix() / int64(totpPeriod/time.Second))
	var message [8]byte
	for i := len(message) - 1; i >= 0; i-- {
		message[i] = byte(counter)
		counter >>= 8
	}
	digest := hmac.New(sha1.New, decoded)
	_, _ = digest.Write(message[:])
	sum := digest.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, value%1000000), nil
}

// VerifyTOTPCode accepts the current 30-second step and one adjacent step to
// account for normal clock skew. It intentionally rejects non-numeric input.
func VerifyTOTPCode(secret, code string, at time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return false
		}
	}
	for _, offset := range []int{-1, 0, 1} {
		expected, err := TOTPCode(secret, at.Add(time.Duration(offset)*totpPeriod))
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

func OTPAuthURI(secret, issuer, account string) string {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(totpDigits))
	query.Set("period", strconv.Itoa(int(totpPeriod/time.Second)))
	return "otpauth://totp/" + label + "?" + query.Encode()
}

func GenerateRecoveryCodes(count int) ([]string, []string, error) {
	if count <= 0 {
		count = 10
	}
	codes := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, nil, err
		}
		code := strings.ToUpper(hex.EncodeToString(raw[:]))
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(sum[:])
}

// ConsumeRecoveryCode returns a new hash slice and whether the supplied code
// matched. Callers persist the returned slice atomically with the user record.
func ConsumeRecoveryCode(code string, hashes []string) ([]string, bool) {
	target := HashRecoveryCode(code)
	for i, hash := range hashes {
		if hmac.Equal([]byte(target), []byte(hash)) {
			out := append([]string(nil), hashes[:i]...)
			out = append(out, hashes[i+1:]...)
			return out, true
		}
	}
	return hashes, false
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.TrimRight(secret, "=")
	if secret == "" {
		return nil, fmt.Errorf("empty TOTP secret")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(decoded) < 10 {
		return nil, fmt.Errorf("invalid TOTP secret")
	}
	return decoded, nil
}
