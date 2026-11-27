package gate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// VRTClaims mirrors RFC-0001 Section 7.2 normative claims.
type VRTClaims struct {
	V    int    `json:"v"`
	JTI  string `json:"jti"`
	KID  string `json:"kid"`
	ISS  string `json:"iss"`
	SUB  string `json:"sub"`
	AUD  string `json:"aud"`
	CHG  string `json:"chg"`
	REQ  string `json:"req"`
	AMT  int64  `json:"amt"`
	CUR  string `json:"cur"`
	DEC  int    `json:"dec"`
	Rail string `json:"rail"`
	Mode string `json:"mode"`
	ESC  string `json:"esc,omitempty"`
	IAT  int64  `json:"iat"`
	EXP  int64  `json:"exp"`
}

type PaymentChallenge struct {
	X402Version    int      `json:"x402Version"`
	Protocol       string   `json:"protocol"`
	ChallengeID    string   `json:"challengeId"`
	Service        string   `json:"service"`
	Resource       string   `json:"resource"`
	Method         string   `json:"method"`
	ReqHash        string   `json:"reqHash"`
	Amount         int64    `json:"amount"`
	Currency       string   `json:"currency"`
	Decimals       int      `json:"decimals"`
	SettlementMode string   `json:"settlementMode"`
	RequireMandate bool     `json:"requireMandate"`
	HitlThreshold  *int64   `json:"hitlThreshold"`
	FacilitatorURL string   `json:"facilitatorUrl"`
	FacilitatorKID string   `json:"facilitatorKid"`
	AcceptedRails  []string `json:"acceptedRails"`
	IssuedAt       int64    `json:"issuedAt"`
	ExpiresAt      int64    `json:"expiresAt"`
}

type PaymentResponse struct {
	X402Version int    `json:"x402Version"`
	Protocol    string `json:"protocol"`
	ReceiptID   string `json:"receiptId"`
	Settled     bool   `json:"settled"`
	Mode        string `json:"mode"`
	EscrowID    string `json:"escrowId,omitempty"`
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	Decimals    int    `json:"decimals"`
	Rail        string `json:"rail"`
	VerifiedAt  int64  `json:"verifiedAt"`
}

func RandomID(prefix string, byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func Base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
}

func ComputeRequestHash(method, target string, body []byte) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	t := target
	if !strings.HasPrefix(t, "/") {
		t = "/" + t
	}
	bodySum := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n%s\n%s", m, t, hex.EncodeToString(bodySum[:]))
	reqSum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(reqSum[:])
}

func PublicKeyToDIDKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid ed25519 public key length: %d", len(pub))
	}
	buf := make([]byte, 34)
	buf[0] = 0xed
	buf[1] = 0x01
	copy(buf[2:], pub)
	return "did:key:z" + base58Encode(buf), nil
}

func DIDKeyToPublicKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return nil, fmt.Errorf("unsupported did format: %s", did)
	}
	decoded, err := base58Decode(strings.TrimPrefix(did, "did:key:z"))
	if err != nil {
		return nil, err
	}
	if len(decoded) != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, errors.New("invalid multicodec prefix in did:key")
	}
	return ed25519.PublicKey(decoded[2:]), nil
}

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	zeroes := 0
	for zeroes < len(input) && input[zeroes] == 0 {
		zeroes++
	}
	num := new(big.Int).SetBytes(input)
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var out []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeroes; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	zeroes := 0
	for zeroes < len(s) && s[zeroes] == '1' {
		zeroes++
	}
	num := big.NewInt(0)
	radix := big.NewInt(58)
	for i := zeroes; i < len(s); i++ {
		idx := strings.IndexByte(base58Alphabet, s[i])
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 char: %c", s[i])
		}
		num.Mul(num, radix)
		num.Add(num, big.NewInt(int64(idx)))
	}
	b := num.Bytes()
	out := make([]byte, zeroes+len(b))
	copy(out[zeroes:], b)
	return out, nil
}

type VerifyOptions struct {
	ExpectedAudience string
	ExpectedReqHash  string
	MinAmount        int64
	ExpectedCurrency string
	NowUnix          int64
	ClockSkewSec     int64
}

type VRTError struct {
	Code   string
	Reason string
}

func (e *VRTError) Error() string {
	return e.Code + ": " + e.Reason
}

// VerifyVRT performs pre-parse Ed25519 verification followed by claim validation.
func VerifyVRT(token string, pubKey ed25519.PublicKey, opts VerifyOptions) (*VRTClaims, *VRTError) {
	trimmed := strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(trimmed), "vectoll ") {
		trimmed = strings.TrimSpace(trimmed[8:])
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 || parts[0] != "vrt1" {
		return nil, &VRTError{Code: "ERR_MALFORMED_VRT", Reason: "expected vrt1.<payload>.<signature>"}
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, &VRTError{Code: "ERR_INVALID_PUBLIC_KEY", Reason: "facilitator public key must be 32 bytes"}
	}

	sigBytes, err := Base64URLDecode(parts[2])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, &VRTError{Code: "ERR_INVALID_RECEIPT_SIGNATURE", Reason: "malformed Ed25519 signature"}
	}

	signingInput := []byte("vrt1." + parts[1])
	if !ed25519.Verify(pubKey, signingInput, sigBytes) {
		return nil, &VRTError{Code: "ERR_INVALID_RECEIPT_SIGNATURE", Reason: "Ed25519 signature verification failed"}
	}

	payloadBytes, err := Base64URLDecode(parts[1])
	if err != nil {
		return nil, &VRTError{Code: "ERR_INVALID_PAYLOAD", Reason: "invalid base64url payload"}
	}

	var claims VRTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, &VRTError{Code: "ERR_INVALID_PAYLOAD", Reason: "invalid JSON claims"}
	}

	if claims.V != 1 || claims.JTI == "" || claims.REQ == "" || claims.AUD == "" {
		return nil, &VRTError{Code: "ERR_INVALID_CLAIMS", Reason: "missing required VRT v1 claims"}
	}

	now := opts.NowUnix
	if now == 0 {
		now = time.Now().Unix()
	}
	skew := opts.ClockSkewSec
	if skew == 0 {
		skew = 5
	}
	if now > claims.EXP+skew {
		return nil, &VRTError{Code: "ERR_RECEIPT_EXPIRED", Reason: "receipt expired"}
	}

	if opts.ExpectedAudience != "" && claims.AUD != opts.ExpectedAudience {
		return nil, &VRTError{Code: "ERR_AUDIENCE_MISMATCH", Reason: "audience mismatch"}
	}

	if opts.ExpectedReqHash != "" {
		if subtle.ConstantTimeCompare([]byte(claims.REQ), []byte(opts.ExpectedReqHash)) != 1 {
			return nil, &VRTError{Code: "ERR_REQUEST_HASH_MISMATCH", Reason: "request method/path/body hash mismatch"}
		}
	}

	if opts.ExpectedCurrency != "" && !strings.EqualFold(claims.CUR, opts.ExpectedCurrency) {
		return nil, &VRTError{Code: "ERR_CURRENCY_MISMATCH", Reason: "currency mismatch"}
	}

	if claims.AMT < opts.MinAmount {
		return nil, &VRTError{Code: "ERR_INSUFFICIENT_RECEIPT_AMOUNT", Reason: "receipt amount below route price"}
	}

	return &claims, nil
}
