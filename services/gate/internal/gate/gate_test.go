package gate_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vectoll/vectoll/services/gate/internal/gate"
)

type testVectorsFile struct {
	Version string `json:"version"`
	Keys    struct {
		Facilitator struct {
			KID                string `json:"kid"`
			SeedHex            string `json:"seedHex"`
			DID                string `json:"did"`
			PublicKeyBase64URL string `json:"publicKeyBase64Url"`
		} `json:"facilitator"`
		Agent struct {
			DID                string `json:"did"`
			PublicKeyBase64URL string `json:"publicKeyBase64Url"`
		} `json:"agent"`
	} `json:"keys"`
	RequestHashes []struct {
		Method          string `json:"method"`
		Target          string `json:"target"`
		BodyUTF8        string `json:"bodyUtf8"`
		ExpectedReqHash string `json:"expectedReqHash"`
	} `json:"requestHashes"`
	VRTVector struct {
		Token  string         `json:"token"`
		Claims gate.VRTClaims `json:"claims"`
	} `json:"vrtVector"`
}

func mintTestVRT(t *testing.T, priv ed25519.PrivateKey, claims gate.VRTClaims) string {
	t.Helper()
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := gate.Base64URLEncode(payloadJSON)
	sig := ed25519.Sign(priv, []byte("vrt1."+payloadB64))
	return "vrt1." + payloadB64 + "." + gate.Base64URLEncode(sig)
}

func TestCrossLanguageCryptoVectors(t *testing.T) {
	vecPath := filepath.Join("..", "..", "..", "..", "spec", "test-vectors", "crypto-vectors.json")
	raw, err := os.ReadFile(vecPath)
	if err != nil {
		t.Skipf("crypto-vectors.json not yet generated (%v)", err)
	}

	var vec testVectorsFile
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatalf("failed to unmarshal vectors: %v", err)
	}

	seedBytes, _ := hex.DecodeString(vec.Keys.Facilitator.SeedHex)
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)

	did, err := gate.PublicKeyToDIDKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if did != vec.Keys.Facilitator.DID {
		t.Fatalf("DID mismatch: got %s, want %s", did, vec.Keys.Facilitator.DID)
	}
	recoveredPub, err := gate.DIDKeyToPublicKey(did)
	if err != nil || !bytes.Equal(recoveredPub, pub) {
		t.Fatalf("DID roundtrip failed")
	}

	for _, rh := range vec.RequestHashes {
		got := gate.ComputeRequestHash(rh.Method, rh.Target, []byte(rh.BodyUTF8))
		if got != rh.ExpectedReqHash {
			t.Fatalf("reqHash mismatch for %s %s: got %s, want %s", rh.Method, rh.Target, got, rh.ExpectedReqHash)
		}
	}

	claims, vrtErr := gate.VerifyVRT(vec.VRTVector.Token, pub, gate.VerifyOptions{
		ExpectedAudience: "acme-hospitality-api",
		ExpectedReqHash:  vec.VRTVector.Claims.REQ,
		MinAmount:        50,
		ExpectedCurrency: "UGX",
		NowUnix:          1795753810,
	})
	if vrtErr != nil {
		t.Fatalf("expected valid VRT from TypeScript vector, got error: %v", vrtErr)
	}
	if claims.JTI != vec.VRTVector.Claims.JTI {
		t.Fatalf("JTI mismatch: %s != %s", claims.JTI, vec.VRTVector.Claims.JTI)
	}
}

func TestProxyHumanPassthrough402ReplayRaceAndMCP(t *testing.T) {
	seed, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	facPriv := ed25519.NewKeyFromSeed(seed)
	facPub := facPriv.Public().(ed25519.PublicKey)
	facPubB64 := gate.Base64URLEncode(facPub)

	// Origin test server verifying header sanitization & provenance injection
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path":     r.URL.Path,
			"verified": r.Header.Get("X-Vectoll-Verified") == "true",
			"receipt":  r.Header.Get("X-Vectoll-Receipt-Id"),
		})
	}))
	defer origin.Close()

	cfgYAML := `
version: "1.0"
service:
  name: "acme-hospitality-api"
  origin: "` + origin.URL + `"
  enable_mcp: true
security:
  rate_limit_rps: 500
settlement:
  facilitator_url: "http://127.0.0.1:4021"
  facilitator_kid: "fac-vec-1"
  facilitator_public_key: "` + facPubB64 + `"
  default_currency: "UGX"
  accepted_rails:
    - "momo"
    - "x402_usdc"
routes:
  - path: "/api/v1/rooms/availability"
    method: "GET"
    price: 50
    human_passthrough: true
    mcp_tool: "check_room_availability"
`
	cfg, err := gate.ParseConfig(cfgYAML)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	proxy, err := gate.NewProxyServer(cfg)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	gateSrv := httptest.NewServer(proxy)
	defer gateSrv.Close()

	// 1. Human browser passthrough -> 200 OK AND spoofed X-Vectoll-Verified header MUST be stripped!
	reqHuman, _ := http.NewRequest("GET", gateSrv.URL+"/api/v1/rooms/availability", nil)
	reqHuman.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")
	reqHuman.Header.Set("Accept", "text/html,application/xhtml+xml")
	reqHuman.Header.Set("X-Vectoll-Verified", "true") // adversarial header spoof attempt!
	resHuman, err := http.DefaultClient.Do(reqHuman)
	if err != nil {
		t.Fatal(err)
	}
	defer resHuman.Body.Close()
	if resHuman.StatusCode != 200 {
		t.Fatalf("expected 200 for human browser, got %d", resHuman.StatusCode)
	}
	var humanBody map[string]any
	_ = json.NewDecoder(resHuman.Body).Decode(&humanBody)
	if humanBody["verified"] == true {
		t.Fatalf("SECURITY FAILURE: spoofed X-Vectoll-Verified header was not stripped!")
	}

	// 2. Agent without receipt -> 402 Payment Required + PAYMENT-REQUIRED header
	reqAgent, _ := http.NewRequest("GET", gateSrv.URL+"/api/v1/rooms/availability?adults=2", nil)
	reqAgent.Header.Set("User-Agent", "VectollAgent/0.1")
	res402, err := http.DefaultClient.Do(reqAgent)
	if err != nil {
		t.Fatal(err)
	}
	defer res402.Body.Close()
	if res402.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for unpaid agent, got %d", res402.StatusCode)
	}
	if res402.Header.Get("PAYMENT-REQUIRED") == "" {
		t.Fatalf("missing PAYMENT-REQUIRED x402 V2 header")
	}

	// 3. Concurrent 50-goroutine Replay Attack Test: ONLY ONE request may succeed!
	now := time.Now().Unix()
	reqHash := gate.ComputeRequestHash("GET", "/api/v1/rooms/availability?adults=2", nil)
	vrtToken := mintTestVRT(t, facPriv, gate.VRTClaims{
		V:    1,
		JTI:  "vrt_race_test_001",
		KID:  "fac-vec-1",
		ISS:  "http://127.0.0.1:4021",
		SUB:  "did:key:z6MkAgent",
		AUD:  "acme-hospitality-api",
		CHG:  "chg_race_001",
		REQ:  reqHash,
		AMT:  50,
		CUR:  "UGX",
		DEC:  0,
		Rail: "momo",
		Mode: "instant",
		IAT:  now,
		EXP:  now + 60,
	})

	var okCount int32
	var replayRejected int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", gateSrv.URL+"/api/v1/rooms/availability?adults=2", nil)
			req.Header.Set("User-Agent", "VectollAgent/0.1")
			req.Header.Set("PAYMENT-SIGNATURE", vrtToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt32(&okCount, 1)
			} else if resp.StatusCode == http.StatusPaymentRequired {
				atomic.AddInt32(&replayRejected, 1)
			}
		}()
	}
	wg.Wait()

	if okCount != 1 || replayRejected != 49 {
		t.Fatalf("expected exactly 1 success and 49 replay rejections; got ok=%d rejected=%d", okCount, replayRejected)
	}

	// 4. Paid MCP tools/call test
	mcpBody := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"check_room_availability","arguments":{"adults":2}}}`)
	mcpHash := gate.ComputeRequestHash("POST", "/mcp", mcpBody)
	mcpVRT := mintTestVRT(t, facPriv, gate.VRTClaims{
		V: 1, JTI: "vrt_mcp_001", KID: "fac-vec-1", ISS: "http://127.0.0.1:4021",
		SUB: "did:key:z6MkAgent", AUD: "acme-hospitality-api", CHG: "chg_mcp_001",
		REQ: mcpHash, AMT: 50, CUR: "UGX", DEC: 0, Rail: "momo", Mode: "instant",
		IAT: now, EXP: now + 60,
	})
	mcpReq, _ := http.NewRequest("POST", gateSrv.URL+"/mcp", bytes.NewReader(mcpBody))
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("PAYMENT-SIGNATURE", mcpVRT)
	mcpRes, err := http.DefaultClient.Do(mcpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer mcpRes.Body.Close()
	if mcpRes.StatusCode != 200 || mcpRes.Header.Get("PAYMENT-RESPONSE") == "" {
		t.Fatalf("expected 200 + PAYMENT-RESPONSE on paid MCP call, got %d", mcpRes.StatusCode)
	}

	// 5. Shorthand 6-line vectoll.yaml with "$0.005" human-readable pricing in Go!
	shortCfg, err := gate.ParseConfig(`
origin: "http://127.0.0.1:3000"
routes:
  GET /api/search: "$0.005"
  GET /blog/*: { price: "$0.001", browsers: "free" }
`)
	if err != nil {
		t.Fatalf("shorthand config failed in Go: %v", err)
	}
	if len(shortCfg.Routes) != 2 || shortCfg.Routes[0].Price != 5000 || !shortCfg.Routes[1].HumanPassthrough {
		t.Fatalf("unexpected shorthand routes in Go: %+v", shortCfg.Routes)
	}

	// 6. Distributed RESP2 RedisReplayStore in Go
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var seenMu sync.Mutex
	seenKeys := make(map[string]bool)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rd := bufio.NewReader(c)
				var raw strings.Builder
				for i := 0; i < 13; i++ {
					line, err := rd.ReadString('\n')
					if err != nil {
						break
					}
					raw.WriteString(line)
				}
				txt := raw.String()
				idx := strings.Index(txt, "vectoll:jti:")
				if idx >= 0 {
					end := strings.Index(txt[idx:], "\r\n")
					key := txt[idx : idx+end]
					seenMu.Lock()
					already := seenKeys[key]
					seenKeys[key] = true
					seenMu.Unlock()
					if already {
						_, _ = c.Write([]byte("$-1\r\n"))
					} else {
						_, _ = c.Write([]byte("+OK\r\n"))
					}
				}
			}(conn)
		}
	}()

	redisStore, err := gate.NewRedisReplayStore("redis://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !redisStore.Consume("vrt_go_redis_1", time.Now().Unix()+60) {
		t.Fatalf("expected first Redis JTI consume to succeed")
	}
	if redisStore.Consume("vrt_go_redis_1", time.Now().Unix()+60) {
		t.Fatalf("expected duplicate Redis JTI consume to be rejected")
	}
}
