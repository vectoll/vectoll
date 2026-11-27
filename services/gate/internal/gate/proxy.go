package gate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ReplayStore struct {
	mu       sync.Mutex
	consumed map[string]int64
}

func NewReplayStore() *ReplayStore {
	return &ReplayStore{consumed: make(map[string]int64)}
}

func (s *ReplayStore) Consume(jti string, expUnix int64) bool {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.consumed) > 5000 {
		for k, exp := range s.consumed {
			if exp < now {
				delete(s.consumed, k)
			}
		}
	}
	if existingExp, exists := s.consumed[jti]; exists && existingExp >= now {
		return false
	}
	ttl := expUnix + 60
	if ttl < now+60 {
		ttl = now + 60
	}
	s.consumed[jti] = ttl
	return true
}

type IPRateLimiter struct {
	mu      sync.Mutex
	rps     float64
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func NewIPRateLimiter(rps int) *IPRateLimiter {
	return &IPRateLimiter{
		rps:     float64(rps),
		buckets: make(map[string]*tokenBucket),
	}
}

func (l *IPRateLimiter) Allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		l.buckets[ip] = &tokenBucket{tokens: l.rps*2 - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rps
	if b.tokens > l.rps*2 {
		b.tokens = l.rps * 2
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

type ProxyServer struct {
	cfg        *Config
	originURL  *url.URL
	revProxy   *httputil.ReverseProxy
	replay     ReplayGuard
	limiter    *IPRateLimiter
	httpClient *http.Client

	keyMu   sync.RWMutex
	pubKey  ed25519.PublicKey
	pubKeys map[string]ed25519.PublicKey
	kid     string

	cntPassthrough uint64
	cntChallenged  uint64
	cntVerified    uint64
	cntRejected    uint64
	cntRateLimited uint64
}

func NewProxyServer(cfg *Config) (*ProxyServer, error) {
	originURL, err := url.Parse(cfg.Service.Origin)
	if err != nil {
		return nil, fmt.Errorf("invalid origin URL: %w", err)
	}

	var replayGuard ReplayGuard = NewReplayStore()
	if cfg.Security.RedisURL != "" {
		rs, err := NewRedisReplayStore(cfg.Security.RedisURL)
		if err != nil {
			return nil, err
		}
		replayGuard = rs
	}

	s := &ProxyServer{
		cfg:        cfg,
		originURL:  originURL,
		replay:     replayGuard,
		limiter:    NewIPRateLimiter(cfg.Security.RateLimitRPS),
		httpClient: &http.Client{Timeout: 5 * time.Second},
		pubKeys:    make(map[string]ed25519.PublicKey),
		kid:        cfg.Settlement.FacilitatorKID,
	}

	if cfg.Settlement.FacilitatorPublicKey != "" {
		raw, err := Base64URLDecode(cfg.Settlement.FacilitatorPublicKey)
		if err == nil && len(raw) == ed25519.PublicKeySize {
			s.pubKey = ed25519.PublicKey(raw)
			s.pubKeys[s.kid] = ed25519.PublicKey(raw)
		}
	}

	rp := httputil.NewSingleHostReverseProxy(originURL)
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = originURL.Host
	}
	rp.ErrorHandler = func(w http.ResponseWriter, req *http.Request, proxyErr error) {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error":             "ERR_ORIGIN_UNREACHABLE",
			"origin":            cfg.Service.Origin,
			"target":            req.URL.RequestURI(),
			"message":           proxyErr.Error(),
			"discoveryManifest": cfg.Service.DiscoveryPath,
			"mcpEndpoint":       "/mcp",
		})
	}
	s.revProxy = rp
	return s, nil
}

func (s *ProxyServer) resolveFacilitatorKeyForToken(vrtToken string) (ed25519.PublicKey, error) {
	// Peek kid from vrt1.<payload>.<sig> if multi-key JWKS is populated
	var tokenKID string
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(vrtToken, "Vectoll ")), ".")
	if len(parts) == 3 {
		if pb, err := Base64URLDecode(parts[1]); err == nil {
			var peek struct {
				KID string `json:"kid"`
			}
			if json.Unmarshal(pb, &peek) == nil {
				tokenKID = peek.KID
			}
		}
	}

	s.keyMu.RLock()
	if tokenKID != "" {
		if k, ok := s.pubKeys[tokenKID]; ok {
			s.keyMu.RUnlock()
			return k, nil
		}
	} else if len(s.pubKey) == ed25519.PublicKeySize {
		k := s.pubKey
		s.keyMu.RUnlock()
		return k, nil
	}
	s.keyMu.RUnlock()

	_, err := s.resolveFacilitatorKey()
	if err != nil {
		return nil, err
	}
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	if tokenKID != "" {
		if k, ok := s.pubKeys[tokenKID]; ok {
			return k, nil
		}
	}
	return s.pubKey, nil
}

func (s *ProxyServer) resolveFacilitatorKey() (ed25519.PublicKey, error) {
	s.keyMu.RLock()
	if len(s.pubKey) == ed25519.PublicKeySize {
		k := s.pubKey
		s.keyMu.RUnlock()
		return k, nil
	}
	s.keyMu.RUnlock()

	jwksURL := strings.TrimRight(s.cfg.Settlement.FacilitatorURL, "/") + "/.well-known/jwks.json"
	resp, err := s.httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch failed: %w", err)
	}
	defer resp.Body.Close()

	var doc struct {
		Keys []struct {
			KID string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || len(doc.Keys) == 0 {
		return nil, fmt.Errorf("invalid jwks response")
	}
	raw, err := Base64URLDecode(doc.Keys[0].X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 key in jwks")
	}

	s.keyMu.Lock()
	s.pubKey = ed25519.PublicKey(raw)
	if doc.Keys[0].KID != "" {
		s.kid = doc.Keys[0].KID
	}
	for _, entry := range doc.Keys {
		if r, e := Base64URLDecode(entry.X); e == nil && len(r) == ed25519.PublicKeySize && entry.KID != "" {
			s.pubKeys[entry.KID] = ed25519.PublicKey(r)
		}
	}
	s.keyMu.Unlock()
	return ed25519.PublicKey(raw), nil
}

func (s *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	if !s.limiter.Allow(clientIP) {
		atomic.AddUint64(&s.cntRateLimited, 1)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "ERR_RATE_LIMITED",
		})
		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/health" {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"service": "vectoll-gate",
			"version": "1.0.0",
			"target":  s.cfg.Service.Name,
		})
		return
	}

	if r.Method == http.MethodGet && r.URL.Path == "/metrics" {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w,
			"# HELP vectoll_gate_requests_total Total HTTP requests processed by Go vectoll-gate\n"+
				"# TYPE vectoll_gate_requests_total counter\n"+
				"vectoll_gate_requests_total{outcome=\"human_passthrough\"} %d\n"+
				"vectoll_gate_requests_total{outcome=\"challenged_402\"} %d\n"+
				"vectoll_gate_requests_total{outcome=\"verified_200\"} %d\n"+
				"vectoll_gate_requests_total{outcome=\"rejected\"} %d\n"+
				"vectoll_gate_requests_total{outcome=\"rate_limited\"} %d\n",
			atomic.LoadUint64(&s.cntPassthrough),
			atomic.LoadUint64(&s.cntChallenged),
			atomic.LoadUint64(&s.cntVerified),
			atomic.LoadUint64(&s.cntRejected),
			atomic.LoadUint64(&s.cntRateLimited),
		)
		return
	}

	if r.Method == http.MethodGet && r.URL.Path == s.cfg.Service.DiscoveryPath {
		s.handleDiscovery(w)
		return
	}

	enableMCP := s.cfg.Service.EnableMCP == nil || *s.cfg.Service.EnableMCP
	if enableMCP && r.URL.Path == "/mcp" {
		if r.Method == http.MethodGet {
			s.handleMCPInfo(w, r)
			return
		}
		if r.Method == http.MethodPost {
			s.handleMCP(w, r)
			return
		}
	}

	route := s.matchRoute(r.Method, r.URL.Path)

	var bodyBytes []byte
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		limited := io.LimitReader(r.Body, s.cfg.Security.MaxBodyBytes+1)
		var readErr error
		bodyBytes, readErr = io.ReadAll(limited)
		if readErr != nil || int64(len(bodyBytes)) > s.cfg.Security.MaxBodyBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "ERR_PAYLOAD_TOO_LARGE"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Sanitize untrusted inbound X-Vectoll-* headers unconditionally
	sanitizeUntrustedHeaders(r)

	if route == nil || route.Price == 0 || classifyTraffic(r, route.HumanPassthrough) == "human" {
		atomic.AddUint64(&s.cntPassthrough, 1)
		s.revProxy.ServeHTTP(w, r)
		return
	}

	target := r.URL.RequestURI()
	reqHash := ComputeRequestHash(r.Method, target, bodyBytes)
	sigHeader := r.Header.Get("PAYMENT-SIGNATURE")
	if sigHeader == "" {
		sigHeader = r.Header.Get("Authorization")
	}

	if sigHeader == "" || (!strings.HasPrefix(sigHeader, "vrt1.") && !strings.HasPrefix(strings.ToLower(sigHeader), "vectoll vrt1.")) {
		atomic.AddUint64(&s.cntChallenged, 1)
		s.writeChallenge(w, r.Method, target, reqHash, route)
		return
	}

	pubKey, err := s.resolveFacilitatorKeyForToken(sigHeader)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "ERR_FACILITATOR_KEY_UNAVAILABLE", "reason": err.Error()})
		return
	}

	claims, vrtErr := VerifyVRT(sigHeader, pubKey, VerifyOptions{
		ExpectedAudience: s.cfg.Service.Name,
		ExpectedReqHash:  reqHash,
		MinAmount:        route.Price,
		ExpectedCurrency: route.Currency,
	})
	if vrtErr != nil {
		atomic.AddUint64(&s.cntRejected, 1)
		writeJSON(w, http.StatusPaymentRequired, map[string]string{
			"error":  vrtErr.Code,
			"reason": vrtErr.Reason,
		})
		return
	}

	if !s.replay.Consume(claims.JTI, claims.EXP) {
		atomic.AddUint64(&s.cntRejected, 1)
		writeJSON(w, http.StatusPaymentRequired, map[string]string{
			"error":  "ERR_RECEIPT_REPLAYED",
			"reason": "VRT jti has already been consumed",
		})
		return
	}

	atomic.AddUint64(&s.cntVerified, 1)

	// Attach trusted Vectoll provenance headers for Origin
	r.Header.Set("X-Vectoll-Verified", "true")
	r.Header.Set("X-Vectoll-Receipt-Id", claims.JTI)
	r.Header.Set("X-Vectoll-Agent-Id", claims.SUB)
	r.Header.Set("X-Vectoll-Paid-Amount", fmt.Sprintf("%d %s", claims.AMT, claims.CUR))
	r.Header.Set("X-Vectoll-Rail", claims.Rail)
	if claims.ESC != "" {
		r.Header.Set("X-Vectoll-Escrow-Id", claims.ESC)
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	payResp := PaymentResponse{
		X402Version: 2,
		Protocol:    "vectoll/0.1",
		ReceiptID:   claims.JTI,
		Settled:     claims.Mode == "instant",
		Mode:        claims.Mode,
		EscrowID:    claims.ESC,
		Amount:      claims.AMT,
		Currency:    claims.CUR,
		Decimals:    claims.DEC,
		Rail:        claims.Rail,
		VerifiedAt:  time.Now().Unix(),
	}
	respBytes, _ := json.Marshal(payResp)
	w.Header().Set("PAYMENT-RESPONSE", Base64URLEncode(respBytes))

	s.revProxy.ServeHTTP(w, r)
}

func (s *ProxyServer) writeChallenge(w http.ResponseWriter, method, resource, reqHash string, route *RouteConfig) {
	_, _ = s.resolveFacilitatorKey()
	s.keyMu.RLock()
	kid := s.kid
	s.keyMu.RUnlock()

	now := time.Now().Unix()
	dec := CurrencyDecimals(route.Currency, route.Decimals)
	chg := PaymentChallenge{
		X402Version:    2,
		Protocol:       "vectoll/0.1",
		ChallengeID:    RandomID("chg", 12),
		Service:        s.cfg.Service.Name,
		Resource:       resource,
		Method:         strings.ToUpper(method),
		ReqHash:        reqHash,
		Amount:         route.Price,
		Currency:       route.Currency,
		Decimals:       dec,
		SettlementMode: route.SettlementMode,
		RequireMandate: route.RequireMandate,
		HitlThreshold:  route.HitlThreshold,
		FacilitatorURL: s.cfg.Settlement.FacilitatorURL,
		FacilitatorKID: kid,
		AcceptedRails:  s.cfg.Settlement.AcceptedRails,
		IssuedAt:       now,
		ExpiresAt:      now + s.cfg.Security.ChallengeTTLSeconds,
	}
	chgJSON, _ := json.Marshal(chg)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("PAYMENT-REQUIRED", Base64URLEncode(chgJSON))
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Vectoll realm="%s", challengeId="%s", facilitator="%s"`,
		s.cfg.Service.Name, chg.ChallengeID, s.cfg.Settlement.FacilitatorURL))
	w.WriteHeader(http.StatusPaymentRequired)
	_, _ = w.Write(chgJSON)
}

func (s *ProxyServer) handleDiscovery(w http.ResponseWriter) {
	_, _ = s.resolveFacilitatorKey()
	s.keyMu.RLock()
	pubB64 := ""
	if len(s.pubKey) == ed25519.PublicKeySize {
		pubB64 = Base64URLEncode(s.pubKey)
	}
	kid := s.kid
	s.keyMu.RUnlock()

	facURL := strings.TrimRight(s.cfg.Settlement.FacilitatorURL, "/")
	routesOut := make([]map[string]any, 0, len(s.cfg.Routes))
	for _, r := range s.cfg.Routes {
		var mcp any
		if r.MCPTool != "" {
			desc := r.MCPDescription
			if desc == "" {
				desc = r.Method + " " + r.Path
			}
			mcp = map[string]string{"name": r.MCPTool, "description": desc}
		}
		routesOut = append(routesOut, map[string]any{
			"path":             r.Path,
			"method":           r.Method,
			"pricingMode":      r.PricingMode,
			"amount":           r.Price,
			"currency":         r.Currency,
			"decimals":         CurrencyDecimals(r.Currency, r.Decimals),
			"settlementMode":   r.SettlementMode,
			"requireMandate":   r.RequireMandate,
			"hitlThreshold":    r.HitlThreshold,
			"humanPassthrough": r.HumanPassthrough,
			"mcpTool":          mcp,
		})
	}

	var mcpEndpoint any = "/mcp"
	if s.cfg.Service.EnableMCP != nil && !*s.cfg.Service.EnableMCP {
		mcpEndpoint = nil
	}

	doc := map[string]any{
		"vectollVersion": "0.1",
		"x402Version":    2,
		"service": map[string]any{
			"name":        s.cfg.Service.Name,
			"description": s.cfg.Service.Description,
			"mcpEndpoint": mcpEndpoint,
		},
		"settlement": map[string]any{
			"facilitatorUrl":       facURL,
			"jwksUrl":              facURL + "/.well-known/jwks.json",
			"facilitatorPublicKey": pubB64,
			"facilitatorKid":       kid,
			"defaultCurrency":      s.cfg.Settlement.DefaultCurrency,
			"defaultDecimals":      CurrencyDecimals(s.cfg.Settlement.DefaultCurrency, s.cfg.Settlement.DefaultDecimals),
			"acceptedRails":        s.cfg.Settlement.AcceptedRails,
		},
		"routes": routesOut,
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *ProxyServer) handleMCPInfo(w http.ResponseWriter, r *http.Request) {
	tools := make([]map[string]any, 0)
	for _, rt := range s.cfg.Routes {
		if rt.MCPTool == "" {
			continue
		}
		desc := rt.MCPDescription
		if desc == "" {
			desc = rt.Method + " " + rt.Path
		}
		tools = append(tools, map[string]any{
			"name":           rt.MCPTool,
			"description":    desc,
			"method":         rt.Method,
			"upstreamPath":   rt.Path,
			"amount":         rt.Price,
			"currency":       rt.Currency,
			"decimals":       CurrencyDecimals(rt.Currency, rt.Decimals),
			"settlementMode": rt.SettlementMode,
			"requireMandate": rt.RequireMandate,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocolVersion": "2025-06-18",
		"transport":       "streamable-http",
		"endpoint":        "/mcp",
		"serverInfo":      map[string]string{"name": s.cfg.Service.Name, "version": "0.1.0"},
		"acceptedRails":   s.cfg.Settlement.AcceptedRails,
		"tools":           tools,
	})
}

func (s *ProxyServer) handleMCP(w http.ResponseWriter, r *http.Request) {
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.Security.MaxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	var rpc struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      any            `json:"id"`
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
	}
	if err := json.Unmarshal(rawBody, &rpc); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "Parse error"},
		})
		return
	}

	switch rpc.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result": map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]string{"name": s.cfg.Service.Name, "version": "0.1.0"},
				"capabilities":    map[string]any{"tools": map[string]any{}},
			},
		})
	case "tools/list":
		tools := make([]map[string]any, 0)
		for _, rt := range s.cfg.Routes {
			if rt.MCPTool == "" {
				continue
			}
			desc := rt.MCPDescription
			if desc == "" {
				desc = rt.Method + " " + rt.Path
			}
			tools = append(tools, map[string]any{
				"name":        rt.MCPTool,
				"description": desc,
				"inputSchema": map[string]any{"type": "object", "additionalProperties": true},
				"_meta": map[string]any{
					"vectollPricing": map[string]any{
						"amount":         rt.Price,
						"currency":       rt.Currency,
						"decimals":       CurrencyDecimals(rt.Currency, rt.Decimals),
						"settlementMode": rt.SettlementMode,
						"requireMandate": rt.RequireMandate,
					},
				},
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0", "id": rpc.ID, "result": map[string]any{"tools": tools},
		})
	case "tools/call":
		toolName, _ := rpc.Params["name"].(string)
		var matched *RouteConfig
		for i := range s.cfg.Routes {
			if s.cfg.Routes[i].MCPTool == toolName {
				matched = &s.cfg.Routes[i]
				break
			}
		}
		if matched == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"jsonrpc": "2.0", "id": rpc.ID,
				"error": map[string]any{"code": -32601, "message": "Unknown MCP tool: " + toolName},
			})
			return
		}

		reqHash := ComputeRequestHash("POST", "/mcp", rawBody)
		sigHeader := r.Header.Get("PAYMENT-SIGNATURE")
		if sigHeader == "" {
			sigHeader = r.Header.Get("Authorization")
		}
		if sigHeader == "" {
			s.writeChallenge(w, "POST", "/mcp", reqHash, matched)
			return
		}

		pubKey, err := s.resolveFacilitatorKeyForToken(sigHeader)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		claims, vrtErr := VerifyVRT(sigHeader, pubKey, VerifyOptions{
			ExpectedAudience: s.cfg.Service.Name,
			ExpectedReqHash:  reqHash,
			MinAmount:        matched.Price,
			ExpectedCurrency: matched.Currency,
		})
		if vrtErr != nil {
			writeJSON(w, http.StatusPaymentRequired, map[string]string{"error": vrtErr.Code, "reason": vrtErr.Reason})
			return
		}
		if !s.replay.Consume(claims.JTI, claims.EXP) {
			writeJSON(w, http.StatusPaymentRequired, map[string]string{"error": "ERR_RECEIPT_REPLAYED"})
			return
		}

		argsMap, _ := rpc.Params["arguments"].(map[string]any)
		destURL := strings.TrimRight(s.cfg.Service.Origin, "/") + matched.Path
		var upstreamReq *http.Request
		if matched.Method == http.MethodGet {
			q := url.Values{}
			for k, v := range argsMap {
				q.Set(k, fmt.Sprintf("%v", v))
			}
			if enc := q.Encode(); enc != "" {
				destURL += "?" + enc
			}
			upstreamReq, _ = http.NewRequest(http.MethodGet, destURL, nil)
		} else {
			argBytes, _ := json.Marshal(argsMap)
			upstreamReq, _ = http.NewRequest(matched.Method, destURL, bytes.NewReader(argBytes))
			upstreamReq.Header.Set("Content-Type", "application/json")
		}
		upstreamReq.Header.Set("X-Vectoll-Verified", "true")
		upstreamReq.Header.Set("X-Vectoll-Receipt-Id", claims.JTI)
		upstreamReq.Header.Set("X-Vectoll-Agent-Id", claims.SUB)

		upResp, err := s.httpClient.Do(upstreamReq)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		defer upResp.Body.Close()
		upBody, _ := io.ReadAll(upResp.Body)

		payResp, _ := json.Marshal(PaymentResponse{
			X402Version: 2, Protocol: "vectoll/0.1", ReceiptID: claims.JTI, Settled: claims.Mode == "instant",
			Mode: claims.Mode, Amount: claims.AMT, Currency: claims.CUR, Decimals: claims.DEC, Rail: claims.Rail,
			VerifiedAt: time.Now().Unix(),
		})
		w.Header().Set("PAYMENT-RESPONSE", Base64URLEncode(payResp))
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result": map[string]any{
				"content": []map[string]string{{"type": "text", "text": string(upBody)}},
				"isError": upResp.StatusCode >= 400,
			},
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"jsonrpc": "2.0", "id": rpc.ID, "error": map[string]any{"code": -32601, "message": "Unsupported method"},
		})
	}
}

func (s *ProxyServer) matchRoute(method, path string) *RouteConfig {
	m := strings.ToUpper(method)
	for i := range s.cfg.Routes {
		rt := &s.cfg.Routes[i]
		if rt.Method != m && rt.Method != "*" {
			continue
		}
		if rt.Path == path {
			return rt
		}
		if strings.HasSuffix(rt.Path, "/*") {
			prefix := strings.TrimSuffix(rt.Path, "*")
			if strings.HasPrefix(path, prefix) || path == strings.TrimSuffix(prefix, "/") {
				return rt
			}
		}
	}
	return nil
}

func sanitizeUntrustedHeaders(r *http.Request) {
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-vectoll-") {
			r.Header.Del(k)
		}
	}
}

var botTokens = []string{
	"gptbot", "claudebot", "perplexitybot", "google-extended", "ccbot",
	"bytespider", "amazonbot", "vectollagent", "mcp-client", "langchain",
	"crewai", "autogen", "python-requests", "python-httpx", "curl/", "wget/",
	"go-http-client", "headlesschrome", "playwright", "puppeteer", "undici",
}

func classifyTraffic(r *http.Request, humanPassthrough bool) string {
	if !humanPassthrough || r.URL.Path == "/mcp" {
		return "agent"
	}
	if r.Header.Get("PAYMENT-SIGNATURE") != "" ||
		r.Header.Get("X-Vectoll-Mode") == "agent" ||
		strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "vectoll ") {
		return "agent"
	}
	ua := r.Header.Get("User-Agent")
	uaLower := strings.ToLower(ua)
	if ua == "" {
		return "agent"
	}
	for _, tok := range botTokens {
		if strings.Contains(uaLower, tok) {
			return "agent"
		}
	}
	accept := r.Header.Get("Accept")
	isBrowser := strings.HasPrefix(ua, "Mozilla/5.0 ") &&
		(strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Safari/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Edg/"))
	if isBrowser && strings.Contains(accept, "text/html") {
		return "human"
	}
	return "agent"
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	b, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
