package gate

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var DefaultGlobalRails = []string{
	"x402_usdc",
	"stripe",
	"sepa_instant",
	"ach_fednow",
	"pix_upi",
	"mpesa",
	"momo",
	"airtel_money",
	"voucher",
}

type RouteConfig struct {
	Path             string `json:"path"`
	Method           string `json:"method"`
	PricingMode      string `json:"pricing_mode"`
	Price            int64  `json:"price"`
	Currency         string `json:"currency"`
	Decimals         *int   `json:"decimals"`
	SettlementMode   string `json:"settlement_mode"`
	RequireMandate   bool   `json:"require_mandate"`
	HitlThreshold    *int64 `json:"hitl_threshold"`
	HumanPassthrough bool   `json:"human_passthrough"`
	MCPTool          string `json:"mcp_tool"`
	MCPDescription   string `json:"mcp_description"`
}

type Config struct {
	Version string `json:"version"`
	Service struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		Origin        string `json:"origin"`
		Listen        string `json:"listen"`
		DiscoveryPath string `json:"discovery_path"`
		EnableMCP     *bool  `json:"enable_mcp"`
	} `json:"service"`
	Security struct {
		RateLimitRPS        int    `json:"rate_limit_rps"`
		MaxBodyBytes        int64  `json:"max_body_bytes"`
		ChallengeTTLSeconds int64  `json:"challenge_ttl_seconds"`
		RedisURL            string `json:"redis_url"`
	} `json:"security"`
	Settlement struct {
		FacilitatorURL       string   `json:"facilitator_url"`
		FacilitatorKID       string   `json:"facilitator_kid"`
		FacilitatorPublicKey string   `json:"facilitator_public_key"`
		DefaultCurrency      string   `json:"default_currency"`
		DefaultDecimals      *int     `json:"default_decimals"`
		AcceptedRails        []string `json:"accepted_rails"`
	} `json:"settlement"`
	Routes []RouteConfig `json:"routes"`
}

func CurrencyDecimals(cur string, explicit *int) int {
	if explicit != nil {
		return *explicit
	}
	switch strings.ToUpper(cur) {
	case "JPY", "KRW", "UGX", "RWF":
		return 0
	case "INR", "BRL", "MXN", "AED", "ZAR", "KES", "NGN", "GHS", "TZS":
		return 2
	case "USD", "EUR", "GBP", "CHF", "CAD", "AUD", "SGD", "USDC", "USDT", "PYUSD":
		return 6
	default:
		return 2
	}
}

// ParsePriceString converts "$0.005", "0.02 EUR", "50 UGX", or "5000" into integer minor units.
func ParsePriceString(raw string, fallbackCurrency string, explicitDec *int) (int64, string, int, error) {
	cur := strings.ToUpper(strings.TrimSpace(fallbackCurrency))
	if cur == "" {
		cur = "USD"
	}
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "free") || s == "0" {
		dec := CurrencyDecimals(cur, explicitDec)
		return 0, cur, dec, nil
	}

	symbols := map[string]string{
		"$": "USD",
		"€": "EUR",
		"£": "GBP",
		"¥": "JPY",
		"₹": "INR",
	}
	for sym, symCur := range symbols {
		if strings.HasPrefix(s, sym) {
			cur = symCur
			s = strings.TrimSpace(strings.TrimPrefix(s, sym))
			break
		}
	}

	fields := strings.Fields(s)
	numStr := s
	if len(fields) == 2 {
		if isAlpha(fields[1]) {
			numStr = fields[0]
			cur = strings.ToUpper(fields[1])
		} else if isAlpha(fields[0]) {
			cur = strings.ToUpper(fields[0])
			numStr = fields[1]
		}
	}

	dec := CurrencyDecimals(cur, explicitDec)
	// If plain integer was passed in legacy YAML without symbol/decimal (e.g. price: 5000), preserve integer minor units ONLY if caller used raw integer field; for string with dot or symbol, scale by decimals.
	parts := strings.Split(numStr, ".")
	if len(parts) > 2 {
		return 0, "", 0, fmt.Errorf("invalid price: %s", raw)
	}
	whole := parts[0]
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
	}
	if len(frac) > dec {
		return 0, "", 0, fmt.Errorf("price %s exceeds %s decimals (%d)", raw, cur, dec)
	}
	padded := frac + strings.Repeat("0", dec-len(frac))
	combined := strings.TrimLeft(whole+padded, "0")
	if combined == "" {
		return 0, cur, dec, nil
	}
	n := new(big.Int)
	if _, ok := n.SetString(combined, 10); !ok || !n.IsInt64() {
		return 0, "", 0, fmt.Errorf("invalid numeric price: %s", raw)
	}
	return n.Int64(), cur, dec, nil
}

func isAlpha(s string) bool {
	if len(s) < 2 || len(s) > 6 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

func LoadConfigFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(path)
	inferred := strings.ToLower(filepath.Base(filepath.Dir(abs)))
	return ParseConfigWithDefaultName(string(b), inferred)
}

func stripComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' && !inD {
			inS = !inS
		} else if c == '"' && !inS {
			inD = !inD
		} else if c == '#' && !inS && !inD {
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return strings.TrimRight(line, " \t\r")
}

func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func ParseConfig(raw string) (*Config, error) {
	return ParseConfigWithDefaultName(raw, "vectoll-service")
}

func ParseConfigWithDefaultName(raw string, defaultName string) (*Config, error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		var cfg Config
		if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
			return nil, err
		}
		return normalizeConfig(&cfg, defaultName)
	}

	cfg := &Config{Version: "1.0"}
	lines := strings.Split(raw, "\n")
	section := ""
	subList := ""
	var curRoute *RouteConfig

	for _, rawLine := range lines {
		line := stripComment(rawLine)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		content := strings.TrimSpace(line)

		if indent == 0 {
			subList = ""
			curRoute = nil
			parts := strings.SplitN(content, ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid YAML line: %s", rawLine)
			}
			key := unquoteScalar(parts[0])
			val := strings.TrimSpace(parts[1])
			if val == "" {
				section = key
			} else {
				section = ""
				uq := unquoteScalar(val)
				switch key {
				case "version":
					cfg.Version = uq
				case "name":
					cfg.Service.Name = uq
				case "origin":
					cfg.Service.Origin = uq
				case "listen":
					cfg.Service.Listen = uq
				case "facilitator":
					cfg.Settlement.FacilitatorURL = uq
				case "currency":
					cfg.Settlement.DefaultCurrency = strings.ToUpper(uq)
				case "mcp":
					b := uq == "true"
					cfg.Service.EnableMCP = &b
				}
			}
			continue
		}

		if section == "routes" {
			// Array style: - path: "/api/..."
			if indent == 2 && strings.HasPrefix(content, "- ") {
				cfg.Routes = append(cfg.Routes, RouteConfig{Method: "GET", PricingMode: "fixed", SettlementMode: "instant"})
				curRoute = &cfg.Routes[len(cfg.Routes)-1]
				applyRouteKV(curRoute, strings.TrimSpace(content[2:]), cfg.Settlement.DefaultCurrency)
				continue
			}
			if indent >= 4 && curRoute != nil && !strings.HasPrefix(content, "- ") {
				applyRouteKV(curRoute, content, cfg.Settlement.DefaultCurrency)
				continue
			}
			// Shorthand map style: GET /api/search: "$0.005" OR GET /blog/*: { price: "$0.002", browsers: "free" }
			if indent == 2 && !strings.HasPrefix(content, "- ") {
				parts := strings.SplitN(content, ":", 2)
				if len(parts) == 2 {
					method, routePath := splitRouteSpec(unquoteScalar(parts[0]))
					rhs := strings.TrimSpace(parts[1])
					rt := RouteConfig{
						Method:         method,
						Path:           routePath,
						PricingMode:    "fixed",
						SettlementMode: "instant",
					}
					cfg.Routes = append(cfg.Routes, rt)
					curRoute = &cfg.Routes[len(cfg.Routes)-1]
					if strings.HasPrefix(rhs, "{") && strings.HasSuffix(rhs, "}") {
						inner := rhs[1 : len(rhs)-1]
						for _, seg := range strings.Split(inner, ",") {
							applyRouteKV(curRoute, strings.TrimSpace(seg), cfg.Settlement.DefaultCurrency)
						}
						curRoute = nil
					} else if rhs != "" {
						applyShorthandPrice(curRoute, unquoteScalar(rhs), cfg.Settlement.DefaultCurrency)
						curRoute = nil
					}
					continue
				}
			}
		}

		if indent == 2 && !strings.HasPrefix(content, "- ") {
			parts := strings.SplitN(content, ":", 2)
			if len(parts) != 2 {
				continue
			}
			k := strings.TrimSpace(parts[0])
			v := unquoteScalar(parts[1])
			if v == "" {
				subList = k
				continue
			}
			subList = ""
			switch section {
			case "service":
				switch k {
				case "name":
					cfg.Service.Name = v
				case "description":
					cfg.Service.Description = v
				case "origin":
					cfg.Service.Origin = v
				case "listen":
					cfg.Service.Listen = v
				case "discovery_path":
					cfg.Service.DiscoveryPath = v
				case "enable_mcp":
					b := v == "true"
					cfg.Service.EnableMCP = &b
				}
			case "security":
				switch k {
				case "rate_limit_rps":
					cfg.Security.RateLimitRPS, _ = strconv.Atoi(v)
				case "max_body_bytes":
					cfg.Security.MaxBodyBytes, _ = strconv.ParseInt(v, 10, 64)
				case "challenge_ttl_seconds":
					cfg.Security.ChallengeTTLSeconds, _ = strconv.ParseInt(v, 10, 64)
				case "redis_url":
					cfg.Security.RedisURL = v
				}
			case "settlement":
				switch k {
				case "facilitator_url":
					cfg.Settlement.FacilitatorURL = v
				case "facilitator_kid":
					cfg.Settlement.FacilitatorKID = v
				case "facilitator_public_key":
					cfg.Settlement.FacilitatorPublicKey = v
				case "default_currency":
					cfg.Settlement.DefaultCurrency = strings.ToUpper(v)
				case "default_decimals":
					d, _ := strconv.Atoi(v)
					cfg.Settlement.DefaultDecimals = &d
				}
			}
			continue
		}

		if indent >= 4 && strings.HasPrefix(content, "- ") && section == "settlement" && subList == "accepted_rails" {
			cfg.Settlement.AcceptedRails = append(cfg.Settlement.AcceptedRails, unquoteScalar(content[2:]))
		}
		if indent >= 2 && strings.HasPrefix(content, "- ") && section == "rails" {
			cfg.Settlement.AcceptedRails = append(cfg.Settlement.AcceptedRails, unquoteScalar(content[2:]))
		}
	}

	return normalizeConfig(cfg, defaultName)
}

func splitRouteSpec(spec string) (string, string) {
	s := strings.TrimSpace(spec)
	idx := strings.IndexByte(s, ' ')
	if idx < 0 {
		if !strings.HasPrefix(s, "/") {
			s = "/" + s
		}
		return "GET", s
	}
	m := strings.ToUpper(strings.TrimSpace(s[:idx]))
	p := strings.TrimSpace(s[idx+1:])
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return m, p
}

func applyShorthandPrice(r *RouteConfig, val string, defCur string) {
	amt, cur, dec, err := ParsePriceString(val, defCur, r.Decimals)
	if err == nil {
		r.Price = amt
		r.Currency = cur
		r.Decimals = &dec
	}
}

func applyRouteKV(r *RouteConfig, line string, defCur string) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return
	}
	k := unquoteScalar(parts[0])
	rawVal := strings.TrimSpace(parts[1])
	v := unquoteScalar(rawVal)
	switch k {
	case "path":
		r.Path = v
	case "method":
		r.Method = strings.ToUpper(v)
	case "pricing_mode":
		r.PricingMode = v
	case "price":
		// Raw unquoted integer in canonical YAML = minor units; quoted or symbol/decimal string = human price
		isQuoted := len(rawVal) >= 2 && (rawVal[0] == '"' || rawVal[0] == '\'')
		if !isQuoted && isDigits(v) {
			r.Price, _ = strconv.ParseInt(v, 10, 64)
		} else {
			applyShorthandPrice(r, v, defCur)
		}
	case "currency":
		r.Currency = strings.ToUpper(v)
	case "decimals":
		d, err := strconv.Atoi(v)
		if err == nil {
			r.Decimals = &d
		}
	case "mode", "settlement_mode":
		r.SettlementMode = v
	case "mandate", "require_mandate":
		r.RequireMandate = v == "true"
	case "browsers":
		r.HumanPassthrough = strings.EqualFold(v, "free")
	case "approve_above":
		amt, _, _, err := ParsePriceString(v, r.Currency, r.Decimals)
		if err == nil {
			r.HitlThreshold = &amt
		}
	case "hitl_threshold":
		if v != "" && v != "null" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				r.HitlThreshold = &n
			}
		}
	case "human_passthrough":
		r.HumanPassthrough = v == "true"
	case "mcp", "mcp_tool":
		r.MCPTool = v
	case "description", "mcp_description":
		r.MCPDescription = v
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func normalizeConfig(cfg *Config, defaultName string) (*Config, error) {
	if cfg.Service.Name == "" {
		if defaultName != "" {
			cfg.Service.Name = defaultName
		} else {
			cfg.Service.Name = "vectoll-service"
		}
	}
	if cfg.Service.Origin == "" {
		return nil, fmt.Errorf("config requires origin (or service.origin)")
	}
	if cfg.Settlement.FacilitatorURL == "" {
		cfg.Settlement.FacilitatorURL = "http://127.0.0.1:4021"
	}
	if cfg.Settlement.DefaultCurrency == "" {
		cfg.Settlement.DefaultCurrency = "USD"
	}
	if len(cfg.Settlement.AcceptedRails) == 0 || (len(cfg.Settlement.AcceptedRails) == 1 && cfg.Settlement.AcceptedRails[0] == "*") {
		cfg.Settlement.AcceptedRails = DefaultGlobalRails
	}
	if cfg.Service.DiscoveryPath == "" {
		cfg.Service.DiscoveryPath = "/.well-known/vectoll.json"
	}
	if cfg.Service.Listen == "" {
		cfg.Service.Listen = ":4020"
	}
	if cfg.Security.RateLimitRPS <= 0 {
		cfg.Security.RateLimitRPS = 100
	}
	if cfg.Security.MaxBodyBytes <= 0 {
		cfg.Security.MaxBodyBytes = 2 * 1024 * 1024
	}
	if cfg.Security.ChallengeTTLSeconds <= 0 {
		cfg.Security.ChallengeTTLSeconds = 60
	}
	if cfg.Settlement.FacilitatorKID == "" {
		cfg.Settlement.FacilitatorKID = "fac-key-1"
	}
	defDec := CurrencyDecimals(cfg.Settlement.DefaultCurrency, cfg.Settlement.DefaultDecimals)
	cfg.Settlement.DefaultDecimals = &defDec
	for i := range cfg.Routes {
		r := &cfg.Routes[i]
		if r.Method == "" {
			r.Method = "GET"
		}
		if r.Currency == "" {
			r.Currency = strings.ToUpper(cfg.Settlement.DefaultCurrency)
		}
		d := CurrencyDecimals(r.Currency, r.Decimals)
		r.Decimals = &d
		if r.SettlementMode == "" {
			r.SettlementMode = "instant"
		}
		if r.PricingMode == "" {
			r.PricingMode = "fixed"
		}
	}
	return cfg, nil
}
