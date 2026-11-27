package gate

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ReplayGuard interface {
	Consume(jti string, expUnix int64) bool
}

// RedisReplayStore implements atomic distributed replay protection (`SET key 1 NX EX ttl`)
// over raw TCP RESP2 with zero external Go module dependencies.
type RedisReplayStore struct {
	addr      string
	password  string
	keyPrefix string
	timeout   time.Duration
}

func NewRedisReplayStore(redisURL string) (*RedisReplayStore, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	port := u.Port()
	if port == "" {
		port = "6379"
	}
	pass, _ := u.User.Password()
	return &RedisReplayStore{
		addr:      net.JoinHostPort(host, port),
		password:  pass,
		keyPrefix: "vectoll:jti:",
		timeout:   1500 * time.Millisecond,
	}, nil
}

func encodeRESP(args ...string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*%d\r\n", len(args)))
	for _, a := range args {
		b.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(a), a))
	}
	return b.String()
}

func (r *RedisReplayStore) Consume(jti string, expUnix int64) bool {
	now := time.Now().Unix()
	ttl := expUnix - now + 60
	if ttl < 60 {
		ttl = 60
	}

	conn, err := net.DialTimeout("tcp", r.addr, r.timeout)
	if err != nil {
		return false // fail closed if Redis cluster unreachable
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(r.timeout))

	reader := bufio.NewReader(conn)
	if r.password != "" {
		if _, err := conn.Write([]byte(encodeRESP("AUTH", r.password))); err != nil {
			return false
		}
		authLine, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(authLine, "+OK") {
			return false
		}
	}

	cmd := encodeRESP("SET", r.keyPrefix+jti, "1", "NX", "EX", strconv.FormatInt(ttl, 10))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return false
	}
	reply, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	return strings.HasPrefix(reply, "+OK")
}
