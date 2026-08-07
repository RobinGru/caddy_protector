package caddyprotector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap/zaptest"
)

type hijackableResponseWriter struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
	conn        *testConn
}

func newHijackableResponseWriter() *hijackableResponseWriter {
	return &hijackableResponseWriter{header: make(http.Header), conn: &testConn{}}
}

func (w *hijackableResponseWriter) Header() http.Header { return w.header }
func (w *hijackableResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}
func (w *hijackableResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = statusCode
}
func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard))
	return w.conn, rw, nil
}

type testConn struct{ closed bool }

func (c *testConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (c *testConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return len(p), nil
}
func (c *testConn) Close() error                       { c.closed = true; return nil }
func (c *testConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(_ time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(_ time.Time) error { return nil }
func newTestProtector(t *testing.T) *CaddyProtector {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/site-key/siteverify" {
			t.Fatalf("unerwarteter Pfad: %s", r.URL.Path)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if payload["secret"] != "cap-secret" || payload["response"] == "" {
			t.Fatalf("unerwartetes payload: %#v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(server.Close)
	return newBaseTestProtector(t, server.URL)
}

func newTestProtectorWithVerifyResponse(t *testing.T, status int, body string) *CaddyProtector {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return newBaseTestProtector(t, server.URL)
}

func newRecordingTestProtector(t *testing.T, status int, body string) (*CaddyProtector, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return newBaseTestProtector(t, server.URL), &calls
}

func tlsServerTransport(t *testing.T, server *httptest.Server) http.RoundTripper {
	t.Helper()
	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("TLS test server did not provide an HTTP transport")
	}
	clone := transport.Clone()
	serverAddress := strings.TrimPrefix(server.URL, "https://")
	clone.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	return clone
}

func newBaseTestProtector(t *testing.T, capURL string) *CaddyProtector {
	t.Helper()
	bb := &CaddyProtector{
		AllowFor:       caddy.Duration(defaultAllowFor),
		VerifyPath:     defaultVerifyPath,
		CapAPIURL:      capURL,
		CapSiteKey:     "site-key",
		CapSecretKey:   "cap-secret",
		CookieName:     defaultCookieName,
		CookiePath:     "/",
		CookieSecure:   boolPtr(true),
		CookieHTTPOnly: boolPtr(true),
		CookieSameSite: "Lax",
		logger:         zaptest.NewLogger(t),
	}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	bb.allowlist.Store(&ipAllowlist{exactIPs: make(map[netip.Addr]struct{})})
	bb.blacklist.Store(&ipAllowlist{exactIPs: make(map[netip.Addr]struct{})})
	return bb
}

func mustReturnState(t *testing.T, bb *CaddyProtector, returnPath string) string {
	t.Helper()
	state, err := bb.createReturnState(returnPath, time.Now())
	if err != nil {
		t.Fatalf("createReturnState() error = %v", err)
	}
	return state
}

func verifyRequestFor(t *testing.T, bb *CaddyProtector, token string) *http.Request {
	t.Helper()
	body, err := json.Marshal(verifyRequest{Token: token, State: mustReturnState(t, bb, "/protected?x=1")})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func newChallengeRequest(method, rawURL, clientIP, userAgent string) *http.Request {
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{"client_ip": clientIP})
	req := httptest.NewRequestWithContext(ctx, method, rawURL, nil)
	req.Header.Set("User-Agent", userAgent)
	return req
}
