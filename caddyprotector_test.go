package caddyprotector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
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

func TestValidateRejectsMissingCapAPIURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.CapAPIURL = ""
	if err := bb.Validate(); err == nil || !strings.Contains(err.Error(), "cap_api_url") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingCapSiteKey(t *testing.T) {
	bb := newTestProtector(t)
	bb.CapSiteKey = ""
	if err := bb.Validate(); err == nil || !strings.Contains(err.Error(), "cap_site_key") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingCapSecretKey(t *testing.T) {
	bb := newTestProtector(t)
	bb.CapSecretKey = ""
	if err := bb.Validate(); err == nil || !strings.Contains(err.Error(), "cap_secret_key") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsBadCapAPIURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.CapAPIURL = "://bad"
	if err := bb.Validate(); err == nil || !strings.Contains(err.Error(), "cap_api_url") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsNonHTTPSCapAPIURLOutsideLoopback(t *testing.T) {
	bb := newTestProtector(t)
	bb.CapAPIURL = "http://cap.example.com"
	if err := bb.Validate(); err == nil || !strings.Contains(err.Error(), "https verwenden") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAllowsLoopbackHTTPURLsForDevelopment(t *testing.T) {
	bb := newTestProtector(t)
	bb.CapAPIURL = "http://127.0.0.1:8080"
	bb.WhitelistURL = "http://localhost:8081/allow.txt"
	bb.BlacklistURL = "http://[::1]:8082/block.txt"
	bb.CountryURL = "http://localhost:8083/country.mmdb"
	bb.WhitelistCountries = []string{"DE"}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsBadCookieSameSite(t *testing.T) {
	bb := newTestProtector(t)
	bb.CookieSameSite = "kaputt"
	if err := bb.Validate(); err == nil || !strings.Contains(err.Error(), "cookie_same_site") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDecodeVerifyRequestAcceptsJSON(t *testing.T) {
	body := `{"token":"abc","state":"def"}`
	req, info, err := decodeVerifyRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("decodeVerifyRequest() error = %v", err)
	}
	if req.Token != "abc" || req.State != "def" {
		t.Fatalf("decodeVerifyRequest() = %#v", req)
	}
	if info.BodyLength != len(body) {
		t.Fatalf("BodyLength = %d", info.BodyLength)
	}
}

func TestDecodeVerifyRequestRejectsUnknownFields(t *testing.T) {
	_, _, err := decodeVerifyRequest(strings.NewReader(`{"token":"abc","state":"def","extra":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decodeVerifyRequest() error = %v", err)
	}
}

func TestReturnStateRoundTrip(t *testing.T) {
	bb := newTestProtector(t)
	now := time.Now()
	token, err := bb.createReturnState("/protected?x=1", now)
	if err != nil {
		t.Fatalf("createReturnState() error = %v", err)
	}
	claims, err := bb.verifyReturnState(token, now)
	if err != nil {
		t.Fatalf("verifyReturnState() error = %v", err)
	}
	if claims.ReturnPath != "/protected?x=1" {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestReturnStateRejectsTampering(t *testing.T) {
	bb := newTestProtector(t)
	token, err := bb.createReturnState("/protected", time.Now())
	if err != nil {
		t.Fatalf("createReturnState() error = %v", err)
	}
	if _, err := bb.verifyReturnState(token+"x", time.Now()); err == nil {
		t.Fatal("manipulierter Return-State sollte fehlschlagen")
	}
}

func TestAllowCookieRoundTrip(t *testing.T) {
	bb := newTestProtector(t)
	rr := httptest.NewRecorder()
	if err := bb.writeAllowCookie(rr, time.Now()); err != nil {
		t.Fatalf("writeAllowCookie() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}
	if !bb.hasValidAllowCookie(req) {
		t.Fatal("erwartetes Freigabe-Cookie wurde nicht erkannt")
	}
}

func TestHandleVerifyRejectsWrongContentType(t *testing.T) {
	bb := newTestProtector(t)
	req := verifyRequestFor(t, bb, "cap-token")
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, req); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestHandleVerifyRejectsMissingToken(t *testing.T) {
	bb := newTestProtector(t)
	body, _ := json.Marshal(verifyRequest{State: mustReturnState(t, bb, "/protected")})
	req := httptest.NewRequest(http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, req); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestHandleVerifyRejectsInvalidState(t *testing.T) {
	bb := newTestProtector(t)
	body, _ := json.Marshal(verifyRequest{Token: "cap-token", State: "kaputt"})
	req := httptest.NewRequest(http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, req); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestHandleVerifyAcceptsVerifiedCapToken(t *testing.T) {
	bb := newTestProtector(t)
	req := verifyRequestFor(t, bb, "cap-token")
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, req); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d", rr.Code)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rr.Header().Get("Cache-Control"))
	}
	if rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("Pragma = %q", rr.Header().Get("Pragma"))
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("Verify sollte ein Freigabe-Cookie setzen")
	}
	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if res["returnTo"] != "/protected?x=1" {
		t.Fatalf("returnTo = %v", res["returnTo"])
	}
}

func TestHandleVerifyRejectsFailedCapVerification(t *testing.T) {
	bb := newTestProtectorWithVerifyResponse(t, http.StatusOK, `{"success":false}`)
	req := verifyRequestFor(t, bb, "cap-token")
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, req); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestServeChallengeSetsCSPAndCapMarkup(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler should not be called")
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Header().Get("X-Bot-Barrier") != "challenge" {
		t.Fatalf("X-Bot-Barrier = %q", rr.Header().Get("X-Bot-Barrier"))
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rr.Header().Get("Cache-Control"))
	}
	if rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("Pragma = %q", rr.Header().Get("Pragma"))
	}
	if got := rr.Header().Get("Content-Security-Policy"); !strings.Contains(got, "cdn.jsdelivr.net") {
		t.Fatalf("unerwarteter CSP-Header: %s", got)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "cap-widget") || !strings.Contains(body, bb.capAPIEndpoint()) {
		t.Fatalf("Challenge-Seite enthaelt kein Cap-Widget: %s", body)
	}
}

func TestServeHTTPAllowsVerifiedClientViaCookie(t *testing.T) {
	bb := newTestProtector(t)
	rrCookie := httptest.NewRecorder()
	if err := bb.writeAllowCookie(rrCookie, time.Now()); err != nil {
		t.Fatalf("writeAllowCookie() error = %v", err)
	}
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	for _, cookie := range rrCookie.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	called := false
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusNoContent)
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !called {
		t.Fatal("next handler wurde nicht aufgerufen")
	}
}

func TestServeHTTPAllowsAllowlistedIPv4Client(t *testing.T) {
	bb := newTestProtector(t)
	bb.allowlist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}})
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	called := false
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusNoContent)
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !called {
		t.Fatal("Allowlist sollte Request durchlassen")
	}
}

func TestServeHTTPCountryWhitelistBlocksAllowlistedClientBeforeAllowlist(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistCountries = []string{"DE"}
	bb.CountryURL = "http://localhost/dev-country.mmdb"
	bb.testCountryLookup = func(netip.Addr) (string, bool) { return "US", true }
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	bb.allowlist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}})
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()
	called := false
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called || !rr.conn.closed {
		t.Fatal("Country-Whitelist sollte vor der Allowlist greifen")
	}
}

func TestServeHTTPCountryWhitelistBlocksVerifiedCookieBeforeCookieCheck(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistCountries = []string{"DE"}
	bb.CountryURL = "http://localhost/dev-country.mmdb"
	bb.testCountryLookup = func(netip.Addr) (string, bool) { return "US", true }
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	rrCookie := httptest.NewRecorder()
	if err := bb.writeAllowCookie(rrCookie, time.Now()); err != nil {
		t.Fatalf("writeAllowCookie() error = %v", err)
	}
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	for _, cookie := range rrCookie.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rr := newHijackableResponseWriter()
	called := false
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called || !rr.conn.closed {
		t.Fatal("Country-Whitelist sollte vor dem Freigabe-Cookie greifen")
	}
}

func TestServeHTTPBlocksBlacklistedIPv4Client(t *testing.T) {
	bb := newTestProtector(t)
	bb.blacklist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}})
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()
	called := false
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called || !rr.conn.closed {
		t.Fatal("Blacklist sollte die Verbindung schliessen")
	}
}

func TestServeHTTPBlacklistedClientFallsBackToAbortHandlerWithoutHijacker(t *testing.T) {
	bb := newTestProtector(t)
	bb.blacklist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}})
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	defer func() {
		recovered := recover()
		if !errors.Is(recovered.(error), http.ErrAbortHandler) {
			t.Fatalf("recover() = %v, erwartet http.ErrAbortHandler", recovered)
		}
	}()
	_ = bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil }))
	t.Fatal("erwarteter Abort blieb aus")
}

func TestServeHTTPRejectsNonPostVerifyPathBeforeAllowlist(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com"+bb.VerifyPath, "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("verify request darf nicht weitergereicht werden")
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestServeHTTPDropsDenyPathPrefixBeforeChallenge(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyPathPrefixes = []string{"/wp-admin"}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	req := newChallengeRequest(http.MethodGet, "http://example.com/wp-admin/install.php", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()
	if err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler sollte nicht aufgerufen werden")
		return nil
	})); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte geschlossen werden")
	}
}

func TestLoadAllowlistMergesInlineFileAndURL(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "goodbots-*.ips")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	t.Cleanup(func() {
		if err := tmpFile.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if _, err := tmpFile.WriteString("198.51.100.0/24\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("2001:db8::/32\n"))
	}))
	defer server.Close()
	bb := newTestProtector(t)
	bb.WhitelistIPs = []string{"192.0.2.1", "192.0.2.1 # duplicate"}
	bb.WhitelistFile = tmpFile.Name()
	bb.WhitelistURL = server.URL
	allowlist, err := bb.loadAllowlist(context.Background())
	if err != nil {
		t.Fatalf("loadAllowlist() error = %v", err)
	}
	if _, ok := allowlist.exactIPs[netip.MustParseAddr("192.0.2.1")]; !ok {
		t.Fatal("Inline-IP fehlt")
	}
	if allowlist.entries != 3 {
		t.Fatalf("entries = %d", allowlist.entries)
	}
}

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
	req := httptest.NewRequest(http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func newChallengeRequest(method, rawURL, clientIP, userAgent string) *http.Request {
	req := httptest.NewRequest(method, rawURL, nil)
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{"client_ip": clientIP})
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", userAgent)
	return req
}
