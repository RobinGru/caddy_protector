package caddyprotector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
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
	"github.com/zeebo/blake3"
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
	return &hijackableResponseWriter{
		header: make(http.Header),
		conn:   &testConn{},
	}
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

func (c *testConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *testConn) Write(p []byte) (int, error)        { if c.closed { return 0, net.ErrClosed }; return len(p), nil }
func (c *testConn) Close() error                       { c.closed = true; return nil }
func (c *testConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(_ time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestValidateRejectsNegativeComplexity(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "-1"

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "complexity muss mindestens 0 sein") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsImpossibleComplexity(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "257"

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "höchstens 256") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingSecret(t *testing.T) {
	bb := newTestProtector(t)
	bb.Secret = ""
	bb.challengeMACKey = nil
	bb.cookieMACKey = nil

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "secret oder secret_file") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsBadCookieSameSite(t *testing.T) {
	bb := newTestProtector(t)
	bb.CookieSameSite = "kaputt"

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "cookie_same_site") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsBadWhitelistURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistURL = "://bad-url"

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "whitelist_url") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingCountryURLWhenCountriesConfigured(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistCountries = []string{"DE"}

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "country_url") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDecodeVerifyRequestAcceptsJSON(t *testing.T) {
	body := `{"challengeToken":"abc.def","nonce":"abcd"}`

	req, info, err := decodeVerifyRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("decodeVerifyRequest() error = %v", err)
	}
	if req.ChallengeToken != "abc.def" || req.Nonce != "abcd" {
		t.Fatalf("decodeVerifyRequest() = %#v", req)
	}
	if info.BodyLength != len(body) {
		t.Fatalf("BodyLength = %d", info.BodyLength)
	}
}

func TestDecodeVerifyRequestRejectsUnknownFields(t *testing.T) {
	_, _, err := decodeVerifyRequest(strings.NewReader(`{"challengeToken":"abc.def","nonce":"abcd","extra":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decodeVerifyRequest() error = %v", err)
	}
}

func TestChallengeTokenRoundTrip(t *testing.T) {
	bb := newTestProtector(t)
	now := time.Now()
	token, err := bb.createChallengeToken(strings.Repeat("11", challengeSeedLength), "/protected?x=1", 8, now)
	if err != nil {
		t.Fatalf("createChallengeToken() error = %v", err)
	}

	claims, err := bb.verifyChallengeToken(token, now)
	if err != nil {
		t.Fatalf("verifyChallengeToken() error = %v", err)
	}
	if claims.ReturnPath != "/protected?x=1" || claims.Complexity != 8 {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestChallengeTokenRejectsTampering(t *testing.T) {
	bb := newTestProtector(t)
	token, err := bb.createChallengeToken(strings.Repeat("11", challengeSeedLength), "/protected", 8, time.Now())
	if err != nil {
		t.Fatalf("createChallengeToken() error = %v", err)
	}

	_, err = bb.verifyChallengeToken(token+"x", time.Now())
	if err == nil {
		t.Fatal("manipuliertes Token sollte fehlschlagen")
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

func TestAllowCookieRejectsExpiredClaims(t *testing.T) {
	bb := newTestProtector(t)
	raw, err := bb.signValue(allowCookieClaims{
		Version:   tokenVersion,
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}, bb.cookieMACKey)
	if err != nil {
		t.Fatalf("signValue() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.AddCookie(&http.Cookie{Name: bb.CookieName, Value: raw})
	if bb.hasValidAllowCookie(req) {
		t.Fatal("abgelaufenes Cookie sollte nicht akzeptiert werden")
	}
}

func TestHandleVerifyRejectsWrongContentType(t *testing.T) {
	bb := newTestProtector(t)
	token, claims := newChallengeTokenFor(t, bb, "/protected", 8, time.Now())
	seedBytes, _ := hex.DecodeString(claims.Seed)
	req := verifyRequestFor(t, token, findNonceHex(t, seedBytes, 8))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	if err := bb.handleVerify(rr, req, 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestVerifyRejectsBadChallengeToken(t *testing.T) {
	bb := newTestProtector(t)
	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, "kaputt", "abcd")

	if err := bb.handleVerify(rr, req, 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestVerifyRejectsWrongNonce(t *testing.T) {
	bb := newTestProtector(t)
	token, _ := newChallengeTokenFor(t, bb, "/protected", 8, time.Now())
	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, token, "00")

	if err := bb.handleVerify(rr, req, 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestVerifyAcceptsCorrectNonce(t *testing.T) {
	bb := newTestProtector(t)
	token, claims := newChallengeTokenFor(t, bb, "/protected?x=1", 8, time.Now())
	seedBytes, _ := hex.DecodeString(claims.Seed)
	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, token, findNonceHex(t, seedBytes, 8))

	if err := bb.handleVerify(rr, req, 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d", rr.Code)
	}
	if len(rr.Result().Cookies()) == 0 {
		t.Fatal("Verify sollte ein Freigabe-Cookie setzen")
	}

	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got := res["returnTo"]; got != "/protected?x=1" {
		t.Fatalf("returnTo = %v", got)
	}
}

func TestSafeReturnPathFrom(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/", "/"},
		{"/foo/bar/../baz", "/foo/baz"},
		{"//evil.example/path", "/"},
		{"", "/"},
	}

	for _, tc := range tests {
		if got := safeReturnPathFrom(tc.input); got != tc.want {
			t.Fatalf("safeReturnPathFrom(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestGetOriginalPathUsesOrigURIFromReplacer(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/", "192.0.2.1", "UA")
	repl, _ := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.request.orig_uri", "/2026-domaintester/?x=1")

	if got := bb.getOriginalPath(req); got != "/2026-domaintester/?x=1" {
		t.Fatalf("getOriginalPath() = %q", got)
	}
}

func TestLoadAllowlistMergesInlineFileAndURL(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "goodbots-*.ips")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer tmpFile.Close()
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
		t.Fatal("Inline-IP fehlt in der Allowlist")
	}
	if allowlist.entries != 3 {
		t.Fatalf("entries = %d", allowlist.entries)
	}
}

func TestNoSetCookieHeaderOnChallengePage(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if got := rr.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("unerwartete Set-Cookie-Header: %v", got)
	}
}

func TestServeChallengeSetsCSPHeader(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler should not be called")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	got := rr.Header().Get("Content-Security-Policy")
	if got == "" || !strings.Contains(got, "script-src 'nonce-") {
		t.Fatalf("unerwarteter CSP-Header: %s", got)
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

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !called {
		t.Fatal("next handler wurde nicht aufgerufen")
	}
}

func TestServeHTTPAllowsAllowlistedIPv4Client(t *testing.T) {
	bb := newTestProtector(t)
	bb.allowlist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{
		netip.MustParseAddr("192.0.2.1"): {},
	}})

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	called := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !called {
		t.Fatal("Allowlist sollte Request durchlassen")
	}
}

func TestServeHTTPBlocksBlacklistedIPv4Client(t *testing.T) {
	bb := newTestProtector(t)
	bb.blacklist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{
		netip.MustParseAddr("192.0.2.1"): {},
	}})

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()
	called := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called {
		t.Fatal("Blacklist sollte Request blockieren")
	}
}

func TestServeHTTPRejectsNonPostVerifyPathBeforeAllowlist(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com"+bb.VerifyPath, "192.0.2.1", "UA")
	rr := httptest.NewRecorder()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("verify request darf nicht weitergereicht werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestServeHTTPVerifyPathIsInterceptedWhenComplexityIsZero(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "0"
	req := verifyRequestFor(t, "abc.def", "abcd")
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{"client_ip": "192.0.2.1"}))
	rr := httptest.NewRecorder()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("verify request darf nicht weitergereicht werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("Status = %d", rr.Code)
	}
}

func TestBLAKE3Vector(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	nonceHex := "000102030405060708090a0b0c0d0e0f"
	expected := "c69e86514b4b59e4a7296fc05db8f4c1dd17825679f25d97d285b970aa2ea853"

	seed, _ := hex.DecodeString(seedHex)
	nonce, _ := hex.DecodeString(nonceHex)
	sum := blake3.Sum256(append(append([]byte(nil), seed...), nonce...))
	if got := hex.EncodeToString(sum[:]); got != expected {
		t.Fatalf("Hash = %s, erwartet %s", got, expected)
	}
}

func newTestProtector(t *testing.T) *CaddyProtector {
	t.Helper()
	bb := &CaddyProtector{
		Complexity:     "8",
		ValidFor:       caddy.Duration(defaultValidFor),
		AllowFor:       caddy.Duration(defaultAllowFor),
		VerifyPath:     defaultVerifyPath,
		CookieName:     defaultCookieName,
		CookiePath:     "/",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		Secret:         "test-secret",
		logger:         zaptest.NewLogger(t),
	}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	bb.allowlist.Store(&ipAllowlist{exactIPs: make(map[netip.Addr]struct{})})
	bb.blacklist.Store(&ipAllowlist{exactIPs: make(map[netip.Addr]struct{})})
	return bb
}

func newChallengeTokenFor(t *testing.T, bb *CaddyProtector, returnPath string, complexity int, now time.Time) (string, challengeTokenClaims) {
	t.Helper()
	seed := make([]byte, challengeSeedLength)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	seedHex := hex.EncodeToString(seed)
	token, err := bb.createChallengeToken(seedHex, returnPath, complexity, now)
	if err != nil {
		t.Fatalf("createChallengeToken() error = %v", err)
	}
	claims, err := bb.verifyChallengeToken(token, now)
	if err != nil {
		t.Fatalf("verifyChallengeToken() error = %v", err)
	}
	return token, claims
}

func verifyRequestFor(t *testing.T, challengeToken, nonceHex string) *http.Request {
	t.Helper()
	body, err := json.Marshal(verifyRequest{ChallengeToken: challengeToken, Nonce: nonceHex})
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

func findNonceHex(t *testing.T, seed []byte, complexity int) string {
	t.Helper()
	nonce := make([]byte, 4)
	for i := 0; ; i++ {
		nonce[0] = byte(i >> 24)
		nonce[1] = byte(i >> 16)
		nonce[2] = byte(i >> 8)
		nonce[3] = byte(i)

		sum := blake3.Sum256(append(append([]byte(nil), seed...), nonce...))
		if countLeadingZeroBits(sum[:]) >= complexity {
			return hex.EncodeToString(nonce)
		}
	}
}
