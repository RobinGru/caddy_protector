package caddyprotector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
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

func TestValidateRejectsBadBlacklistURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.BlacklistURL = "://bad-url"

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "blacklist_url") {
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

func TestValidateRejectsBadCountryCode(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistCountries = []string{"D3"}
	bb.CountryURL = "https://example.com/GeoLite2-Country.mmdb"

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "whitelist_country") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsBadCSPScriptSrc(t *testing.T) {
	tests := []string{
		" https://example.com",
		"https://example.com; default-src 'none'",
		"https://example.com\nhttps://evil.example",
		"",
	}

	for _, source := range tests {
		t.Run(source, func(t *testing.T) {
			bb := newTestProtector(t)
			bb.CSPScriptSrc = []string{source}

			err := bb.Validate()
			if err == nil || !strings.Contains(err.Error(), "csp_script_src") {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestValidateAcceptsSafeCSPScriptSrc(t *testing.T) {
	bb := newTestProtector(t)
	bb.CSPScriptSrc = []string{"https://example.com", "'strict-dynamic'"}

	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsEmptyDenyPathPrefix(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyPathPrefixes = []string{"   "}

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "deny_path_prefix") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsEmptyDenyQuerySubstring(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyQuerySubstrings = []string{""}

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "deny_query_substring") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsEmptyDenyHeaderSubstringName(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyHeaderSubstrings = []HeaderSubstringRule{{Name: " ", Needle: "sqlmap"}}

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "header-name") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsEmptyDenyHeaderSubstringNeedle(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyHeaderSubstrings = []HeaderSubstringRule{{Name: "User-Agent", Needle: " "}}

	err := bb.Validate()
	if err == nil || !strings.Contains(err.Error(), "deny_header_substring") {
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

func TestWriteAllowCookieHonorsExplicitFalseFlags(t *testing.T) {
	bb := newTestProtector(t)
	bb.CookieSecure = boolPtr(false)
	bb.CookieHTTPOnly = boolPtr(false)

	rr := httptest.NewRecorder()
	if err := bb.writeAllowCookie(rr, time.Now()); err != nil {
		t.Fatalf("writeAllowCookie() error = %v", err)
	}

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, erwartet 1", len(cookies))
	}
	if cookies[0].Secure {
		t.Fatal("Cookie sollte Secure=false respektieren")
	}
	if cookies[0].HttpOnly {
		t.Fatal("Cookie sollte HttpOnly=false respektieren")
	}
}

func TestHandleVerifyRejectsWrongContentType(t *testing.T) {
	bb := newTestProtector(t)
	token, claims := newChallengeTokenFor(t, bb, "/protected", 8, time.Now())
	seedBytes, _ := hex.DecodeString(claims.Seed)
	req := verifyRequestFor(t, token, findNonceHex(t, seedBytes, 8))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	if err := bb.handleVerify(rr, req); err != nil {
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

	if err := bb.handleVerify(rr, req); err != nil {
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

	if err := bb.handleVerify(rr, req); err != nil {
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

	if err := bb.handleVerify(rr, req); err != nil {
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

func TestVerifyAcceptsTokenComplexityIndependentFromVerifyRequestComplexity(t *testing.T) {
	bb := newTestProtector(t)
	token, claims := newChallengeTokenFor(t, bb, "/protected", 8, time.Now())
	seedBytes, _ := hex.DecodeString(claims.Seed)
	req := verifyRequestFor(t, token, findNonceHex(t, seedBytes, 8))

	repl := caddy.NewReplacer()
	repl.Set("vars.caddy_protector_complexity", "0")
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, req); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusOK)
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

func TestParseAllowlistEntryAcceptsCommentsAndCIDR(t *testing.T) {
	entry, err := parseAllowlistEntry("inline", 1, "2001:db8::/32 # good bot")
	if err != nil {
		t.Fatalf("parseAllowlistEntry() error = %v", err)
	}
	if entry == nil || entry.prefix.String() != "2001:db8::/32" {
		t.Fatalf("Entry = %#v, erwartet Prefix 2001:db8::/32", entry)
	}

	entry, err = parseAllowlistEntry("inline", 2, "# nur Kommentar")
	if err != nil {
		t.Fatalf("parseAllowlistEntry() error = %v", err)
	}
	if entry != nil {
		t.Fatalf("Kommentar sollte ignoriert werden, erhalten: %#v", entry)
	}
}

func TestLoadAllowlistRejectsInvalidInlineEntry(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistIPs = []string{"kaputt"}

	_, err := bb.loadAllowlist(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Allowlist-Eintrag") {
		t.Fatalf("loadAllowlist() error = %v", err)
	}
}

func TestLoadBlacklistMergesInlineFileAndURL(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "badbots-*.ips")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer tmpFile.Close()
	if _, err := tmpFile.WriteString("203.0.113.0/24\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("2001:db8:bad::/48\n"))
	}))
	defer server.Close()

	bb := newTestProtector(t)
	bb.BlacklistIPs = []string{"198.51.100.7", "198.51.100.7 # duplicate"}
	bb.BlacklistFile = tmpFile.Name()
	bb.BlacklistURL = server.URL

	blacklist, err := bb.loadBlacklist(context.Background())
	if err != nil {
		t.Fatalf("loadBlacklist() error = %v", err)
	}
	if _, ok := blacklist.exactIPs[netip.MustParseAddr("198.51.100.7")]; !ok {
		t.Fatal("Inline-IP fehlt in der Blacklist")
	}
	if blacklist.entries != 3 {
		t.Fatalf("entries = %d", blacklist.entries)
	}
}

func TestLoadBlacklistRejectsMissingFile(t *testing.T) {
	bb := newTestProtector(t)
	bb.BlacklistFile = t.TempDir() + "\\missing.ips"

	_, err := bb.loadBlacklist(context.Background())
	if err == nil || !strings.Contains(err.Error(), "blacklist_file") {
		t.Fatalf("loadBlacklist() error = %v", err)
	}
}

func TestAllowlistRefreshKeepsPreviousSnapshotOnFailure(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "goodbots-*.ips")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer tmpFile.Close()
	if _, err := tmpFile.WriteString("192.0.2.1\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	bb := newTestProtector(t)
	bb.WhitelistFile = tmpFile.Name()
	allowlist, err := bb.loadAllowlist(context.Background())
	if err != nil {
		t.Fatalf("loadAllowlist() error = %v", err)
	}
	bb.allowlist.Store(allowlist)

	if err := os.WriteFile(tmpFile.Name(), []byte("kaputt\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := bb.loadAllowlist(context.Background()); err == nil {
		t.Fatal("erwarteter Refresh-Fehler fehlt")
	}
	if !bb.isAllowlisted(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("vorherige Allowlist sollte aktiv bleiben")
	}
}

func TestFetchURLBytesLimitedRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer server.Close()

	bb := newTestProtector(t)
	_, err := bb.fetchURLBytesLimited(context.Background(), "whitelist", server.URL, 5)
	if err == nil || !strings.Contains(err.Error(), "zu gross") {
		t.Fatalf("fetchURLBytesLimited() error = %v", err)
	}
}

func TestFetchURLBytesLimitedRejectsOversizedContentLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "6")
		_, _ = w.Write([]byte("abc"))
	}))
	defer server.Close()

	bb := newTestProtector(t)
	_, err := bb.fetchURLBytesLimited(context.Background(), "country", server.URL, 5)
	if err == nil || !strings.Contains(err.Error(), "zu gross") {
		t.Fatalf("fetchURLBytesLimited() error = %v", err)
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

func TestServeHTTPAllowsAllowlistedIPv6Prefix(t *testing.T) {
	bb := newTestProtector(t)
	bb.allowlist.Store(&ipAllowlist{
		exactIPs: make(map[netip.Addr]struct{}),
		prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	})

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "2001:db8::1234", "UA")
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
		t.Fatal("IPv6-Prefix-Allowlist sollte Request durchlassen")
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
	if !rr.conn.closed {
		t.Fatal("Blacklist sollte die Verbindung schliessen")
	}
}

func TestServeHTTPBlacklistBeatsAllowlist(t *testing.T) {
	bb := newTestProtector(t)
	addr := netip.MustParseAddr("192.0.2.1")
	bb.allowlist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{addr: {}}})
	bb.blacklist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{addr: {}}})

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
		t.Fatal("Blacklist muss vor Allowlist greifen")
	}
	if !rr.conn.closed {
		t.Fatal("Blacklist muss die Verbindung vor der Allowlist schliessen")
	}
}

func TestServeHTTPBlacklistedClientFallsBackToAbortHandlerWithoutHijacker(t *testing.T) {
	bb := newTestProtector(t)
	bb.blacklist.Store(&ipAllowlist{
		exactIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}},
	})

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	called := false

	defer func() {
		recovered := recover()
		if !errors.Is(recovered.(error), http.ErrAbortHandler) {
			t.Fatalf("recover() = %v, erwartet http.ErrAbortHandler", recovered)
		}
		if called {
			t.Fatal("blacklisted Traffic darf im Abort-Fallback nicht weitergereicht werden")
		}
	}()

	_ = bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	}))
	t.Fatal("erwarteter Abort fuer nicht hijackbaren ResponseWriter blieb aus")
}

func TestServeHTTPCountryBlacklistBlocksBeforeIPAllowlist(t *testing.T) {
	bb := newTestProtector(t)
	addr := netip.MustParseAddr("192.0.2.1")
	bb.BlacklistCountries = []string{"RU"}
	bb.CountryURL = "https://example.com/GeoLite2-Country.mmdb"
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	bb.testCountryLookup = func(got netip.Addr) (string, bool) {
		if got != addr {
			t.Fatalf("lookup addr = %v, erwartet %v", got, addr)
		}
		return "RU", true
	}
	bb.allowlist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{addr: {}}})

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
		t.Fatal("Country-Blacklist darf nicht von der IP-Allowlist uebersteuert werden")
	}
	if !rr.conn.closed {
		t.Fatal("Country-Blacklist sollte die Verbindung schliessen")
	}
}

func TestServeHTTPCountryWhitelistStillServesChallenge(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistCountries = []string{"DE"}
	bb.CountryURL = "https://example.com/GeoLite2-Country.mmdb"
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	bb.testCountryLookup = func(netip.Addr) (string, bool) {
		return "DE", true
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("Country-Whitelist darf nicht direkt freigeben")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Code != http.StatusOK || rr.Header().Get("X-Bot-Barrier") != "challenge" {
		t.Fatalf("Status=%d X-Bot-Barrier=%q", rr.Code, rr.Header().Get("X-Bot-Barrier"))
	}
}

func TestServeHTTPCountryWhitelistAllowsFurtherIPAllowlist(t *testing.T) {
	bb := newTestProtector(t)
	addr := netip.MustParseAddr("192.0.2.1")
	bb.WhitelistCountries = []string{"DE"}
	bb.CountryURL = "https://example.com/GeoLite2-Country.mmdb"
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	bb.testCountryLookup = func(netip.Addr) (string, bool) {
		return "DE", true
	}
	bb.allowlist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{addr: {}}})

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
		t.Fatal("IP-Allowlist sollte nach erfolgreichem Country-Gate weiter greifen")
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

func TestServeHTTPDropsDenyPathPrefixBeforeChallenge(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyPathPrefixes = []string{"/wp-admin"}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/wp-admin/install.php", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()
	nextCalled := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if nextCalled {
		t.Fatal("next handler sollte bei deny_path_prefix nicht aufgerufen werden")
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte bei deny_path_prefix geschlossen werden")
	}
}

func TestServeHTTPDropsDenyQuerySubstringOnRawQuery(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyQuerySubstrings = []string{"union select"}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/search?q=1+UNION+SELECT+1", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler sollte bei deny_query_substring nicht aufgerufen werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte bei deny_query_substring geschlossen werden")
	}
}

func TestServeHTTPDropsDenyQuerySubstringAfterOneDecode(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyQuerySubstrings = []string{"../"}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/download?file=%2e%2e%2fetc%2fpasswd", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler sollte bei dekodierter deny_query_substring nicht aufgerufen werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte bei dekodierter deny_query_substring geschlossen werden")
	}
}

func TestServeHTTPDropsDenyHeaderSubstring(t *testing.T) {
	bb := newTestProtector(t)
	bb.DenyHeaderSubstrings = []HeaderSubstringRule{{Name: "User-Agent", Needle: "sqlmap"}}
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "Mozilla/5.0 sqlmap")
	rr := newHijackableResponseWriter()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler sollte bei deny_header_substring nicht aufgerufen werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte bei deny_header_substring geschlossen werden")
	}
}

func TestServeHTTPDropsBuiltInPathRuleByDefault(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/.git/config", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler sollte bei built-in path rule nicht aufgerufen werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte bei built-in path rule geschlossen werden")
	}
}

func TestServeHTTPDropsBuiltInPathRuleAfterOneDecode(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/%2egit/config", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler sollte bei URL-kodierter built-in path rule nicht aufgerufen werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte bei URL-kodierter built-in path rule geschlossen werden")
	}
}

func TestServeHTTPDisablesBuiltInHeaderRuleWhenConfiguredOff(t *testing.T) {
	bb := newTestProtector(t)
	bb.BuiltInRules = boolPtr(false)
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "Mozilla/5.0 sqlmap")
	rr := httptest.NewRecorder()
	nextCalled := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if nextCalled {
		t.Fatal("ohne Cookie und ohne built-in rule sollte weiterhin die Challenge ausgeliefert werden, nicht der Upstream")
	}
	if got := rr.Header().Get("X-Bot-Barrier"); got != "challenge" {
		t.Fatalf("X-Bot-Barrier = %q, erwartet challenge", got)
	}
}

func TestServeHTTPDoesNotApplyAggressiveBuiltInPathRuleByDefault(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/graphql", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("ohne Cookie sollte weiterhin die Challenge ausgeliefert werden, nicht der Upstream")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if got := rr.Header().Get("X-Bot-Barrier"); got != "challenge" {
		t.Fatalf("X-Bot-Barrier = %q, erwartet challenge", got)
	}
}

func TestServeHTTPAppliesAggressiveBuiltInPathRuleWhenEnabled(t *testing.T) {
	bb := newTestProtector(t)
	bb.AggressiveBuiltInRules = boolPtr(true)
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/graphql", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler sollte bei aggressive built-in path rule nicht aufgerufen werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Verbindung sollte bei aggressive built-in path rule geschlossen werden")
	}
}

func TestServeHTTPAppliesRequestRulesBeforeAllowlist(t *testing.T) {
	bb := newTestProtector(t)
	bb.allowlist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{
		netip.MustParseAddr("192.0.2.1"): {},
	}})

	req := newChallengeRequest(http.MethodGet, "http://example.com/.git/config", "192.0.2.1", "UA")
	rr := newHijackableResponseWriter()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("Allowlist darf Built-in Request-Regeln nicht uebersteuern")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if !rr.conn.closed {
		t.Fatal("Built-in Request-Regeln sollten vor Allowlist schliessen")
	}
}

func TestServeHTTPVerifyPathAllowsValidTokenWhenComplexityIsZero(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "0"
	token, claims := newChallengeTokenFor(t, bb, "/protected", 8, time.Now())
	seedBytes, _ := hex.DecodeString(claims.Seed)
	req := verifyRequestFor(t, token, findNonceHex(t, seedBytes, 8))
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{"client_ip": "192.0.2.1"}))
	rr := httptest.NewRecorder()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("verify request darf nicht weitergereicht werden")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Code != http.StatusOK {
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
		CookieSecure:   boolPtr(true),
		CookieHTTPOnly: boolPtr(true),
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
