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

func (w *hijackableResponseWriter) Header() http.Header {
	return w.header
}

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

type testConn struct {
	closed bool
}

func (c *testConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *testConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (c *testConn) Close() error {
	c.closed = true
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *testConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *testConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func TestValidateRejectsNegativeComplexity(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "-1"

	err := bb.Validate()
	if err == nil {
		t.Fatal("erwarteter Fehler für negative Complexity fehlt")
	}
	if !strings.Contains(err.Error(), "complexity muss mindestens 0 sein") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf Mindestwert", err)
	}
}

func TestValidateRejectsImpossibleComplexity(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "257"

	err := bb.Validate()
	if err == nil {
		t.Fatal("erwarteter Fehler für unmögliche Complexity fehlt")
	}
	if !strings.Contains(err.Error(), "höchstens 256") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf BLAKE3-256-Grenze", err)
	}
}

func TestValidateRejectsBadWhitelistURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistURL = "://bad-url"

	err := bb.Validate()
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltige whitelist_url fehlt")
	}
	if !strings.Contains(err.Error(), "whitelist_url") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf whitelist_url", err)
	}
}

func TestValidateRejectsBadBlacklistURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.BlacklistURL = "://bad-url"

	err := bb.Validate()
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltige blacklist_url fehlt")
	}
	if !strings.Contains(err.Error(), "blacklist_url") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf blacklist_url", err)
	}
}

func TestResolveComplexityFallsBackForImpossiblePlaceholderValue(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "{vars.caddy_protector_complexity}"
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	repl := caddy.NewReplacer()
	repl.Set("vars.caddy_protector_complexity", "257")
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

	got := bb.resolveComplexity(req, bb.logger)
	if got != 16 {
		t.Fatalf("resolveComplexity() = %d, erwartet Fallback 16", got)
	}
}

func TestClientKey(t *testing.T) {
	got := clientKey("192.0.2.1", "UA")
	want := "192.0.2.1\x00UA"
	if got != want {
		t.Fatalf("clientKey() = %q, want %q", got, want)
	}
}

func TestAllowedExpires(t *testing.T) {
	bb := newTestProtector(t)
	key := clientKey("192.0.2.1", "UA")

	bb.mu.Lock()
	bb.allowed[key] = time.Now().Add(-time.Second)
	bb.mu.Unlock()

	if bb.isAllowed(key) {
		t.Fatal("erwarteter Ablauf des Freigabe-Eintrags ist ausgeblieben")
	}
	if _, ok := bb.allowed[key]; ok {
		t.Fatal("abgelaufener Freigabe-Eintrag wurde nicht entfernt")
	}
}

func TestPendingChallengeExpires(t *testing.T) {
	bb := newTestProtector(t)

	bb.mu.Lock()
	bb.pending["seed"] = pendingChallenge{
		Key:       "client",
		Seed:      bytes.Repeat([]byte{0x01}, challengeSeedLength),
		ExpiresAt: time.Now().Add(-time.Second),
	}
	bb.cleanupExpiredLocked(time.Now())
	_, ok := bb.pending["seed"]
	bb.mu.Unlock()

	if ok {
		t.Fatal("abgelaufene Pending-Challenge wurde nicht entfernt")
	}
}

func TestDecodeVerifyRequestAcceptsJSON(t *testing.T) {
	body := `{"seed":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","nonce":"abcd"}`

	req, info, err := decodeVerifyRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("decodeVerifyRequest() error = %v", err)
	}
	if req.Seed != "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" {
		t.Fatalf("Seed = %q", req.Seed)
	}
	if req.Nonce != "abcd" {
		t.Fatalf("Nonce = %q", req.Nonce)
	}
	if info.BodyLength != len(body) {
		t.Fatalf("BodyLength = %d, erwartet %d", info.BodyLength, len(body))
	}
}

func TestDecodeVerifyRequestRejectsMalformedJSON(t *testing.T) {
	_, info, err := decodeVerifyRequest(strings.NewReader(`{"seed":`))
	if err == nil {
		t.Fatal("erwarteter Fehler für ungültiges JSON fehlt")
	}
	if info.BodyLength == 0 {
		t.Fatal("erwartete Body-Debug-Information fehlt")
	}
}

func TestDecodeVerifyRequestRejectsUnknownFields(t *testing.T) {
	body := `{"seed":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","nonce":"abcd","extra":true}`

	_, _, err := decodeVerifyRequest(strings.NewReader(body))
	if err == nil {
		t.Fatal("erwarteter Fehler für unbekanntes JSON-Feld fehlt")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf unbekanntes Feld", err)
	}
}

func TestHandleVerifyRejectsWrongContentType(t *testing.T) {
	bb := newTestProtector(t)
	seedHex, pending := addPendingChallenge(t, bb, clientKey("192.0.2.1", "UA"), "/protected")
	nonceHex := findNonceHex(t, pending.Seed, 8)
	req := verifyRequestFor(t, seedHex, nonceHex)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	if err := bb.handleVerify(rr, req, clientKey("192.0.2.1", "UA"), 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusUnsupportedMediaType)
	}
}

func TestVerifyRejectsUnknownSeed(t *testing.T) {
	bb := newTestProtector(t)

	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "abcd")
	if err := bb.handleVerify(rr, req, clientKey("192.0.2.1", "UA"), 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusForbidden)
	}
}

func TestVerifyRejectsWrongIPUA(t *testing.T) {
	bb := newTestProtector(t)
	seedHex, pending := addPendingChallenge(t, bb, clientKey("192.0.2.1", "UA"), "/protected")
	nonceHex := findNonceHex(t, pending.Seed, 8)

	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, seedHex, nonceHex)
	if err := bb.handleVerify(rr, req, clientKey("198.51.100.7", "Other"), 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusForbidden)
	}
}

func TestVerifyRejectsWrongNonce(t *testing.T) {
	bb := newTestProtector(t)
	seedHex, _ := addPendingChallenge(t, bb, clientKey("192.0.2.1", "UA"), "/protected")

	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, seedHex, "00")
	if err := bb.handleVerify(rr, req, clientKey("192.0.2.1", "UA"), 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusForbidden)
	}
}

func TestVerifyAcceptsCorrectNonce(t *testing.T) {
	bb := newTestProtector(t)
	seedHex, pending := addPendingChallenge(t, bb, clientKey("192.0.2.1", "UA"), "/protected?x=1")
	nonceHex := findNonceHex(t, pending.Seed, 8)

	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, seedHex, nonceHex)
	if err := bb.handleVerify(rr, req, clientKey("192.0.2.1", "UA"), 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusOK)
	}

	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if ok, _ := res["ok"].(bool); !ok {
		t.Fatalf("erwartet war ok=true, erhalten: %v", res["ok"])
	}
	if got := res["returnTo"]; got != "/protected?x=1" {
		t.Fatalf("returnTo = %v, erwartet %q", got, "/protected?x=1")
	}
}

func TestVerifyDeletesPendingAfterSuccess(t *testing.T) {
	bb := newTestProtector(t)
	seedHex, pending := addPendingChallenge(t, bb, clientKey("192.0.2.1", "UA"), "/protected")
	nonceHex := findNonceHex(t, pending.Seed, 8)

	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, seedHex, nonceHex)
	_ = bb.handleVerify(rr, req, clientKey("192.0.2.1", "UA"), 8)

	bb.mu.Lock()
	_, ok := bb.pending[seedHex]
	bb.mu.Unlock()

	if ok {
		t.Fatal("Pending-Challenge wurde nach Erfolg nicht gelöscht")
	}
}

func TestVerifyMarksAllowedForAllowForDuration(t *testing.T) {
	bb := newTestProtector(t)
	seedHex, pending := addPendingChallenge(t, bb, clientKey("192.0.2.1", "UA"), "/protected")
	nonceHex := findNonceHex(t, pending.Seed, 8)
	key := clientKey("192.0.2.1", "UA")

	before := time.Now()
	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, seedHex, nonceHex)
	_ = bb.handleVerify(rr, req, key, 8)

	bb.mu.Lock()
	exp, ok := bb.allowed[key]
	bb.mu.Unlock()

	if !ok {
		t.Fatal("Client wurde nicht freigegeben")
	}
	minExp := before.Add(time.Duration(bb.AllowFor) - time.Second)
	maxExp := before.Add(time.Duration(bb.AllowFor) + time.Second)
	if exp.Before(minExp) || exp.After(maxExp) {
		t.Fatalf("Freigabe-Ablauf = %v, erwartet zwischen %v und %v", exp, minExp, maxExp)
	}
}

func TestCreatePendingChallengeStoresReturnPath(t *testing.T) {
	bb := newTestProtector(t)
	key := clientKey("192.0.2.1", "UA")

	seedHex, pending := addPendingChallenge(t, bb, key, "/geschuetzt?x=1")
	if seedHex == "" {
		t.Fatal("erwarteter Seed fehlt")
	}
	if pending.Key != key {
		t.Fatalf("pending.Key = %q, want %q", pending.Key, key)
	}
	if pending.ReturnPath != "/geschuetzt?x=1" {
		t.Fatalf("pending.ReturnPath = %q, want %q", pending.ReturnPath, "/geschuetzt?x=1")
	}
}

func TestSafeReturnPathRejectsSchemeRelativePath(t *testing.T) {
	req := newChallengeRequest(http.MethodGet, "http://example.com//evil.example/path?token=secret", "192.0.2.1", "UA")

	if got := safeReturnPath(req); got != "/" {
		t.Fatalf("safeReturnPath() = %q, erwartet /", got)
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
	if len(allowlist.prefixes) != 2 {
		t.Fatalf("prefixes = %d, erwartet 2", len(allowlist.prefixes))
	}
	if allowlist.entries != 3 {
		t.Fatalf("entries = %d, erwartet 3 deduplizierte Eintraege", allowlist.entries)
	}
}

func TestLoadAllowlistRejectsInvalidInlineEntry(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistIPs = []string{"kaputt"}

	_, err := bb.loadAllowlist(context.Background())
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungÃ¼ltigen Inline-Eintrag fehlt")
	}
	if !strings.Contains(err.Error(), "Allowlist-Eintrag") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf den Eintrag", err)
	}
}

func TestLoadAllowlistRejectsMissingFile(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistFile = t.TempDir() + "\\missing.ips"

	_, err := bb.loadAllowlist(context.Background())
	if err == nil {
		t.Fatal("erwarteter Fehler fuer fehlende Datei fehlt")
	}
	if !strings.Contains(err.Error(), "whitelist_file") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf whitelist_file", err)
	}
}

func TestLoadAllowlistRejectsBadURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.WhitelistURL = "://bad-url"

	_, err := bb.loadAllowlist(context.Background())
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungÃ¼ltige URL fehlt")
	}
	if !strings.Contains(err.Error(), "whitelist_url") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf whitelist_url", err)
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
	if len(blacklist.prefixes) != 2 {
		t.Fatalf("prefixes = %d, erwartet 2", len(blacklist.prefixes))
	}
	if blacklist.entries != 3 {
		t.Fatalf("entries = %d, erwartet 3 deduplizierte Eintraege", blacklist.entries)
	}
}

func TestLoadBlacklistRejectsMissingFile(t *testing.T) {
	bb := newTestProtector(t)
	bb.BlacklistFile = t.TempDir() + "\\missing.ips"

	_, err := bb.loadBlacklist(context.Background())
	if err == nil {
		t.Fatal("erwarteter Fehler fuer fehlende Datei fehlt")
	}
	if !strings.Contains(err.Error(), "blacklist_file") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf blacklist_file", err)
	}
}

func TestLoadBlacklistRejectsBadURL(t *testing.T) {
	bb := newTestProtector(t)
	bb.BlacklistURL = "://bad-url"

	_, err := bb.loadBlacklist(context.Background())
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltige URL fehlt")
	}
	if !strings.Contains(err.Error(), "blacklist_url") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf blacklist_url", err)
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

func TestBlacklistRefreshKeepsPreviousSnapshotOnFailure(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "badbots-*.ips")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer tmpFile.Close()
	if _, err := tmpFile.WriteString("198.51.100.7\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	bb := newTestProtector(t)
	bb.BlacklistFile = tmpFile.Name()

	blacklist, err := bb.loadBlacklist(context.Background())
	if err != nil {
		t.Fatalf("loadBlacklist() error = %v", err)
	}
	bb.blacklist.Store(blacklist)

	if err := os.WriteFile(tmpFile.Name(), []byte("kaputt\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := bb.loadBlacklist(context.Background()); err == nil {
		t.Fatal("erwarteter Refresh-Fehler fehlt")
	}

	if !bb.isBlacklisted(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("vorherige Blacklist sollte aktiv bleiben")
	}
}

func TestCreatePendingChallengeRejectsMaxPendingLimit(t *testing.T) {
	bb := newTestProtector(t)
	bb.MaxPendingChallenges = 1
	key := clientKey("192.0.2.1", "UA")

	if _, err := bb.createPendingChallenge(key, "/one"); err != nil {
		t.Fatalf("erste Challenge sollte erlaubt sein: %v", err)
	}
	if _, err := bb.createPendingChallenge(key, "/two"); err == nil {
		t.Fatal("zweite Challenge sollte wegen max_pending_challenges fehlschlagen")
	}
}

func TestNoSetCookieHeader(t *testing.T) {
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
		t.Fatalf("es wurden unerwartete Set-Cookie-Header gefunden: %v", got)
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
	if got == "" {
		t.Fatal("erwarteter Content-Security-Policy-Header fehlt")
	}
	if !strings.Contains(got, "script-src 'nonce-") {
		t.Fatalf("unerwarteter CSP-Header: %s", got)
	}
}

func TestVerifyRejectsAfterTooManyAttempts(t *testing.T) {
	bb := newTestProtector(t)
	seedHex, _ := addPendingChallenge(t, bb, clientKey("192.0.2.1", "UA"), "/protected")

	for i := 0; i < maxVerifyAttempts; i++ {
		rr := httptest.NewRecorder()
		req := verifyRequestFor(t, seedHex, "00")
		_ = bb.handleVerify(rr, req, clientKey("192.0.2.1", "UA"), 8)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("Versuch %d: Status = %d, erwartet %d", i+1, rr.Code, http.StatusForbidden)
		}
	}

	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, seedHex, "00")
	_ = bb.handleVerify(rr, req, clientKey("192.0.2.1", "UA"), 8)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusTooManyRequests)
	}
}

func TestServeHTTPVerifyPathIsInterceptedEvenWhenAllowed(t *testing.T) {
	bb := newTestProtector(t)
	key := clientKey("192.0.2.1", "UA")
	bb.markAllowed(key)

	req := verifyRequestFor(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "abcd")
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		"client_ip": "192.0.2.1",
	}))
	rr := httptest.NewRecorder()
	called := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called {
		t.Fatal("verify request darf nicht an den nächsten Handler weitergereicht werden")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusForbidden)
	}
}

func TestServeHTTPVerifyPathIsInterceptedWhenComplexityIsZero(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "0"
	req := verifyRequestFor(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "abcd")
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		"client_ip": "192.0.2.1",
	}))
	rr := httptest.NewRecorder()
	called := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called {
		t.Fatal("Verify-Endpunkt darf bei complexity 0 nicht an den nächsten Handler weitergereicht werden")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusNotFound)
	}
}

func TestBLAKE3Vector(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	nonceHex := "000102030405060708090a0b0c0d0e0f"
	expected := "c69e86514b4b59e4a7296fc05db8f4c1dd17825679f25d97d285b970aa2ea853"

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(seed) error = %v", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(nonce) error = %v", err)
	}

	input := append(append([]byte(nil), seed...), nonce...)
	sum := blake3.Sum256(input)
	if got := hex.EncodeToString(sum[:]); got != expected {
		t.Fatalf("Hash = %s, erwartet %s", got, expected)
	}
}

func TestServeHTTPAllowsVerifiedClient(t *testing.T) {
	bb := newTestProtector(t)
	key := clientKey("192.0.2.1", "UA")
	bb.markAllowed(key)

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
		t.Fatal("der nächste Handler wurde nicht aufgerufen")
	}
	if rr.Header().Get("X-Bot-Barrier") != "" {
		t.Fatal("freigegebener Client sollte keinen Challenge-Header erhalten")
	}
}

func TestServeHTTPAllowsAllowlistedIPv4Client(t *testing.T) {
	bb := newTestProtector(t)
	bb.allowlist.Store(&ipAllowlist{
		exactIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.1"): {},
		},
	})

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
		t.Fatal("der nÃ¤chste Handler wurde nicht aufgerufen")
	}
	if len(bb.pending) != 0 {
		t.Fatalf("allowlisted Traffic darf keine Pending-Challenge erzeugen: %v", bb.pending)
	}
	if len(bb.challengeAttempts) != 0 {
		t.Fatalf("allowlisted Traffic darf keinen Challenge-Zaehler erhoehen: %v", bb.challengeAttempts)
	}
	if rr.Header().Get("X-Bot-Barrier") != "" {
		t.Fatalf("allowlisted Traffic darf keinen Challenge-Header setzen: %q", rr.Header().Get("X-Bot-Barrier"))
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
		t.Fatal("der nÃ¤chste Handler wurde nicht aufgerufen")
	}
}

func TestServeHTTPAllowsAllowlistedEvenWhenComplexityIsZero(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "0"
	bb.allowlist.Store(&ipAllowlist{
		exactIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.1"): {},
		},
	})

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
		t.Fatal("allowlisted Request sollte direkt weitergereicht werden")
	}
	if rr.Header().Get("X-Bot-Barrier") != "" {
		t.Fatalf("allowlisted Request darf keinen Barrier-Header setzen: %q", rr.Header().Get("X-Bot-Barrier"))
	}
}

func TestServeHTTPBlocksBlacklistedIPv4Client(t *testing.T) {
	bb := newTestProtector(t)
	bb.blacklist.Store(&ipAllowlist{
		exactIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.1"): {},
		},
	})

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
		t.Fatal("blacklisted Traffic darf nicht weitergereicht werden")
	}
	if !rr.conn.closed {
		t.Fatal("blacklisted Traffic muss die Verbindung schliessen")
	}
	if rr.wroteHeader {
		t.Fatalf("blacklisted Traffic darf keinen HTTP-Status schreiben: %d", rr.status)
	}
	if rr.body.Len() != 0 {
		t.Fatalf("blacklisted Traffic darf keinen Body schreiben: %q", rr.body.String())
	}
	if len(bb.pending) != 0 {
		t.Fatalf("blacklisted Traffic darf keine Pending-Challenge erzeugen: %v", bb.pending)
	}
	if len(bb.challengeAttempts) != 0 {
		t.Fatalf("blacklisted Traffic darf keinen Challenge-Zaehler erhoehen: %v", bb.challengeAttempts)
	}
}

func TestServeHTTPBlocksBlacklistedEvenWhenComplexityIsZero(t *testing.T) {
	bb := newTestProtector(t)
	bb.Complexity = "0"
	bb.blacklist.Store(&ipAllowlist{
		exactIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.1"): {},
		},
	})

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
		t.Fatal("blacklisted Request darf nie weitergereicht werden")
	}
	if !rr.conn.closed {
		t.Fatal("blacklisted Request muss die Verbindung schliessen")
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
		exactIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.1"): {},
		},
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
		if len(bb.pending) != 0 {
			t.Fatalf("blacklisted Traffic darf keine Pending-Challenge erzeugen: %v", bb.pending)
		}
		if len(bb.challengeAttempts) != 0 {
			t.Fatalf("blacklisted Traffic darf keinen Challenge-Zaehler erhoehen: %v", bb.challengeAttempts)
		}
	}()

	_ = bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	}))
	t.Fatal("erwarteter Abort fuer nicht hijackbaren ResponseWriter blieb aus")
}

func TestServeHTTPServesChallenge(t *testing.T) {
	bb := newTestProtector(t)
	req := newChallengeRequest(http.MethodGet, "http://example.com/protected?x=1", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler should not be called")
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusOK)
	}
	if rr.Header().Get("X-Bot-Barrier") != "challenge" {
		t.Fatalf("X-Bot-Barrier = %q, erwartet challenge", rr.Header().Get("X-Bot-Barrier"))
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"verifyPath":"`+bb.VerifyPath+`"`) {
		t.Fatalf("im Challenge-Body fehlt verifyPath: %s", body)
	}
	if !strings.Contains(body, `"complexity":8`) {
		t.Fatalf("im Challenge-Body fehlt complexity: %s", body)
	}
}

func TestServeHTTPVerifyPathIsInterceptedEvenWhenAllowlisted(t *testing.T) {
	bb := newTestProtector(t)
	bb.allowlist.Store(&ipAllowlist{
		exactIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.1"): {},
		},
	})

	req := verifyRequestFor(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "abcd")
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		"client_ip": "192.0.2.1",
	}))
	rr := httptest.NewRecorder()
	called := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called {
		t.Fatal("Verify-Endpunkt darf auch fuer allowlisted Clients nicht weitergereicht werden")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusForbidden)
	}
}

func TestServeHTTPVerifyPathIsInterceptedEvenWhenBlacklisted(t *testing.T) {
	bb := newTestProtector(t)
	bb.blacklist.Store(&ipAllowlist{
		exactIPs: map[netip.Addr]struct{}{
			netip.MustParseAddr("192.0.2.1"): {},
		},
	})

	req := verifyRequestFor(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "abcd")
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		"client_ip": "192.0.2.1",
	}))
	rr := httptest.NewRecorder()
	called := false

	err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	}))
	if err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if called {
		t.Fatal("Verify-Endpunkt darf auch fuer blacklisted Clients nicht weitergereicht werden")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusForbidden)
	}
}

func TestChallengeAttemptCounterExpiresAfterBlockWindow(t *testing.T) {
	bb := newTestProtector(t)
	key := clientKey("192.0.2.1", "UA")

	bb.mu.Lock()
	bb.challengeAttempts[key] = challengeAttemptCounter{
		Count:     1,
		FirstSeen: time.Now().Add(-time.Duration(bb.BlockFor) - time.Second),
	}
	bb.cleanupExpiredLocked(time.Now())
	_, ok := bb.challengeAttempts[key]
	bb.mu.Unlock()

	if ok {
		t.Fatal("abgelaufener Challenge-Abrufzähler wurde nicht entfernt")
	}
}

func TestBlockedChallengeAttemptCounterExpiresAfterBlockFor(t *testing.T) {
	bb := newTestProtector(t)
	key := clientKey("192.0.2.1", "UA")

	bb.mu.Lock()
	bb.challengeAttempts[key] = challengeAttemptCounter{
		Count:        bb.MaxChallengeAttempts + 1,
		FirstSeen:    time.Now().Add(-time.Duration(bb.BlockFor) - time.Second),
		BlockedUntil: time.Now().Add(-time.Second),
	}
	bb.cleanupExpiredLocked(time.Now())
	_, ok := bb.challengeAttempts[key]
	bb.mu.Unlock()

	if ok {
		t.Fatal("abgelaufene Challenge-Sperre wurde nicht entfernt")
	}
}

func TestServeHTTPBlocksAfterTooManyChallengeAttempts(t *testing.T) {
	bb := newTestProtector(t)
	bb.MaxChallengeAttempts = 2
	bb.BlockFor = caddy.Duration(defaultBlockFor)

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Fatal("next handler should not be called")
		return nil
	})

	for i := 0; i < bb.MaxChallengeAttempts; i++ {
		req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
		rr := httptest.NewRecorder()
		if err := bb.ServeHTTP(rr, req, next); err != nil {
			t.Fatalf("ServeHTTP() error = %v", err)
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("Versuch %d: Status = %d, erwartet %d", i+1, rr.Code, http.StatusOK)
		}
	}

	req := newChallengeRequest(http.MethodGet, "http://example.com/protected", "192.0.2.1", "UA")
	rr := httptest.NewRecorder()
	if err := bb.ServeHTTP(rr, req, next); err != nil {
		t.Fatalf("ServeHTTP() error = %v", err)
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Status = %d, erwartet %d", rr.Code, http.StatusTooManyRequests)
	}
	if rr.Header().Get("X-Bot-Barrier") != "blocked" {
		t.Fatalf("X-Bot-Barrier = %q, erwartet blocked", rr.Header().Get("X-Bot-Barrier"))
	}
	if got := rr.Header().Get("Retry-After"); got != "1800" {
		t.Fatalf("Retry-After = %q, erwartet 1800", got)
	}
	if !strings.Contains(rr.Body.String(), "Too Many Requests") {
		t.Fatalf("Response-Body enthält keinen Too-Many-Requests-Hinweis: %q", rr.Body.String())
	}
}

func TestSuccessfulVerifyClearsChallengeAttemptCounter(t *testing.T) {
	bb := newTestProtector(t)
	bb.MaxChallengeAttempts = 2
	key := clientKey("192.0.2.1", "UA")

	blocked, _ := bb.registerChallengeAttempt(key)
	if blocked {
		t.Fatal("erster Challenge-Abruf darf nicht blockieren")
	}

	seedHex, pending := addPendingChallenge(t, bb, key, "/protected")
	nonceHex := findNonceHex(t, pending.Seed, 8)
	rr := httptest.NewRecorder()
	req := verifyRequestFor(t, seedHex, nonceHex)
	if err := bb.handleVerify(rr, req, key, 8); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}

	bb.mu.Lock()
	_, ok := bb.challengeAttempts[key]
	bb.mu.Unlock()
	if ok {
		t.Fatal("Challenge-Abrufzähler wurde nach erfolgreicher Verifikation nicht gelöscht")
	}
}

func TestCleanupStopsRefreshLoops(t *testing.T) {
	bb := newTestProtector(t)
	bb.allowlistStop = make(chan struct{})
	bb.allowlistDone = make(chan struct{})
	bb.blacklistStop = make(chan struct{})
	bb.blacklistDone = make(chan struct{})

	go func() {
		<-bb.allowlistStop
		close(bb.allowlistDone)
	}()
	go func() {
		<-bb.blacklistStop
		close(bb.blacklistDone)
	}()

	if err := bb.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if bb.allowlistStop != nil || bb.allowlistDone != nil || bb.blacklistStop != nil || bb.blacklistDone != nil {
		t.Fatal("Cleanup() sollte Refresh-Kanaele zuruecksetzen")
	}
}

func newTestProtector(t *testing.T) *CaddyProtector {
	t.Helper()
	bb := &CaddyProtector{
		Complexity:           "8",
		ValidFor:             caddy.Duration(defaultValidFor),
		AllowFor:             caddy.Duration(defaultAllowFor),
		VerifyPath:           defaultVerifyPath,
		MaxChallengeAttempts: defaultMaxChallengeAttempts,
		MaxPendingChallenges: defaultMaxPendingChallenges,
		BlockFor:             caddy.Duration(defaultBlockFor),
		pending:              make(map[string]pendingChallenge),
		allowed:              make(map[string]time.Time),
		challengeAttempts:    make(map[string]challengeAttemptCounter),
		logger:               zaptest.NewLogger(t),
	}
	bb.allowlist.Store(&ipAllowlist{exactIPs: make(map[netip.Addr]struct{})})
	bb.blacklist.Store(&ipAllowlist{exactIPs: make(map[netip.Addr]struct{})})
	return bb
}

func addPendingChallenge(t *testing.T, bb *CaddyProtector, key, returnPath string) (string, pendingChallenge) {
	t.Helper()
	seedHex, err := bb.createPendingChallenge(key, returnPath)
	if err != nil {
		t.Fatalf("createPendingChallenge() Fehler = %v", err)
	}

	bb.mu.Lock()
	pending := bb.pending[seedHex]
	bb.mu.Unlock()
	return seedHex, pending
}

func verifyRequestFor(t *testing.T, seedHex, nonceHex string) *http.Request {
	t.Helper()
	body, err := json.Marshal(verifyRequest{Seed: seedHex, Nonce: nonceHex})
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
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{
		"client_ip": clientIP,
	})
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

		input := append(append([]byte(nil), seed...), nonce...)
		sum := blake3.Sum256(input)
		if countLeadingZeroBits(sum[:]) >= complexity {
			return hex.EncodeToString(nonce)
		}
	}
}
