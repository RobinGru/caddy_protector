package caddyprotector

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

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
