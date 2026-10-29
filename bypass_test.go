package caddyprotector

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestValidateBypassAPIKey(t *testing.T) {
	for _, tt := range []struct {
		name    string
		key     string
		wantErr bool
	}{
		{name: "disabled"},
		{name: "minimum length", key: strings.Repeat("a", 32)},
		{name: "longer key", key: strings.Repeat("a", 64)},
		{name: "too short", key: strings.Repeat("a", 31), wantErr: true},
		{name: "whitespace only", key: strings.Repeat(" ", 32), wantErr: true},
		{name: "leading whitespace", key: " " + strings.Repeat("a", 32), wantErr: true},
		{name: "trailing whitespace", key: strings.Repeat("a", 32) + "\n", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bb := newBaseTestProtector(t, "http://localhost")
			bb.BypassAPIKey = tt.key
			err := bb.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, want error %v", err, tt.wantErr)
			}
			if err != nil && (!strings.Contains(err.Error(), "bypass_api_key") || strings.Contains(err.Error(), tt.key)) {
				t.Fatal("validation error must identify the option without exposing the key")
			}
		})
	}
}

func TestServeHTTPAPIKeyBypass(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"
	for _, tt := range []struct {
		name       string
		method     string
		headers    []string
		disabled   bool
		wantBypass bool
	}{
		{name: "GET", method: http.MethodGet, headers: []string{key}, wantBypass: true},
		{name: "POST", method: http.MethodPost, headers: []string{key}, wantBypass: true},
		{name: "PUT", method: http.MethodPut, headers: []string{key}, wantBypass: true},
		{name: "wrong key", method: http.MethodGet, headers: []string{strings.Repeat("x", len(key))}},
		{name: "case sensitive", method: http.MethodGet, headers: []string{strings.ToUpper(key)}},
		{name: "truncated key", method: http.MethodGet, headers: []string{key[:31]}},
		{name: "empty key", method: http.MethodGet, headers: []string{""}},
		{name: "query key only", method: http.MethodGet},
		{name: "form key only", method: http.MethodPost},
		{name: "duplicate keys", method: http.MethodGet, headers: []string{key, key}},
		{name: "conflicting keys", method: http.MethodGet, headers: []string{key, "wrong"}},
		{name: "combined keys", method: http.MethodGet, headers: []string{key + ", " + key}},
		{name: "disabled with key", method: http.MethodGet, headers: []string{key}, disabled: true},
		{name: "disabled without key", method: http.MethodGet, disabled: true},
		{name: "disabled with empty key", method: http.MethodGet, headers: []string{""}, disabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bb := newBaseTestProtector(t, "http://localhost")
			if !tt.disabled {
				bb.BypassAPIKey = key
			}
			body := "apikey=" + key + "&payload=unchanged"
			req := newChallengeRequest(tt.method, "http://example.com/protected?apikey="+key, "192.0.2.1", "UA")
			req.Body = io.NopCloser(strings.NewReader(body))
			req.ContentLength = int64(len(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, value := range tt.headers {
				req.Header.Add("X-API-Key", value)
			}
			rr := httptest.NewRecorder()
			called := false
			err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				called = true
				gotBody, err := io.ReadAll(r.Body)
				if err != nil || string(gotBody) != body || r.ContentLength != int64(len(body)) {
					t.Fatalf("upstream body changed: body = %q, error = %v", gotBody, err)
				}
				if r != req || r.Header.Get("X-API-Key") != key {
					t.Fatal("upstream must receive the original request and headers")
				}
				w.WriteHeader(http.StatusNoContent)
				return nil
			}))
			if err != nil || called != tt.wantBypass {
				t.Fatalf("ServeHTTP() error = %v, bypass = %v, want %v", err, called, tt.wantBypass)
			}
			if !tt.wantBypass && rr.Header().Get("X-Bot-Barrier") != "challenge" {
				t.Fatal("invalid or missing API key must fall through to normal protection")
			}
			if len(rr.Result().Cookies()) != 0 {
				t.Fatal("API key requests must not issue allow cookies")
			}
		})
	}
}

func TestServeHTTPAPIKeyBypassesFilters(t *testing.T) {
	bb := newBaseTestProtector(t, "http://localhost")
	bb.BypassAPIKey = "0123456789abcdef0123456789abcdef"
	bb.DenyPathPrefixes = []string{"/blocked"}
	bb.DenyQuerySubstrings = []string{"blocked"}
	bb.DenyHeaderSubstrings = []HeaderSubstringRule{{Name: "User-Agent", Needle: "blocked"}}
	bb.WhitelistCountries = []string{"DE"}
	bb.BlacklistCountries = []string{"US"}
	bb.CountryURL = "http://localhost/country.mmdb"
	bb.testCountryLookup = func(netip.Addr) (string, bool) {
		t.Fatal("API key bypass must skip country lookups")
		return "US", true
	}
	bb.blacklist.Store(&ipAllowlist{exactIPs: map[netip.Addr]struct{}{netip.MustParseAddr("192.0.2.1"): {}}})
	if err := bb.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	req := newChallengeRequest(http.MethodPost, "http://example.com/blocked?blocked", "192.0.2.1", "blocked")
	req.Header.Set("X-API-Key", bb.BypassAPIKey)
	wantErr := errors.New("upstream error")
	err := bb.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		return wantErr
	}))
	if !errors.Is(err, wantErr) {
		t.Fatalf("ServeHTTP() error = %v, want upstream error", err)
	}
}

func TestServeHTTPAPIKeyPreservesVerifyEndpoint(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			bb := newBaseTestProtector(t, "http://localhost")
			bb.BypassAPIKey = "0123456789abcdef0123456789abcdef"
			req := newChallengeRequest(method, "http://example.com"+bb.VerifyPath, "192.0.2.1", "UA")
			req.Header.Set("X-API-Key", bb.BypassAPIKey)
			rr := httptest.NewRecorder()
			err := bb.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				t.Fatal("verify endpoint must not reach upstream")
				return nil
			}))
			wantStatus := http.StatusMethodNotAllowed
			if method == http.MethodPost {
				wantStatus = http.StatusUnsupportedMediaType
			}
			if err != nil || rr.Code != wantStatus {
				t.Fatalf("ServeHTTP() error = %v, status = %d, want %d", err, rr.Code, wantStatus)
			}
		})
	}
}
