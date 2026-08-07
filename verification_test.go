package caddyprotector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/protected", nil)
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
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

func TestVerificationAbuseResilienceAC1RejectsMalformedStateAndInvalidClientBeforeCap(t *testing.T) {
	bb, capCalls := newRecordingTestProtector(t, http.StatusOK, `{"success":true}`)

	tests := []struct {
		name string
		req  *http.Request
		want int
	}{
		{
			name: "malformed JSON",
			req: func() *http.Request {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, defaultVerifyPath, strings.NewReader(`{"token":`))
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			want: http.StatusBadRequest,
		},
		{
			name: "invalid signed state",
			req: func() *http.Request {
				body, err := json.Marshal(verifyRequest{Token: "cap-token", State: "invalid"})
				if err != nil {
					t.Fatalf("json.Marshal() error = %v", err)
				}
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			want: http.StatusForbidden,
		},
		{
			name: "missing client IP",
			req: func() *http.Request {
				req := verifyRequestFor(t, bb, "cap-token")
				req.RemoteAddr = ""
				return req
			}(),
			want: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			if err := bb.handleVerify(rr, tt.req); err != nil {
				t.Fatalf("handleVerify() error = %v", err)
			}
			if rr.Code != tt.want {
				t.Fatalf("Status = %d, want %d", rr.Code, tt.want)
			}
		})
	}
	if got := capCalls.Load(); got != 0 {
		t.Fatalf("Cap calls = %d, want 0", got)
	}
}

func TestVerificationAbuseResilienceAC2AdmitsBurst(t *testing.T) {
	bb, capCalls := newRecordingTestProtector(t, http.StatusOK, `{"success":true}`)
	for i := 0; i < verifyRateLimitBurst; i++ {
		rr := httptest.NewRecorder()
		if err := bb.handleVerify(rr, verifyRequestFor(t, bb, "cap-token")); err != nil {
			t.Fatalf("attempt %d: handleVerify() error = %v", i, err)
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("attempt %d: Status = %d", i, rr.Code)
		}
	}
	if got := capCalls.Load(); got != verifyRateLimitBurst {
		t.Fatalf("Cap calls = %d, want %d", got, verifyRateLimitBurst)
	}
}

func TestVerificationAbuseResilienceAC3LimitsWithRetryAfter(t *testing.T) {
	bb, capCalls := newRecordingTestProtector(t, http.StatusOK, `{"success":true}`)
	for i := 0; i < verifyRateLimitBurst; i++ {
		rr := httptest.NewRecorder()
		if err := bb.handleVerify(rr, verifyRequestFor(t, bb, "cap-token")); err != nil {
			t.Fatalf("attempt %d: handleVerify() error = %v", i, err)
		}
	}

	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, verifyRequestFor(t, bb, "cap-token")); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
	if got := rr.Header().Get("Retry-After"); got != "3" {
		t.Fatalf("Retry-After = %q, want %q", got, "3")
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := capCalls.Load(); got != verifyRateLimitBurst {
		t.Fatalf("Cap calls = %d, want %d", got, verifyRateLimitBurst)
	}
}

func TestVerificationAbuseResilienceAC4RefillsOneTokenAfterThreeSeconds(t *testing.T) {
	bb, capCalls := newRecordingTestProtector(t, http.StatusOK, `{"success":true}`)
	now := time.Now()
	bb.testNow = func() time.Time { return now }
	for i := 0; i < verifyRateLimitBurst; i++ {
		rr := httptest.NewRecorder()
		if err := bb.handleVerify(rr, verifyRequestFor(t, bb, "cap-token")); err != nil {
			t.Fatalf("attempt %d: handleVerify() error = %v", i, err)
		}
	}
	now = now.Add(verifyRateLimitRefill)
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, verifyRequestFor(t, bb, "cap-token")); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := capCalls.Load(); got != verifyRateLimitBurst+1 {
		t.Fatalf("Cap calls = %d, want %d", got, verifyRateLimitBurst+1)
	}
}

func TestVerificationAbuseResilienceAC5ConcurrentRequestsRespectBurst(t *testing.T) {
	bb, capCalls := newRecordingTestProtector(t, http.StatusOK, `{"success":true}`)
	const attempts = verifyRateLimitBurst * 2
	requests := make([]*http.Request, attempts)
	for i := range requests {
		requests[i] = verifyRequestFor(t, bb, "cap-token")
	}

	statuses := make(chan int, attempts)
	var wg sync.WaitGroup
	for _, req := range requests {
		wg.Add(1)
		go func(req *http.Request) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			if err := bb.handleVerify(rr, req); err != nil {
				t.Errorf("handleVerify() error = %v", err)
				return
			}
			statuses <- rr.Code
		}(req)
	}
	wg.Wait()
	close(statuses)

	var admitted, limited int
	for status := range statuses {
		switch status {
		case http.StatusOK:
			admitted++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if admitted != verifyRateLimitBurst || limited != verifyRateLimitBurst {
		t.Fatalf("admitted = %d, limited = %d", admitted, limited)
	}
	if got := capCalls.Load(); got != verifyRateLimitBurst {
		t.Fatalf("Cap calls = %d, want %d", got, verifyRateLimitBurst)
	}
}

func TestVerificationAbuseResilienceAC6BoundsExpiresAndCleansUpState(t *testing.T) {
	bb := newTestProtector(t)
	now := time.Now()
	for i := 0; i < maxVerifyRateLimitEntries+1; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		allowed, _ := bb.allowVerifyAttempt(addr, now)
		if i < maxVerifyRateLimitEntries && !allowed {
			t.Fatalf("entry %d unexpectedly rejected", i)
		}
		if i == maxVerifyRateLimitEntries && allowed {
			t.Fatal("state bound did not reject a new identity")
		}
	}
	if got := len(bb.verifyRateLimits); got != maxVerifyRateLimitEntries {
		t.Fatalf("entries = %d, want %d", got, maxVerifyRateLimitEntries)
	}
	if allowed, _ := bb.allowVerifyAttempt(netip.MustParseAddr("192.0.2.1"), now.Add(verifyRateLimitEntryLifetime)); !allowed {
		t.Fatal("expired entries were not reclaimed")
	}
	if got := len(bb.verifyRateLimits); got != 1 {
		t.Fatalf("entries after expiry = %d, want 1", got)
	}
	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("ProvisionContext() error = %v", err)
	}
	if err := bb.Provision(ctx); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if got := len(bb.verifyRateLimits); got != 0 {
		t.Fatalf("entries after provision = %d, want 0", got)
	}
	if err := bb.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if got := len(bb.verifyRateLimits); got != 0 {
		t.Fatalf("entries after cleanup = %d, want 0", got)
	}
}

func TestVerificationAbuseResilienceAC7KeepsCapFailureDistinct(t *testing.T) {
	bb, capCalls := newRecordingTestProtector(t, http.StatusServiceUnavailable, `unavailable`)
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, verifyRequestFor(t, bb, "cap-token")); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	if rr.Header().Get("Retry-After") != "" {
		t.Fatalf("Retry-After = %q, want empty", rr.Header().Get("Retry-After"))
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Fatal("Cap failure must not grant a cookie")
	}
	if got := capCalls.Load(); got != 1 {
		t.Fatalf("Cap calls = %d, want 1", got)
	}
}

func TestVerificationAbuseResilienceAC8IgnoresUntrustedForwardingHeaders(t *testing.T) {
	bb, capCalls := newRecordingTestProtector(t, http.StatusOK, `{"success":true}`)
	for i := 0; i < verifyRateLimitBurst+1; i++ {
		req := verifyRequestFor(t, bb, "cap-token")
		req.RemoteAddr = "192.0.2.99:1234"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i))
		rr := httptest.NewRecorder()
		if err := bb.handleVerify(rr, req); err != nil {
			t.Fatalf("attempt %d: handleVerify() error = %v", i, err)
		}
		want := http.StatusOK
		if i == verifyRateLimitBurst {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("attempt %d: Status = %d, want %d", i, rr.Code, want)
		}
	}
	if got := capCalls.Load(); got != verifyRateLimitBurst {
		t.Fatalf("Cap calls = %d, want %d", got, verifyRateLimitBurst)
	}
}
