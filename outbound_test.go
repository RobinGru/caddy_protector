package caddyprotector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestVerifyCapTokenRejectsCrossOriginRedirectWithoutCredentials(t *testing.T) {
	received := make(chan string, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	bb := newBaseTestProtector(t, "https://cap.example.com")
	bb.testOutboundTransport = tlsServerTransport(t, source)
	ok, err := bb.verifyCapToken(context.Background(), "cap-token")
	if err == nil || ok || !strings.Contains(err.Error(), "cross-origin redirect") {
		t.Fatalf("verifyCapToken() = (%t, %v)", ok, err)
	}
	if strings.Contains(err.Error(), "cap-secret") || strings.Contains(err.Error(), "cap-token") {
		t.Fatalf("verifyCapToken() leaked sensitive data: %v", err)
	}
	select {
	case body := <-received:
		t.Fatalf("redirect target received request body: %q", body)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHandleVerifyRedirectFailureRedactsSensitiveData(t *testing.T) {
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example.com/siteverify", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	bb := newBaseTestProtector(t, "https://cap.example.com")
	bb.testOutboundTransport = tlsServerTransport(t, source)
	core, logs := observer.New(zap.ErrorLevel)
	bb.logger = zap.New(core)
	state := mustReturnState(t, bb, "/protected")
	body, err := json.Marshal(verifyRequest{Token: "cap-token", State: state})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, defaultVerifyPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := bb.handleVerify(rr, req); err != nil {
		t.Fatalf("handleVerify() error = %v", err)
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("Status = %d", rr.Code)
	}
	entries := logs.FilterMessage("Cap-Siteverify fehlgeschlagen").All()
	if len(entries) != 1 {
		t.Fatalf("redirect failure log entries = %d", len(entries))
	}
	diagnostic := fmt.Sprint(entries[0].ContextMap()["error"])
	for _, sensitive := range []string{"cap-secret", "cap-token", state} {
		if strings.Contains(diagnostic, sensitive) {
			t.Fatalf("redirect failure diagnostic leaked sensitive data: %q", diagnostic)
		}
	}
}

func TestVerifyCapTokenRejectsHTTPSDowngrade(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("HTTP redirect target must not receive a request")
	}))
	t.Cleanup(target.Close)

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusPermanentRedirect)
	}))
	t.Cleanup(source.Close)

	bb := newBaseTestProtector(t, "https://cap.example.com")
	bb.testOutboundTransport = tlsServerTransport(t, source)
	ok, err := bb.verifyCapToken(context.Background(), "cap-token")
	if err == nil || ok || !strings.Contains(err.Error(), "HTTPS redirect to HTTP") {
		t.Fatalf("verifyCapToken() = (%t, %v)", ok, err)
	}
}

func TestFetchURLBytesRejectsRedirectToNonPublicAddress(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1/private", http.StatusFound)
	}))
	t.Cleanup(source.Close)

	bb := newTestProtector(t)
	_, err := bb.fetchURLBytes(context.Background(), "whitelist", source.URL)
	if err == nil || !strings.Contains(err.Error(), "whitelist redirect rejected: redirect target uses a non-public address") {
		t.Fatalf("fetchURLBytes() error = %v", err)
	}
}

func TestProvisionFailsForRejectedInitialSourceRedirect(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1/private", http.StatusFound)
	}))
	t.Cleanup(source.Close)

	ctx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatalf("ProvisionContext() error = %v", err)
	}
	bb := newTestProtector(t)
	bb.WhitelistURL = source.URL
	if err := bb.Provision(ctx); err == nil || !strings.Contains(err.Error(), "whitelist redirect rejected") {
		t.Fatalf("Provision() error = %v", err)
	}
}

func TestFetchURLBytesFollowsAllowedRedirectChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/one", http.StatusFound)
		case "/one":
			http.Redirect(w, r, "/two", http.StatusFound)
		case "/two":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte("192.0.2.1\n"))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	bb := newTestProtector(t)
	body, err := bb.fetchURLBytes(context.Background(), "whitelist", server.URL+"/start")
	if err != nil {
		t.Fatalf("fetchURLBytes() error = %v", err)
	}
	if string(body) != "192.0.2.1\n" {
		t.Fatalf("fetchURLBytes() = %q", body)
	}
}

func TestFetchURLBytesRejectsRedirectChainBeyondLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bb := newTestProtector(t)
	_, err := bb.fetchURLBytes(ctx, "whitelist", server.URL+"/loop")
	if err == nil || !strings.Contains(err.Error(), "redirect limit of 3 exceeded") {
		t.Fatalf("fetchURLBytes() error = %v", err)
	}
}
