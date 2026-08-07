//go:build integration

package caddyprotector

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCaddyIntegration(t *testing.T) {
	binary := buildIntegrationCaddy(t)
	assertRegisteredModule(t, binary)

	cap := newSyntheticCapService(t)
	upstream := newRecordingUpstream(t)
	port := reserveLoopbackPort(t)
	dir := t.TempDir()
	initialConfig := filepath.Join(dir, "Caddyfile.initial")
	replacementConfig := filepath.Join(dir, "Caddyfile.replacement")
	invalidConfig := filepath.Join(dir, "Caddyfile.invalid")

	writeIntegrationConfig(t, initialConfig, integrationConfig{
		ListenPort:       port,
		CapURL:           cap.URL,
		UpstreamURL:      upstream.URL,
		AllowlistURL:     cap.URL + "/allowlist",
		AllowlistRefresh: true,
	})
	writeIntegrationConfig(t, replacementConfig, integrationConfig{
		ListenPort:  port,
		CapURL:      cap.URL,
		UpstreamURL: upstream.URL,
		AllowlistIP: "127.0.0.1",
	})
	if err := os.WriteFile(invalidConfig, []byte("{\n  auto_https off\n}\n\nhttp://127.0.0.1:"+fmt.Sprint(port)+" {\n  caddy_protector {\n    allow_for invalid\n  }\n}\n"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	caddy := startIntegrationCaddy(t, binary, initialConfig)
	protectedURL := fmt.Sprintf("http://127.0.0.1:%d/protected", port)
	client := newIntegrationClient(t)

	challenge := getIntegrationResponse(t, client, protectedURL)
	challengeBody := readIntegrationBody(t, challenge)
	if challenge.StatusCode != http.StatusOK || challenge.Header.Get("X-Bot-Barrier") != "challenge" {
		t.Fatalf("unverified request = status %d, X-Bot-Barrier %q", challenge.StatusCode, challenge.Header.Get("X-Bot-Barrier"))
	}
	if upstream.Count() != 0 {
		t.Fatalf("upstream received %d requests before verification", upstream.Count())
	}
	state := challengeState(t, challengeBody)

	verifyResponse := postVerification(t, client, fmt.Sprintf("http://127.0.0.1:%d/verify", port), state)
	defer verifyResponse.Body.Close()
	if verifyResponse.StatusCode != http.StatusOK {
		t.Fatalf("verification status = %d", verifyResponse.StatusCode)
	}
	if len(verifyResponse.Cookies()) == 0 {
		t.Fatal("verification did not set an allow cookie")
	}
	if cap.Verifications() != 1 {
		t.Fatalf("synthetic Cap verifications = %d, want 1", cap.Verifications())
	}
	if upstream.Count() != 0 {
		t.Fatalf("upstream received verification request")
	}

	allowed := getIntegrationResponse(t, client, protectedURL)
	if allowed.StatusCode != http.StatusOK || readIntegrationBody(t, allowed) != "upstream" {
		t.Fatalf("cookie-protected request did not reach upstream")
	}
	if upstream.Count() != 1 {
		t.Fatalf("upstream requests after allow cookie = %d, want 1", upstream.Count())
	}

	blocked, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/blocked", port))
	if err == nil {
		defer blocked.Body.Close()
		if blocked.StatusCode < http.StatusBadRequest {
			t.Fatalf("blocked request status = %d", blocked.StatusCode)
		}
	} else if !errors.Is(err, io.EOF) {
		t.Fatalf("blocked request: %v", err)
	}
	if upstream.Count() != 1 {
		t.Fatalf("upstream received denied request")
	}

	reloadIntegrationConfig(t, binary, replacementConfig)
	allowlisted := getIntegrationResponse(t, newIntegrationClient(t), protectedURL)
	if allowlisted.StatusCode != http.StatusOK || readIntegrationBody(t, allowlisted) != "upstream" {
		t.Fatalf("reloaded allowlist behavior is not observable")
	}
	if upstream.Count() != 2 {
		t.Fatalf("upstream requests after allowlist bypass = %d, want 2", upstream.Count())
	}
	if cap.Verifications() != 1 {
		t.Fatalf("allowlisted request unexpectedly verified by Cap")
	}

	if cap.AllowlistLoads() != 1 {
		t.Fatalf("allowlist refresh was not loaded exactly once before reload: loads = %d, want 1", cap.AllowlistLoads())
	}

	if output, err := exec.Command(binary, "reload", "--config", invalidConfig, "--adapter", "caddyfile").CombinedOutput(); err == nil {
		t.Fatal("invalid reload unexpectedly succeeded")
	} else if len(output) == 0 {
		t.Fatal("invalid reload failed without diagnostic output")
	}
	stillActive := getIntegrationResponse(t, newIntegrationClient(t), protectedURL)
	if stillActive.StatusCode != http.StatusOK || readIntegrationBody(t, stillActive) != "upstream" {
		t.Fatalf("previous route was not available after invalid reload")
	}
	if upstream.Count() != 3 {
		t.Fatalf("upstream requests after rejected reload = %d, want 3", upstream.Count())
	}

	caddy.stop(t)
}
