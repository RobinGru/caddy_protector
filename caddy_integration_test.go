//go:build integration

package caddyprotector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const integrationCaddyVersion = "v2.11.4"

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

	time.Sleep(65 * time.Second)
	if cap.AllowlistLoads() != 1 {
		t.Fatalf("old allowlist refresh worker remained active: loads = %d, want 1", cap.AllowlistLoads())
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

type integrationConfig struct {
	ListenPort       int
	CapURL           string
	UpstreamURL      string
	AllowlistURL     string
	AllowlistRefresh bool
	AllowlistIP      string
}

func writeIntegrationConfig(t *testing.T, path string, config integrationConfig) {
	t.Helper()
	var options strings.Builder
	fmt.Fprintf(&options, "    cap_api_url %s\n    cap_site_key synthetic-site\n    cap_secret_key synthetic-secret\n    cookie_secure false\n    verify_path /verify\n    deny_path_prefix /blocked\n", config.CapURL)
	if config.AllowlistURL != "" {
		fmt.Fprintf(&options, "    whitelist_url %s\n", config.AllowlistURL)
	}
	if config.AllowlistRefresh {
		options.WriteString("    whitelist_refresh 1\n")
	}
	if config.AllowlistIP != "" {
		fmt.Fprintf(&options, "    whitelist_ip %s\n", config.AllowlistIP)
	}
	content := fmt.Sprintf("{\n  auto_https off\n}\n\nhttp://127.0.0.1:%d {\n  caddy_protector {\n%s  }\n  reverse_proxy %s\n}\n", config.ListenPort, options.String(), config.UpstreamURL)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write Caddyfile %s: %v", path, err)
	}
}

func buildIntegrationCaddy(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("CADDY_INTEGRATION_BINARY"); binary != "" {
		return binary
	}
	xcaddy, err := exec.LookPath("xcaddy")
	if err != nil {
		t.Fatalf("integration environment requires xcaddy or CADDY_INTEGRATION_BINARY: %v", err)
	}
	output := filepath.Join(t.TempDir(), "caddy")
	if runtime.GOOS == "windows" {
		output += ".exe"
	}
	command := exec.Command(xcaddy, "build", integrationCaddyVersion, "--output", output, "--with", "github.com/RobinGru/caddy_protector=.")
	command.Dir = repositoryRoot(t)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Caddy %s with local module: %v\n%s", integrationCaddyVersion, err, result)
	}
	return output
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("get repository root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("test must run from repository root: %v", err)
	}
	return root
}

func assertRegisteredModule(t *testing.T, binary string) {
	t.Helper()
	output, err := exec.Command(binary, "list-modules").CombinedOutput()
	if err != nil {
		t.Fatalf("list Caddy modules: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "http.handlers.caddy_protector") {
		t.Fatal("custom Caddy binary does not register http.handlers.caddy_protector")
	}
}

type integrationCaddy struct {
	cmd    *exec.Cmd
	done   chan error
	output *lockedBuffer
	once   sync.Once
}

func startIntegrationCaddy(t *testing.T, binary, config string) *integrationCaddy {
	t.Helper()
	output := new(lockedBuffer)
	cmd := exec.Command(binary, "run", "--config", config, "--adapter", "caddyfile")
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Caddy: %v", err)
	}
	caddy := &integrationCaddy{cmd: cmd, done: make(chan error, 1), output: output}
	go func() { caddy.done <- cmd.Wait() }()
	t.Cleanup(func() { caddy.stop(t) })
	return caddy
}

func (c *integrationCaddy) stop(t *testing.T) {
	t.Helper()
	c.once.Do(func() {
		if c.cmd.ProcessState == nil {
			_ = c.cmd.Process.Signal(os.Interrupt)
		}
		select {
		case err := <-c.done:
			if err != nil {
				t.Logf("Caddy exit error: %v\n%s", err, c.output.String())
			}
		case <-time.After(5 * time.Second):
			_ = c.cmd.Process.Kill()
			<-c.done
		}
	})
}

func reloadIntegrationConfig(t *testing.T, binary, config string) {
	t.Helper()
	output, err := exec.Command(binary, "reload", "--config", config, "--adapter", "caddyfile").CombinedOutput()
	if err != nil {
		t.Fatalf("reload Caddy: %v\n%s", err, output)
	}
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func newIntegrationClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

func getIntegrationResponse(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(rawURL)
		if err == nil {
			return response
		}
		if time.Now().After(deadline) {
			t.Fatalf("request %s: %v", rawURL, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func readIntegrationBody(t *testing.T, response *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(body)
}

var challengeConfigPattern = regexp.MustCompile(`window\.__BOT_BARRIER__ = (\{.*\});`)

func challengeState(t *testing.T, body string) string {
	t.Helper()
	matches := challengeConfigPattern.FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatal("challenge response did not contain verification state")
	}
	var config struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		t.Fatalf("decode challenge configuration: %v", err)
	}
	if config.State == "" {
		t.Fatal("challenge response contained an empty verification state")
	}
	return config.State
}

func postVerification(t *testing.T, client *http.Client, rawURL, state string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"token": "synthetic-token", "state": state})
	if err != nil {
		t.Fatalf("encode verification payload: %v", err)
	}
	request, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create verification request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send verification request: %v", err)
	}
	return response
}

type syntheticCapService struct {
	*httptest.Server
	mu             sync.Mutex
	verifications  int
	allowlistLoads int
}

func newSyntheticCapService(t *testing.T) *syntheticCapService {
	t.Helper()
	service := &syntheticCapService{}
	service.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		service.mu.Lock()
		defer service.mu.Unlock()
		switch request.URL.Path {
		case "/synthetic-site/siteverify":
			service.verifications++
			var payload map[string]string
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload["secret"] != "synthetic-secret" || payload["response"] != "synthetic-token" {
				http.Error(w, "invalid synthetic verification", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/allowlist":
			service.allowlistLoads++
			_, _ = w.Write([]byte("192.0.2.1\n"))
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(service.Close)
	return service
}

func (s *syntheticCapService) Verifications() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifications
}

func (s *syntheticCapService) AllowlistLoads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowlistLoads
}

type recordingUpstream struct {
	*httptest.Server
	mu    sync.Mutex
	count int
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	t.Helper()
	upstream := &recordingUpstream{}
	upstream.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstream.mu.Lock()
		upstream.count++
		upstream.mu.Unlock()
		_, _ = io.WriteString(w, "upstream")
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

func (u *recordingUpstream) Count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.count
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
