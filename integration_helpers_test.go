//go:build integration

package caddyprotector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
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
