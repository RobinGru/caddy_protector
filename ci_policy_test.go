package caddyprotector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCIVerificationPolicyAC(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(content)
	}

	workflow := read(".github/workflows/ci.yml")
	policy := read("docs/ci-verification.md")

	t.Run("AC1 required checks and pinned tooling", func(t *testing.T) {
		for _, required := range []string{
			"name: Lint (golangci-lint)",
			"name: Vet",
			"name: Test (ubuntu, ${{ matrix.go }})",
			"name: Integration (Caddy)",
			"name: Build",
			"name: Mod tidy check",
			"name: govulncheck",
			"govulncheck@v1.6.0",
		} {
			if !strings.Contains(workflow, required) {
				t.Fatalf("workflow must contain %q", required)
			}
		}
		if strings.Contains(workflow, "govulncheck@latest") {
			t.Fatal("govulncheck must use a pinned version")
		}
	})

	t.Run("AC2 coverage artifact cannot mask test failures", func(t *testing.T) {
		if !strings.Contains(workflow, "hashFiles('coverage.out') != ''") {
			t.Fatal("coverage upload must require an existing profile")
		}
	})

	t.Run("AC3 race suite runs once", func(t *testing.T) {
		if count := strings.Count(workflow, "go test -race"); count != 1 {
			t.Fatalf("expected one race-enabled test run, got %d", count)
		}
	})

	t.Run("AC4 and AC5 coverage threshold", func(t *testing.T) {
		if !strings.Contains(workflow, "minimum: 70%") || !strings.Contains(workflow, "coverage >= 70") {
			t.Fatal("workflow must enforce the approved 70% coverage minimum")
		}
	})

	t.Run("AC6 fork-safe permissions and integration cadence", func(t *testing.T) {
		if !strings.Contains(workflow, "contents: read") || strings.Contains(workflow, "pull_request_target") {
			t.Fatal("workflow must remain read-only and avoid pull_request_target")
		}
		if !strings.Contains(workflow, "pull_request:") || !strings.Contains(workflow, "name: Integration (Caddy)") {
			t.Fatal("integration must run for pull requests")
		}
	})

	t.Run("documented policy", func(t *testing.T) {
		for _, required := range []string{"70%", "v1.6.0", "Required Checks", "einmal wiederholt"} {
			if !strings.Contains(policy, required) {
				t.Fatalf("policy must document %q", required)
			}
		}
	})
}

func TestGovulncheckInfrastructurePolicyAC7(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		scenario  string
		wantError bool
		wantCalls int
	}{
		{name: "success", scenario: "success", wantCalls: 1},
		{name: "vulnerability", scenario: "vulnerability", wantError: true, wantCalls: 1},
		{name: "infrastructure outage", scenario: "outage", wantCalls: 2},
		{name: "unclassified failure", scenario: "unexpected", wantError: true, wantCalls: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			tempDir := t.TempDir()
			callsPath := filepath.Join(tempDir, "calls")
			fakeGovulncheck := filepath.Join(tempDir, "govulncheck")
			fakeScript := "#!/bin/sh\n" +
				"printf x >> \"$GOVULNCHECK_CALLS\"\n" +
				"case \"$GOVULNCHECK_SCENARIO\" in\n" +
				"success) exit 0 ;;\n" +
				"vulnerability) echo 'known vulnerability'; exit 1 ;;\n" +
				"outage) echo 'dial tcp: no such host'; exit 1 ;;\n" +
				"*) echo 'unexpected local failure'; exit 1 ;;\n" +
				"esac\n"
			if err := os.WriteFile(fakeGovulncheck, []byte(fakeScript), 0o755); err != nil {
				t.Fatal(err)
			}

			command := exec.CommandContext(t.Context(), "sh", "scripts/run-govulncheck.sh")
			command.Env = append(os.Environ(),
				"PATH="+tempDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GOVULNCHECK_CALLS="+callsPath,
				"GOVULNCHECK_SCENARIO="+testCase.scenario,
			)
			output, err := command.CombinedOutput()
			if (err != nil) != testCase.wantError {
				t.Fatalf("run error = %v, want error %t; output: %s", err, testCase.wantError, output)
			}
			calls, err := os.ReadFile(callsPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(calls); got != strings.Repeat("x", testCase.wantCalls) {
				t.Fatalf("govulncheck calls = %q, want %q", got, strings.Repeat("x", testCase.wantCalls))
			}
		})
	}
}
