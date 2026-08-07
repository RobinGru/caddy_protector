package caddyprotector

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseContractAC(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(content)
	}

	readme := read("README.md")

	releaseTemplate := read(".github/RELEASE_TEMPLATE.md")
	ciWorkflow := read(".github/workflows/ci.yml")

	t.Run("AC1 and AC5 installation guidance", func(t *testing.T) {
		if !strings.Contains(readme, "github.com/RobinGru/caddy_protector@v1.0.1") {
			t.Fatal("README must provide an exact production module version")
		}
		if !strings.Contains(readme, "@main") || !strings.Contains(readme, "instabile Entwicklungsoption") {
			t.Fatal("README must label main builds as unstable development builds")
		}
	})

	t.Run("AC2, AC3, and AC6 release template", func(t *testing.T) {
		for _, required := range []string{
			"Go: `>= 1.26.5`",
			"Caddy: `>= v2.11.4, < v3.0.0`",
			"Sicherheitsrelevante Änderungen",
			"Konfigurationsänderungen oder -erweiterungen",
			"Verhaltensänderungen",
			"Deprecations",
			"Migrationsschritte",
			"Rückzug oder Ablösung",
			"Ersatz:",
		} {
			if !strings.Contains(releaseTemplate, required) {
				t.Fatalf("release template must contain %q", required)
			}
		}
	})

	t.Run("AC4 release tag verification", func(t *testing.T) {
		if !strings.Contains(ciWorkflow, "tags: ['v*']") {
			t.Fatal("CI must run for release tags")
		}
	})
}
