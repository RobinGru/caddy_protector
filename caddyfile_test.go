package caddyprotector

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileParsesAllowForAndVerifyPath(t *testing.T) {
	input := `
caddy_protector {
	complexity 18
	valid_for 120
	allow_for 1800
	max_challenge_attempts 10
	max_pending_challenges 1234
	block_for 1800
	verify_path /__caddy_protector/verify
	whitelist_ip 66.249.64.0/19
	whitelist_ip 2001:db8::/32
	whitelist_file /etc/caddy/goodbots.ips
	whitelist_url https://example.com/goodbots.ips
	whitelist_refresh 43200
	whitelist_country DE AT NL
	blacklist_ip 203.0.113.0/24
	blacklist_file /etc/caddy/badbots.ips
	blacklist_url https://example.com/badbots.ips
	blacklist_refresh 3600
	blacklist_country RU CN
	country_url https://example.com/GeoLite2-Country.mmdb
	country_url_refresh 172800
	disable_csp_header
}
`

	var bb CaddyProtector
	if err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if bb.Complexity != "18" {
		t.Fatalf("Complexity = %q, erwartet %q", bb.Complexity, "18")
	}
	if bb.VerifyPath != "/__caddy_protector/verify" {
		t.Fatalf("VerifyPath = %q, erwartet %q", bb.VerifyPath, "/__caddy_protector/verify")
	}
	if len(bb.WhitelistIPs) != 2 {
		t.Fatalf("WhitelistIPs = %v, erwartet 2 Eintraege", bb.WhitelistIPs)
	}
	if bb.WhitelistFile != "/etc/caddy/goodbots.ips" {
		t.Fatalf("WhitelistFile = %q", bb.WhitelistFile)
	}
	if bb.WhitelistURL != "https://example.com/goodbots.ips" {
		t.Fatalf("WhitelistURL = %q", bb.WhitelistURL)
	}
	if bb.WhitelistRefresh != caddy.Duration(12*time.Hour) {
		t.Fatalf("WhitelistRefresh = %v, erwartet 12h", time.Duration(bb.WhitelistRefresh))
	}
	if got := strings.Join(bb.WhitelistCountries, ","); got != "DE,AT,NL" {
		t.Fatalf("WhitelistCountries = %q", got)
	}
	if len(bb.BlacklistIPs) != 1 {
		t.Fatalf("BlacklistIPs = %v, erwartet 1 Eintrag", bb.BlacklistIPs)
	}
	if bb.BlacklistFile != "/etc/caddy/badbots.ips" {
		t.Fatalf("BlacklistFile = %q", bb.BlacklistFile)
	}
	if bb.BlacklistURL != "https://example.com/badbots.ips" {
		t.Fatalf("BlacklistURL = %q", bb.BlacklistURL)
	}
	if bb.BlacklistRefresh != caddy.Duration(time.Hour) {
		t.Fatalf("BlacklistRefresh = %v, erwartet 1h", time.Duration(bb.BlacklistRefresh))
	}
	if got := strings.Join(bb.BlacklistCountries, ","); got != "RU,CN" {
		t.Fatalf("BlacklistCountries = %q", got)
	}
	if bb.CountryURL != "https://example.com/GeoLite2-Country.mmdb" {
		t.Fatalf("CountryURL = %q", bb.CountryURL)
	}
	if bb.CountryRefresh != caddy.Duration(48*time.Hour) {
		t.Fatalf("CountryRefresh = %v, erwartet 48h", time.Duration(bb.CountryRefresh))
	}
	if bb.ValidFor != caddy.Duration(defaultValidFor) {
		t.Fatalf("ValidFor = %d, erwartet 120s", bb.ValidFor)
	}
	if bb.AllowFor != caddy.Duration(defaultAllowFor) {
		t.Fatalf("AllowFor = %d, erwartet 1800s", bb.AllowFor)
	}
	if bb.MaxChallengeAttempts != 10 {
		t.Fatalf("MaxChallengeAttempts = %d, erwartet %d", bb.MaxChallengeAttempts, 10)
	}
	if bb.MaxPendingChallenges != 1234 {
		t.Fatalf("MaxPendingChallenges = %d, erwartet %d", bb.MaxPendingChallenges, 1234)
	}
	if bb.BlockFor != caddy.Duration(defaultBlockFor) {
		t.Fatalf("BlockFor = %d, erwartet 1800s", bb.BlockFor)
	}
	if !bb.DisableCSPHeader {
		t.Fatal("DisableCSPHeader sollte true sein")
	}
}

func TestUnmarshalCaddyfileAcceptsExplicitSecondsSuffix(t *testing.T) {
	input := `
caddy_protector {
	valid_for 120s
	allow_for 1800s
	block_for 1800s
	whitelist_refresh 3600s
	blacklist_refresh 7200s
	country_url_refresh 10800s
}
`

	var bb CaddyProtector
	if err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if bb.ValidFor != caddy.Duration(defaultValidFor) {
		t.Fatalf("ValidFor = %d, erwartet 120s", bb.ValidFor)
	}
	if bb.AllowFor != caddy.Duration(defaultAllowFor) {
		t.Fatalf("AllowFor = %d, erwartet 1800s", bb.AllowFor)
	}
	if bb.BlockFor != caddy.Duration(defaultBlockFor) {
		t.Fatalf("BlockFor = %d, erwartet 1800s", bb.BlockFor)
	}
	if bb.WhitelistRefresh != caddy.Duration(time.Hour) {
		t.Fatalf("WhitelistRefresh = %v, erwartet 1h", time.Duration(bb.WhitelistRefresh))
	}
	if bb.BlacklistRefresh != caddy.Duration(2*time.Hour) {
		t.Fatalf("BlacklistRefresh = %v, erwartet 2h", time.Duration(bb.BlacklistRefresh))
	}
	if bb.CountryRefresh != caddy.Duration(3*time.Hour) {
		t.Fatalf("CountryRefresh = %v, erwartet 3h", time.Duration(bb.CountryRefresh))
	}
}

func TestUnmarshalCaddyfileRejectsMinuteDurations(t *testing.T) {
	tests := []string{"valid_for", "allow_for", "block_for", "whitelist_refresh", "blacklist_refresh", "country_url_refresh"}

	for _, option := range tests {
		t.Run(option, func(t *testing.T) {
			input := `
caddy_protector {
	` + option + ` 30m
}
`

			var bb CaddyProtector
			err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if err == nil {
				t.Fatalf("%s sollte nur Sekunden akzeptieren", option)
			}
			if !strings.Contains(err.Error(), "Sekunden") {
				t.Fatalf("Fehler = %v, erwartet Hinweis auf Sekunden", err)
			}
		})
	}
}

func TestUnmarshalCaddyfileRejectsLegacyOptions(t *testing.T) {
	tests := []string{
		"secret",
		"seed_cookie_name",
		"solution_cookie_name",
		"mac_cookie_name",
	}

	for _, option := range tests {
		t.Run(option, func(t *testing.T) {
			input := `
caddy_protector {
	` + option + ` legacy-value
}
`

			var bb CaddyProtector
			err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if err == nil {
				t.Fatalf("die Legacy-Option %s sollte fehlschlagen", option)
			}
			want := "unbekannte Option: " + option
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("Fehler = %v, erwartet %s", err, want)
			}
		})
	}
}

func TestUnmarshalCaddyfileRejectsBadAllowFor(t *testing.T) {
	input := `
caddy_protector {
	allow_for kaputt
}
`

	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltige allow_for-Dauer fehlt")
	}
	if !strings.Contains(err.Error(), "allow_for-Dauer") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf allow_for-Dauer", err)
	}
}

func TestUnmarshalCaddyfileRejectsBadMaxPendingChallenges(t *testing.T) {
	input := `
caddy_protector {
	max_pending_challenges kaputt
}
`

	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltigen max_pending_challenges-Wert fehlt")
	}
	if !strings.Contains(err.Error(), "max_pending_challenges-Wert") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf max_pending_challenges-Wert", err)
	}
}

func TestUnmarshalCaddyfileRejectsBadWhitelistRefresh(t *testing.T) {
	input := `
caddy_protector {
	whitelist_refresh kaputt
}
`

	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltige whitelist_refresh-Dauer fehlt")
	}
	if !strings.Contains(err.Error(), "whitelist_refresh-Dauer") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf whitelist_refresh-Dauer", err)
	}
}

func TestUnmarshalCaddyfileRejectsBadBlacklistRefresh(t *testing.T) {
	input := `
caddy_protector {
	blacklist_refresh kaputt
}
`

	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltige blacklist_refresh-Dauer fehlt")
	}
	if !strings.Contains(err.Error(), "blacklist_refresh-Dauer") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf blacklist_refresh-Dauer", err)
	}
}

func TestUnmarshalCaddyfileRejectsBadCountryRefresh(t *testing.T) {
	input := `
caddy_protector {
	country_url_refresh kaputt
}
`

	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil {
		t.Fatal("erwarteter Fehler fuer ungueltige country_url_refresh-Dauer fehlt")
	}
	if !strings.Contains(err.Error(), "country_url_refresh-Dauer") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf country_url_refresh-Dauer", err)
	}
}

func TestUnmarshalCaddyfileRejectsMissingCountryArguments(t *testing.T) {
	input := `
caddy_protector {
	whitelist_country
}
`

	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil {
		t.Fatal("erwarteter Argumentfehler fuer fehlende Country-Codes fehlt")
	}
}

func TestUnmarshalCaddyfileRejectsUnexpectedArgumentCount(t *testing.T) {
	tests := map[string]string{
		"missing complexity argument": `
caddy_protector {
	complexity
}
`,
		"extra complexity argument": `
caddy_protector {
	complexity 18 19
}
`,
		"extra disable_csp_header argument": `
caddy_protector {
	disable_csp_header true
}
`,
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var bb CaddyProtector
			err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if err == nil {
				t.Fatal("erwarteter Argumentfehler fehlt")
			}
		})
	}
}
