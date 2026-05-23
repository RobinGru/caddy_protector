package caddyprotector

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	caddyfileAdapter "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestUnmarshalCaddyfileParsesAllowForAndVerifyPath(t *testing.T) {
	input := `
caddy_protector {
	complexity 18
	valid_for 120
	allow_for 1800
	secret test-secret
	cookie_name protector
	cookie_path /foo
	cookie_domain example.com
	cookie_secure false
	cookie_http_only false
	cookie_same_site Strict
	verify_path /__caddy_protector/verify
	whitelist_ip 66.249.64.0/19
	whitelist_ip 2001:db8::/32
	whitelist_file /etc/caddy/goodbots.ips
	whitelist_url https://example.com/goodbots.ips
	whitelist_refresh 720
	whitelist_country DE AT NL
	blacklist_ip 203.0.113.0/24
	blacklist_file /etc/caddy/badbots.ips
	blacklist_url https://example.com/badbots.ips
	blacklist_refresh 60
	blacklist_country RU CN
	country_url https://example.com/GeoLite2-Country.mmdb
	country_url_refresh 2880
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
	if bb.Secret != "test-secret" {
		t.Fatalf("Secret = %q", bb.Secret)
	}
	if bb.CookieName != "protector" {
		t.Fatalf("CookieName = %q", bb.CookieName)
	}
	if bb.CookiePath != "/foo" {
		t.Fatalf("CookiePath = %q", bb.CookiePath)
	}
	if bb.CookieDomain != "example.com" {
		t.Fatalf("CookieDomain = %q", bb.CookieDomain)
	}
	if bb.CookieSecure {
		t.Fatal("CookieSecure sollte false sein")
	}
	if bb.CookieHTTPOnly {
		t.Fatal("CookieHTTPOnly sollte false sein")
	}
	if bb.CookieSameSite != "Strict" {
		t.Fatalf("CookieSameSite = %q", bb.CookieSameSite)
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
		t.Fatalf("ValidFor = %d, erwartet 120m", bb.ValidFor)
	}
	if bb.AllowFor != caddy.Duration(defaultAllowFor) {
		t.Fatalf("AllowFor = %d, erwartet 1800m", bb.AllowFor)
	}
	if !bb.DisableCSPHeader {
		t.Fatal("DisableCSPHeader sollte true sein")
	}
}

func TestUnmarshalCaddyfileAcceptsExplicitMinutesSuffix(t *testing.T) {
	input := `
caddy_protector {
	valid_for 120m
	allow_for 1800m
	whitelist_refresh 60m
	blacklist_refresh 120m
	country_url_refresh 180m
}
`

	var bb CaddyProtector
	if err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if bb.ValidFor != caddy.Duration(defaultValidFor) {
		t.Fatalf("ValidFor = %d, erwartet 120m", bb.ValidFor)
	}
	if bb.AllowFor != caddy.Duration(defaultAllowFor) {
		t.Fatalf("AllowFor = %d, erwartet 1800m", bb.AllowFor)
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

func TestUnmarshalCaddyfileRejectsSecondDurations(t *testing.T) {
	tests := []string{"valid_for", "allow_for", "whitelist_refresh", "blacklist_refresh", "country_url_refresh"}

	for _, option := range tests {
		t.Run(option, func(t *testing.T) {
			input := `
caddy_protector {
	` + option + ` 30s
}
`

			var bb CaddyProtector
			err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if err == nil {
				t.Fatalf("%s sollte nur Minuten akzeptieren", option)
			}
			if !strings.Contains(err.Error(), "Minuten") {
				t.Fatalf("Fehler = %v, erwartet Hinweis auf Minuten", err)
			}
		})
	}
}

func TestUnmarshalCaddyfileRejectsLegacyOptions(t *testing.T) {
	tests := []string{
		"seed_cookie_name",
		"solution_cookie_name",
		"mac_cookie_name",
		"max_pending_challenges",
		"max_challenge_attempts",
		"block_for",
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
			if option == "max_pending_challenges" || option == "max_challenge_attempts" || option == "block_for" {
				want = "nicht mehr unterstuetzt"
			}
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

func TestUnmarshalCaddyfileRejectsRemovedMaxPendingChallenges(t *testing.T) {
	input := `
caddy_protector {
	max_pending_challenges 1
}
`

	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil {
		t.Fatal("erwarteter Fehler fuer entfernte max_pending_challenges-Option fehlt")
	}
	if !strings.Contains(err.Error(), "nicht mehr unterstuetzt") {
		t.Fatalf("Fehler = %v, erwartet Hinweis auf entfernte Option", err)
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

func TestCaddyfileAdapterAcceptsMultipleCountryCodesInImportedSnippet(t *testing.T) {
	input := `
(common_protector) {
	caddy_protector {
		complexity 15
		valid_for 15
		allow_for 20
		secret imported-secret
		verify_path /__caddy_protector/verify
		whitelist_country AT BE BG CY CZ DE DK EE ES FI FR GR HR IE IT LT LU LV MT NL GB US
		whitelist_url https://raw.githubusercontent.com/AnTheMaker/GoodBots/main/all.ips
		whitelist_refresh 1440
		blacklist_url https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/ip_blacklist.txt
		blacklist_refresh 1440
		country_url https://git.io/GeoLite2-Country.mmdb
		country_url_refresh 2880
	}
}

example.com {
	import common_protector
	respond "ok"
}
`

	adapter := caddyfileAdapter.Adapter{ServerType: httpcaddyfile.ServerType{}}
	_, _, err := adapter.Adapt([]byte(input), map[string]any{"filename": "Caddyfile"})
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}
}
