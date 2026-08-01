package caddyprotector

import (
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func TestUnmarshalCaddyfileParsesCapConfiguration(t *testing.T) {
	input := `
caddy_protector {
    allow_for 1800
    cap_api_url https://cap.example.com
    cap_site_key site-key
    cap_secret_key secret-key
    cookie_name protector
    cookie_path /foo
    cookie_domain example.com
    cookie_secure false
    cookie_http_only false
    cookie_same_site Strict
    verify_path /__caddy_protector/verify
    deny_path_prefix /wp-admin
    deny_path_prefix /.git
    deny_query_substring "union select"
    deny_header_substring User-Agent sqlmap
    whitelist_ip 66.249.64.0/19
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

	if bb.CapAPIURL != "https://cap.example.com" || bb.CapSiteKey != "site-key" || bb.CapSecretKey != "secret-key" {
		t.Fatalf("Cap config = %q %q %q", bb.CapAPIURL, bb.CapSiteKey, bb.CapSecretKey)
	}
	if bb.VerifyPath != "/__caddy_protector/verify" {
		t.Fatalf("VerifyPath = %q", bb.VerifyPath)
	}
	if bb.CookieName != "protector" || bb.CookiePath != "/foo" || bb.CookieDomain != "example.com" {
		t.Fatalf("Cookie config = %q %q %q", bb.CookieName, bb.CookiePath, bb.CookieDomain)
	}
	if bb.CookieSecure == nil || *bb.CookieSecure {
		t.Fatal("CookieSecure sollte false sein")
	}
	if bb.CookieHTTPOnly == nil || *bb.CookieHTTPOnly {
		t.Fatal("CookieHTTPOnly sollte false sein")
	}
	if bb.CookieSameSite != "Strict" {
		t.Fatalf("CookieSameSite = %q", bb.CookieSameSite)
	}
	if got := strings.Join(bb.DenyPathPrefixes, ","); got != "/wp-admin,/.git" {
		t.Fatalf("DenyPathPrefixes = %q", got)
	}
	if got := strings.Join(bb.DenyQuerySubstrings, ","); got != "union select" {
		t.Fatalf("DenyQuerySubstrings = %q", got)
	}
	if len(bb.DenyHeaderSubstrings) != 1 || bb.DenyHeaderSubstrings[0].Name != "User-Agent" {
		t.Fatalf("DenyHeaderSubstrings = %#v", bb.DenyHeaderSubstrings)
	}
	if bb.WhitelistRefresh != caddy.Duration(12*time.Hour) {
		t.Fatalf("WhitelistRefresh = %v", time.Duration(bb.WhitelistRefresh))
	}
	if bb.BlacklistRefresh != caddy.Duration(time.Hour) {
		t.Fatalf("BlacklistRefresh = %v", time.Duration(bb.BlacklistRefresh))
	}
	if bb.CountryRefresh != caddy.Duration(48*time.Hour) {
		t.Fatalf("CountryRefresh = %v", time.Duration(bb.CountryRefresh))
	}
	if bb.AllowFor != caddy.Duration(defaultAllowFor) {
		t.Fatalf("AllowFor = %v", time.Duration(bb.AllowFor))
	}
	if !bb.DisableCSPHeader {
		t.Fatal("DisableCSPHeader sollte true sein")
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
	if err == nil || !strings.Contains(err.Error(), "allow_for-Dauer") {
		t.Fatalf("Fehler = %v", err)
	}
}

func TestUnmarshalCaddyfileRejectsBadDenyHeaderSubstringArgCount(t *testing.T) {
	input := `
caddy_protector {
    deny_header_substring User-Agent
}
`
	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil || !strings.Contains(err.Error(), "genau 2 Argumente") {
		t.Fatalf("Fehler = %v", err)
	}
}

func TestUnmarshalCaddyfileAcceptsExplicitMinutesSuffix(t *testing.T) {
	input := `
caddy_protector {
    allow_for 1800m
    whitelist_refresh 60m
    blacklist_refresh 120m
    country_url_refresh 180m
    cap_api_url https://cap.example.com
    cap_site_key site-key
    cap_secret_key secret-key
}
`
	var bb CaddyProtector
	if err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	if bb.AllowFor != caddy.Duration(defaultAllowFor) {
		t.Fatalf("AllowFor = %v", time.Duration(bb.AllowFor))
	}
	if bb.WhitelistRefresh != caddy.Duration(time.Hour) {
		t.Fatalf("WhitelistRefresh = %v", time.Duration(bb.WhitelistRefresh))
	}
	if bb.BlacklistRefresh != caddy.Duration(2*time.Hour) {
		t.Fatalf("BlacklistRefresh = %v", time.Duration(bb.BlacklistRefresh))
	}
	if bb.CountryRefresh != caddy.Duration(3*time.Hour) {
		t.Fatalf("CountryRefresh = %v", time.Duration(bb.CountryRefresh))
	}
}

func TestUnmarshalCaddyfileRejectsSecondDurations(t *testing.T) {
	tests := []string{"allow_for", "whitelist_refresh", "blacklist_refresh", "country_url_refresh"}
	for _, option := range tests {
		t.Run(option, func(t *testing.T) {
			input := "caddy_protector {\n\t" + option + " 30s\n\tcap_api_url https://cap.example.com\n\tcap_site_key site-key\n\tcap_secret_key secret-key\n}\n"
			var bb CaddyProtector
			err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if err == nil || !strings.Contains(err.Error(), "Minuten") {
				t.Fatalf("Fehler = %v", err)
			}
		})
	}
}

func TestUnmarshalCaddyfileRejectsUnexpectedArgumentCount(t *testing.T) {
	tests := []string{
		"caddy_protector {\n\tcap_api_url\n}\n",
		"caddy_protector {\n\tdisable_csp_header true\n}\n",
	}
	for _, input := range tests {
		var bb CaddyProtector
		if err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
			t.Fatal("erwarteter Argumentfehler fehlt")
		}
	}
}

func TestUnmarshalCaddyfileRejectsUnknownOption(t *testing.T) {
	input := "caddy_protector {\n\tunknown_option value\n}\n"
	var bb CaddyProtector
	err := bb.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
	if err == nil || !strings.Contains(err.Error(), "unbekannte Option") {
		t.Fatalf("Fehler = %v", err)
	}
}

func TestCaddyfileAdapterAcceptsImportedSnippet(t *testing.T) {
	input := `
(common_protector) {
    caddy_protector {
        allow_for 20
        cap_api_url https://cap.example.com
        cap_site_key site-key
        cap_secret_key secret-key
        verify_path /__caddy_protector/verify
        whitelist_country AT BE DE NL US
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
	adapter := caddyfile.Adapter{ServerType: httpcaddyfile.ServerType{}}
	if _, _, err := adapter.Adapt([]byte(input), map[string]any{"filename": "Caddyfile"}); err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}
}
