package caddyprotector

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(&CaddyProtector{})
	httpcaddyfile.RegisterHandlerDirective("caddy_protector", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("caddy_protector", "before", "basic_auth")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m = new(CaddyProtector)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UnmarshalCaddyfile liest die Konfiguration aus dem Caddyfile.
func (bb *CaddyProtector) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			param := d.Val()
			if param == "disable_csp_header" {
				if d.CountRemainingArgs() != 0 {
					return d.ArgErr()
				}
				bb.DisableCSPHeader = true
				continue
			}

			if param == "whitelist_country" || param == "blacklist_country" {
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				if param == "whitelist_country" {
					bb.WhitelistCountries = append(bb.WhitelistCountries, args...)
				} else {
					bb.BlacklistCountries = append(bb.BlacklistCountries, args...)
				}
				continue
			}

			if param == "csp_script_src" {
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				bb.CSPScriptSrc = append(bb.CSPScriptSrc, args...)
				continue
			}

			var arg string
			if !d.AllArgs(&arg) {
				return d.ArgErr()
			}

			switch param {
			case "complexity":
				bb.Complexity = arg
			case "valid_for":
				duration, err := parseMinutesDuration(arg)
				if err != nil {
					return d.Errf("ungueltige valid_for-Dauer: %v", err)
				}
				bb.ValidFor = caddy.Duration(duration)
			case "allow_for":
				duration, err := parseMinutesDuration(arg)
				if err != nil {
					return d.Errf("ungueltige allow_for-Dauer: %v", err)
				}
				bb.AllowFor = caddy.Duration(duration)
			case "secret":
				bb.Secret = arg
			case "secret_file":
				bb.SecretFile = arg
			case "cookie_name":
				bb.CookieName = arg
			case "cookie_path":
				bb.CookiePath = arg
			case "cookie_domain":
				bb.CookieDomain = arg
			case "cookie_secure":
				value, err := strconv.ParseBool(arg)
				if err != nil {
					return d.Errf("ungueltiger cookie_secure-Wert: %v", err)
				}
				bb.CookieSecure = value
			case "cookie_http_only":
				value, err := strconv.ParseBool(arg)
				if err != nil {
					return d.Errf("ungueltiger cookie_http_only-Wert: %v", err)
				}
				bb.CookieHTTPOnly = value
			case "cookie_same_site":
				bb.CookieSameSite = arg
			case "verify_path":
				bb.VerifyPath = arg
			case "whitelist_ip":
				bb.WhitelistIPs = append(bb.WhitelistIPs, arg)
			case "whitelist_file":
				bb.WhitelistFile = arg
			case "whitelist_url":
				bb.WhitelistURL = arg
			case "whitelist_refresh":
				duration, err := parseMinutesDuration(arg)
				if err != nil {
					return d.Errf("ungueltige whitelist_refresh-Dauer: %v", err)
				}
				bb.WhitelistRefresh = caddy.Duration(duration)
			case "blacklist_ip":
				bb.BlacklistIPs = append(bb.BlacklistIPs, arg)
			case "blacklist_file":
				bb.BlacklistFile = arg
			case "blacklist_url":
				bb.BlacklistURL = arg
			case "blacklist_refresh":
				duration, err := parseMinutesDuration(arg)
				if err != nil {
					return d.Errf("ungueltige blacklist_refresh-Dauer: %v", err)
				}
				bb.BlacklistRefresh = caddy.Duration(duration)
			case "country_url":
				bb.CountryURL = arg
			case "country_url_refresh":
				duration, err := parseMinutesDuration(arg)
				if err != nil {
					return d.Errf("ungueltige country_url_refresh-Dauer: %v", err)
				}
				bb.CountryRefresh = caddy.Duration(duration)
			case "template":
				bb.TemplatePath = arg
			case "max_challenge_attempts":
				return d.Errf("max_challenge_attempts wird in der stateless Variante nicht mehr unterstuetzt")
			case "block_for":
				return d.Errf("block_for wird in der stateless Variante nicht mehr unterstuetzt")
			case "max_pending_challenges":
				return d.Errf("max_pending_challenges wird in der stateless Variante nicht mehr unterstuetzt")
			default:
				return d.Errf("unbekannte Option: %s", param)
			}
		}
	}
	return nil
}

func parseMinutesDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, fmt.Errorf("Dauer muss in Minuten angegeben werden")
	}

	minutesText := strings.TrimSuffix(raw, "m")
	if minutesText == "" || strings.ContainsAny(minutesText, ".+-") {
		return 0, fmt.Errorf("Dauer muss als positive ganze Minuten angegeben werden, z.B. 120 oder 120m")
	}

	minutes, err := strconv.Atoi(minutesText)
	if err != nil {
		return 0, fmt.Errorf("Dauer muss als positive ganze Minuten angegeben werden, z.B. 120 oder 120m")
	}
	if minutes <= 0 {
		return 0, fmt.Errorf("Dauer muss groesser als 0 Minuten sein")
	}

	return time.Duration(minutes) * time.Minute, nil
}
