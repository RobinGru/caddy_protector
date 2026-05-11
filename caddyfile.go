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

			var arg string
			if !d.AllArgs(&arg) {
				return d.ArgErr()
			}

			switch param {
			case "complexity":
				bb.Complexity = arg
			case "valid_for":
				duration, err := parseSecondsDuration(arg)
				if err != nil {
					return d.Errf("ungueltige valid_for-Dauer: %v", err)
				}
				bb.ValidFor = caddy.Duration(duration)
			case "allow_for":
				duration, err := parseSecondsDuration(arg)
				if err != nil {
					return d.Errf("ungueltige allow_for-Dauer: %v", err)
				}
				bb.AllowFor = caddy.Duration(duration)
			case "max_challenge_attempts":
				attempts, err := strconv.Atoi(arg)
				if err != nil {
					return d.Errf("ungueltiger max_challenge_attempts-Wert: %v", err)
				}
				bb.MaxChallengeAttempts = attempts
			case "max_pending_challenges":
				maxPendingChallenges, err := strconv.Atoi(arg)
				if err != nil {
					return d.Errf("ungueltiger max_pending_challenges-Wert: %v", err)
				}
				bb.MaxPendingChallenges = maxPendingChallenges
			case "block_for":
				duration, err := parseSecondsDuration(arg)
				if err != nil {
					return d.Errf("ungueltige block_for-Dauer: %v", err)
				}
				bb.BlockFor = caddy.Duration(duration)
			case "verify_path":
				bb.VerifyPath = arg
			case "whitelist_ip":
				bb.WhitelistIPs = append(bb.WhitelistIPs, arg)
			case "whitelist_file":
				bb.WhitelistFile = arg
			case "whitelist_url":
				bb.WhitelistURL = arg
			case "whitelist_refresh":
				duration, err := parseSecondsDuration(arg)
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
				duration, err := parseSecondsDuration(arg)
				if err != nil {
					return d.Errf("ungueltige blacklist_refresh-Dauer: %v", err)
				}
				bb.BlacklistRefresh = caddy.Duration(duration)
			case "country_url":
				bb.CountryURL = arg
			case "country_url_refresh":
				duration, err := parseSecondsDuration(arg)
				if err != nil {
					return d.Errf("ungueltige country_url_refresh-Dauer: %v", err)
				}
				bb.CountryRefresh = caddy.Duration(duration)
			case "template":
				bb.TemplatePath = arg
			default:
				return d.Errf("unbekannte Option: %s", param)
			}
		}
	}
	return nil
}

func parseSecondsDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, fmt.Errorf("Dauer muss in Sekunden angegeben werden")
	}

	secondsText := strings.TrimSuffix(raw, "s")
	if secondsText == "" || strings.ContainsAny(secondsText, ".+-") {
		return 0, fmt.Errorf("Dauer muss als positive ganze Sekunden angegeben werden, z.B. 120 oder 120s")
	}

	seconds, err := strconv.Atoi(secondsText)
	if err != nil {
		return 0, fmt.Errorf("Dauer muss als positive ganze Sekunden angegeben werden, z.B. 120 oder 120s")
	}
	if seconds <= 0 {
		return 0, fmt.Errorf("Dauer muss groesser als 0 Sekunden sein")
	}

	return time.Duration(seconds) * time.Second, nil
}
