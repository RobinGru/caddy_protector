package caddyprotector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// CaddyModule beschreibt das Caddy-Modul und seine Instanziierung.
func (*CaddyProtector) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.caddy_protector",
		New: func() caddy.Module { return new(CaddyProtector) },
	}
}

// Provision initialisiert das Modul, den Logger und die Standardwerte.
func (bb *CaddyProtector) Provision(ctx caddy.Context) error {
	bb.logger = ctx.Logger(bb)

	if bb.AllowFor == 0 {
		bb.AllowFor = caddy.Duration(defaultAllowFor)
	}
	if bb.VerifyPath == "" {
		bb.VerifyPath = defaultVerifyPath
	}
	if bb.CookieName == "" {
		bb.CookieName = defaultCookieName
	}
	if bb.CookiePath == "" {
		bb.CookiePath = "/"
	}
	if bb.CookieSecure == nil {
		bb.CookieSecure = boolPtr(true)
	}
	if bb.CookieHTTPOnly == nil {
		bb.CookieHTTPOnly = boolPtr(true)
	}
	if bb.CookieSameSite == "" {
		bb.CookieSameSite = "Lax"
	}
	if err := bb.Validate(); err != nil {
		return err
	}
	bb.resetVerifyRateLimits()

	challengeTemplate, err := bb.loadChallengeTemplate()
	if err != nil {
		return err
	}
	bb.challengeTemplate = challengeTemplate

	allowlist, err := bb.loadAllowlist(context.Background())
	if err != nil {
		return err
	}
	bb.allowlist.Store(allowlist)
	bb.logAllowlistLoaded("initial", allowlist)

	blacklist, err := bb.loadBlacklist(context.Background())
	if err != nil {
		return err
	}
	bb.blacklist.Store(blacklist)
	bb.logIPListLoaded("initial", "blacklist", blacklist)

	if bb.hasCountryRules {
		countryDB, err := bb.loadCountryDB(context.Background())
		if err != nil {
			return err
		}
		bb.setCountryDB(countryDB)
		bb.logCountryDBLoaded("initial", countryDB)
	}

	if time.Duration(bb.WhitelistRefresh) > 0 && (bb.WhitelistFile != "" || bb.WhitelistURL != "") {
		bb.allowlistStop = make(chan struct{})
		bb.allowlistDone = make(chan struct{})
		go bb.runIPListRefreshLoop("allowlist", time.Duration(bb.WhitelistRefresh), bb.allowlistStop, bb.allowlistDone, bb.loadAllowlist, bb.allowlist.Store)
	}
	if time.Duration(bb.BlacklistRefresh) > 0 && (bb.BlacklistFile != "" || bb.BlacklistURL != "") {
		bb.blacklistStop = make(chan struct{})
		bb.blacklistDone = make(chan struct{})
		go bb.runIPListRefreshLoop("blacklist", time.Duration(bb.BlacklistRefresh), bb.blacklistStop, bb.blacklistDone, bb.loadBlacklist, bb.blacklist.Store)
	}
	if time.Duration(bb.CountryRefresh) > 0 && bb.CountryURL != "" && bb.hasCountryRules {
		bb.countryStop = make(chan struct{})
		bb.countryDone = make(chan struct{})
		go bb.runCountryRefreshLoop(time.Duration(bb.CountryRefresh), bb.countryStop, bb.countryDone)
	}

	bb.logger.Info("CaddyProtector-Modul erfolgreich initialisiert",
		zap.Duration("allow_for", time.Duration(bb.AllowFor)),
		zap.String("verify_path", bb.VerifyPath),
		zap.String("cap_api_url", bb.CapAPIURL),
		zap.String("cap_site_key", bb.CapSiteKey),
		zap.String("cookie_name", bb.CookieName),
		zap.String("cookie_path", bb.CookiePath),
		zap.String("cookie_domain", bb.CookieDomain),
		zap.Bool("cookie_secure", bb.cookieSecureValue()),
		zap.Bool("cookie_http_only", bb.cookieHTTPOnlyValue()),
		zap.String("cookie_same_site", bb.CookieSameSite),
		zap.Strings("whitelist_ips", bb.WhitelistIPs),
		zap.String("whitelist_file", bb.WhitelistFile),
		zap.String("whitelist_url", bb.WhitelistURL),
		zap.Duration("whitelist_refresh", time.Duration(bb.WhitelistRefresh)),
		zap.Strings("whitelist_countries", bb.WhitelistCountries),
		zap.Strings("blacklist_ips", bb.BlacklistIPs),
		zap.String("blacklist_file", bb.BlacklistFile),
		zap.String("blacklist_url", bb.BlacklistURL),
		zap.Duration("blacklist_refresh", time.Duration(bb.BlacklistRefresh)),
		zap.Strings("blacklist_countries", bb.BlacklistCountries),
		zap.String("country_url", bb.CountryURL),
		zap.Duration("country_url_refresh", time.Duration(bb.CountryRefresh)),
	)
	return nil
}

// Validate prüft die Konfiguration.
func (bb *CaddyProtector) Validate() error {
	whitelistCountries, err := normalizeCountryCodes("whitelist_country", bb.WhitelistCountries)
	if err != nil {
		return err
	}
	blacklistCountries, err := normalizeCountryCodes("blacklist_country", bb.BlacklistCountries)
	if err != nil {
		return err
	}
	bb.WhitelistCountries = whitelistCountries
	bb.BlacklistCountries = blacklistCountries
	bb.whitelistCountrySet = countryCodeSet(whitelistCountries)
	bb.blacklistCountrySet = countryCodeSet(blacklistCountries)
	bb.hasCountryRules = len(bb.WhitelistCountries) > 0 || len(bb.BlacklistCountries) > 0
	bb.hasCountryWhitelist = len(bb.WhitelistCountries) > 0

	if err := validateIPListConfig("whitelist", bb.WhitelistIPs, bb.WhitelistFile, bb.WhitelistURL, bb.WhitelistRefresh); err != nil {
		return err
	}
	if err := validateIPListConfig("blacklist", bb.BlacklistIPs, bb.BlacklistFile, bb.BlacklistURL, bb.BlacklistRefresh); err != nil {
		return err
	}
	if err := validateCountryConfig(bb.WhitelistCountries, bb.BlacklistCountries, bb.CountryURL, bb.CountryRefresh); err != nil {
		return err
	}
	if time.Duration(bb.AllowFor) <= 0 {
		return fmt.Errorf("allow_for muss größer als 0 sein")
	}
	if strings.TrimSpace(bb.CapSiteKey) == "" {
		return fmt.Errorf("cap_site_key darf nicht leer sein")
	}
	if strings.TrimSpace(bb.CapSecretKey) == "" {
		return fmt.Errorf("cap_secret_key darf nicht leer sein")
	}
	if err := validateRemoteURL("cap_api_url", bb.CapAPIURL); err != nil {
		return err
	}
	secretMaterial := []byte(bb.CapSecretKey)
	bb.returnStateMACKey = deriveMACKey(returnStateContext, secretMaterial)
	bb.cookieMACKey = deriveMACKey(cookieMACContext, secretMaterial)
	if bb.VerifyPath == "" || bb.VerifyPath[0] != '/' {
		return fmt.Errorf("verify_path muss mit '/' beginnen")
	}
	if bb.CookieName == "" {
		return fmt.Errorf("cookie_name darf nicht leer sein")
	}
	if bb.CookiePath == "" || bb.CookiePath[0] != '/' {
		return fmt.Errorf("cookie_path muss mit '/' beginnen")
	}
	if _, err := parseSameSiteMode(bb.CookieSameSite); err != nil {
		return err
	}
	if err := bb.compileRequestRules(); err != nil {
		return err
	}
	return nil
}
