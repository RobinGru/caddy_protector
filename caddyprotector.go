package caddyprotector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/zeebo/blake3"
	"go.uber.org/zap"

	_ "embed"
)

//go:embed challenge_template.html
var defaultHTML string

const (
	defaultVerifyPath   = "/__caddy_protector/verify"
	defaultAllowFor     = 1800 * time.Minute
	defaultCookieName   = "caddy_protector"
	maxVerifyBodyBytes  = 4096
	maxIPListBytes      = 100 << 20
	maxCountryDBBytes   = 100 << 20
	tokenVersion        = 1
	returnStateValidFor = 15 * time.Minute
	returnStateContext  = "caddy_protector:return_state:v1"
	cookieMACContext    = "caddy_protector:cookie_mac:v1"
)

type verifyRequest struct {
	Token string `json:"token"`
	State string `json:"state,omitempty"`
}

type verifyDecodeInfo struct {
	BodyLength          int
	BodyPreview         string
	OriginalDecodeError string
}

type ipAllowlist struct {
	exactIPs map[netip.Addr]struct{}
	prefixes []netip.Prefix
	sources  []string
	entries  int
}

type allowlistParseResult struct {
	exactIPs map[netip.Addr]struct{}
	prefixes map[string]netip.Prefix
	sources  []string
	entries  int
}

type allowlistEntry struct {
	addr   netip.Addr
	prefix netip.Prefix
}

type countryDB struct {
	reader *maxminddb.Reader
	source string
	size   int
}

type geoIPCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type returnStateClaims struct {
	Version    int    `json:"v"`
	ReturnPath string `json:"return_to"`
	ExpiresAt  int64  `json:"exp"`
}

type allowCookieClaims struct {
	Version   int   `json:"v"`
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

type HeaderSubstringRule struct {
	Name   string `json:"name"`
	Needle string `json:"needle"`
}

type compiledStringRule struct {
	Value  string
	Source string
}

type compiledHeaderRule struct {
	Name   string
	Needle string
	Source string
}

type requestRuleMatch struct {
	Source     string
	Type       string
	HeaderName string
}

// CaddyProtector ist ein Caddy-Middleware-Modul, das Requests mit einer vorgeschalteten
// Cap-Verifikation absichert und nach erfolgreicher Verifikation ein signiertes Freigabe-Cookie setzt.
type CaddyProtector struct {
	// TemplatePath ist der Pfad zu einem benutzerdefinierten HTML-Template.
	TemplatePath string `json:"template,omitempty"`

	// DisableCSPHeader deaktiviert den von CaddyProtector gesetzten CSP-Header.
	DisableCSPHeader bool `json:"disable_csp_header,omitempty"`

	// AllowFor bestimmt, wie lange ein erfolgreicher Client freigegeben bleibt.
	AllowFor caddy.Duration `json:"allow_for,omitempty"`

	// VerifyPath ist der interne POST-Endpunkt für die Verifikation.
	VerifyPath string `json:"verify_path,omitempty"`

	// CapAPIURL ist die öffentliche Basis-URL der Cap-Instanz.
	CapAPIURL string `json:"cap_api_url,omitempty"`

	// CapSiteKey ist der Site-Key der Cap-Instanz.
	CapSiteKey string `json:"cap_site_key,omitempty"`

	// CapSecretKey ist der Secret-Key für serverseitige /siteverify-Requests.
	CapSecretKey string `json:"cap_secret_key,omitempty"`

	// CookieName ist der Name des Freigabe-Cookies.
	CookieName string `json:"cookie_name,omitempty"`

	// CookiePath ist der Pfad des Freigabe-Cookies.
	CookiePath string `json:"cookie_path,omitempty"`

	// CookieDomain ist optional die Domain des Freigabe-Cookies.
	CookieDomain string `json:"cookie_domain,omitempty"`

	// CookieSecure steuert das Secure-Flag des Freigabe-Cookies.
	CookieSecure *bool `json:"cookie_secure,omitempty"`

	// CookieHTTPOnly steuert das HttpOnly-Flag des Freigabe-Cookies.
	CookieHTTPOnly *bool `json:"cookie_http_only,omitempty"`

	// CookieSameSite steuert das SameSite-Attribut des Freigabe-Cookies.
	CookieSameSite string `json:"cookie_same_site,omitempty"`

	// DenyPathPrefixes sperrt Requests mit passenden Pfad-Präfixen.
	DenyPathPrefixes []string `json:"deny_path_prefix,omitempty"`

	// DenyQuerySubstrings sperrt Requests mit passenden Query-Teilstrings.
	DenyQuerySubstrings []string `json:"deny_query_substring,omitempty"`

	// DenyHeaderSubstrings sperrt Requests mit passenden Header-Teilstrings.
	DenyHeaderSubstrings []HeaderSubstringRule `json:"deny_header_substring,omitempty"`

	// WhitelistIPs sind IPs oder CIDR-Praefixe, die ohne Challenge weitergelassen werden.
	WhitelistIPs []string `json:"whitelist_ip,omitempty"`

	// WhitelistFile verweist auf eine Datei mit IP- oder CIDR-Eintraegen.
	WhitelistFile string `json:"whitelist_file,omitempty"`

	// WhitelistURL verweist auf eine URL mit IP- oder CIDR-Eintraegen.
	WhitelistURL string `json:"whitelist_url,omitempty"`

	// WhitelistRefresh bestimmt das Refresh-Intervall fuer Datei- und URL-Quellen.
	WhitelistRefresh caddy.Duration `json:"whitelist_refresh,omitempty"`

	// WhitelistCountries begrenzt Requests auf bestimmte ISO-3166-1-Alpha-2-Laender.
	WhitelistCountries []string `json:"whitelist_country,omitempty"`

	// BlacklistIPs sind IPs oder CIDR-Praefixe, die sofort gesperrt werden.
	BlacklistIPs []string `json:"blacklist_ip,omitempty"`

	// BlacklistFile verweist auf eine Datei mit IP- oder CIDR-Eintraegen.
	BlacklistFile string `json:"blacklist_file,omitempty"`

	// BlacklistURL verweist auf eine URL mit IP- oder CIDR-Eintraegen.
	BlacklistURL string `json:"blacklist_url,omitempty"`

	// BlacklistRefresh bestimmt das Refresh-Intervall fuer Datei- und URL-Quellen.
	BlacklistRefresh caddy.Duration `json:"blacklist_refresh,omitempty"`

	// BlacklistCountries sperrt Requests aus bestimmten ISO-3166-1-Alpha-2-Laendern.
	BlacklistCountries []string `json:"blacklist_country,omitempty"`

	// CountryURL verweist auf eine MaxMind-MMDB fuer Country-Lookups.
	CountryURL string `json:"country_url,omitempty"`

	// CountryRefresh bestimmt das Refresh-Intervall fuer die Country-MMDB.
	CountryRefresh caddy.Duration `json:"country_url_refresh,omitempty"`

	challengeTemplate   *template.Template
	logger              *zap.Logger
	allowlist           atomic.Value
	blacklist           atomic.Value
	countryDBMu         sync.RWMutex
	countryDB           *countryDB
	allowlistStop       chan struct{}
	allowlistDone       chan struct{}
	blacklistStop       chan struct{}
	blacklistDone       chan struct{}
	countryStop         chan struct{}
	countryDone         chan struct{}
	whitelistCountrySet map[string]struct{}
	blacklistCountrySet map[string]struct{}
	hasCountryRules     bool
	hasCountryWhitelist bool
	testCountryLookup   func(netip.Addr) (string, bool)
	testCountryLoader   func(context.Context, string) (*countryDB, error)
	returnStateMACKey   []byte
	cookieMACKey        []byte
	compiledPathRules   []compiledStringRule
	compiledQueryRules  []compiledStringRule
	compiledHeaderRules []compiledHeaderRule
}

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

// ServeHTTP prüft den Challenge-Status oder liefert eine Challenge-Seite aus.
func (bb *CaddyProtector) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := getClientIP(r.Context(), r.RemoteAddr)

	logger := bb.logger.With(
		zap.String("client_ip", clientIP),
		zap.String("method", r.Method),
		zap.String("requested_url", redactURLForLog(r.URL)),
	)

	if r.URL.Path == bb.VerifyPath {
		if r.Method != http.MethodPost {
			logger.Warn("Verify-Endpunkt wurde mit nicht erlaubter Methode aufgerufen", zap.String("allowed_method", http.MethodPost))
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return nil
		}
		return bb.handleVerify(w, r)
	}
	if match, ok := bb.matchRequestRules(r); ok {
		fields := []zap.Field{
			zap.String("rule_source", match.Source),
			zap.String("rule_type", match.Type),
		}
		if match.HeaderName != "" {
			fields = append(fields, zap.String("header_name", match.HeaderName))
		}
		logger.Warn("Request durch einfache Request-Regel verworfen", fields...)
		writeBlacklistedResponse(w)
		return nil
	}

	clientAddr, clientAddrErr := netip.ParseAddr(clientIP)
	countryCode, countryFound := "", false
	if bb.hasCountryRules {
		countryCode, countryFound = bb.lookupCountryCode(clientAddr, clientAddrErr)
		if countryFound {
			logger = logger.With(zap.String("client_country", countryCode))
		}
		if countryFound && bb.isCountryBlacklisted(countryCode) {
			logger.Warn("Client-Land steht auf der Country-Blacklist", zap.String("client_country", countryCode))
			writeBlacklistedResponse(w)
			return nil
		}
		if bb.hasCountryWhitelist && (!countryFound || !bb.isCountryWhitelisted(countryCode)) {
			logger.Warn("Client-Land ist nicht auf der Country-Whitelist", zap.String("client_country", countryCode))
			writeBlacklistedResponse(w)
			return nil
		}
	}
	if clientAddrErr == nil && bb.isBlacklisted(clientAddr) {
		logger.Warn("Client-IP steht auf der Blacklist")
		writeBlacklistedResponse(w)
		return nil
	}

	if clientAddrErr == nil && bb.isAllowlisted(clientAddr) {
		logger.Debug("Client-IP steht auf der Allowlist")
		return next.ServeHTTP(w, r)
	}

	if bb.hasValidAllowCookie(r) {
		logger.Debug("Client hat ein gültiges Freigabe-Cookie")
		return next.ServeHTTP(w, r)
	}

	logger.Info("Challenge-Seite wird ausgeliefert")
	return bb.serveChallenge(w, r)
}

func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func safeReturnPathFrom(returnPath string) string {
	if returnPath == "" || returnPath[0] != '/' || strings.HasPrefix(returnPath, "//") {
		return "/"
	}
	// Pfad-Traversal verhindern mit path.Clean
	parts := strings.SplitN(returnPath, "?", 2)
	rawPath := parts[0]
	hasTrailingSlash := len(rawPath) > 1 && rawPath[len(rawPath)-1] == '/'
	cleanPath := path.Clean(rawPath)
	if cleanPath == "." || !strings.HasPrefix(cleanPath, "/") {
		return "/"
	}
	// path.Clean entfernt den trailing Slash; wir stellen ihn wieder her, falls vorhanden
	if hasTrailingSlash && cleanPath[len(cleanPath)-1] != '/' {
		cleanPath += "/"
	}
	if len(parts) > 1 {
		return cleanPath + "?" + parts[1]
	}
	return cleanPath
}

func safeReturnPath(r *http.Request) string {
	return safeReturnPathFrom(r.URL.RequestURI())
}

// getOriginalPath ermittelt den ursprünglichen Pfad aus dem Caddy-Replacer,
// falls verfügbar. Dies ist notwendig, wenn Caddy's handle_path den
// r.URL.Path modifiziert hat (z. B. /2026-domaintester/ -> /).
// Fallback ist der aktuelle r.URL.RequestURI().
func (bb *CaddyProtector) getOriginalPath(r *http.Request) string {
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok && repl != nil {
		val, found := repl.Get("http.request.orig_uri")
		if found {
			origURI, ok := val.(string)
			if ok && origURI != "" && origURI[0] == '/' {
				return safeReturnPathFrom(origURI)
			}
		}
	}
	return safeReturnPath(r)
}

func redactURLForLog(u *url.URL) string {
	if u == nil {
		return ""
	}
	redacted := *u
	redacted.RawQuery = ""
	redacted.ForceQuery = false
	return redacted.String()
}

func redactHeaderURLForLog(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return shortValue(raw, 128)
	}
	return redactURLForLog(u)
}

func redactPathForLog(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return shortValue(raw, 128)
	}
	return redactURLForLog(u)
}

func normalizeRuleValue(kind, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("%s darf nicht leer sein", kind)
	}
	return strings.ToLower(value), nil
}

func (bb *CaddyProtector) compileRequestRules() error {
	pathRules := make([]compiledStringRule, 0, len(bb.DenyPathPrefixes))
	queryRules := make([]compiledStringRule, 0, len(bb.DenyQuerySubstrings))
	headerRules := make([]compiledHeaderRule, 0, len(bb.DenyHeaderSubstrings))

	for _, raw := range bb.DenyPathPrefixes {
		value, err := normalizeRuleValue("deny_path_prefix", raw)
		if err != nil {
			return err
		}
		pathRules = append(pathRules, compiledStringRule{Value: value, Source: "config"})
	}
	for _, raw := range bb.DenyQuerySubstrings {
		value, err := normalizeRuleValue("deny_query_substring", raw)
		if err != nil {
			return err
		}
		queryRules = append(queryRules, compiledStringRule{Value: value, Source: "config"})
	}
	for i, rule := range bb.DenyHeaderSubstrings {
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(rule.Name))
		if name == "" {
			return fmt.Errorf("deny_header_substring header-name darf nicht leer sein")
		}
		needle, err := normalizeRuleValue("deny_header_substring", rule.Needle)
		if err != nil {
			return err
		}
		bb.DenyHeaderSubstrings[i] = HeaderSubstringRule{Name: name, Needle: strings.TrimSpace(rule.Needle)}
		headerRules = append(headerRules, compiledHeaderRule{Name: name, Needle: needle, Source: "config"})
	}

	bb.compiledPathRules = pathRules
	bb.compiledQueryRules = queryRules
	bb.compiledHeaderRules = headerRules
	return nil
}

func (bb *CaddyProtector) matchRequestRules(r *http.Request) (requestRuleMatch, bool) {
	pathValue := r.URL.EscapedPath()
	if pathValue == "" {
		pathValue = r.URL.Path
	}
	pathValues := []string{strings.ToLower(pathValue)}
	if unescaped, err := url.PathUnescape(pathValue); err == nil && unescaped != pathValue {
		pathValues = append(pathValues, strings.ToLower(unescaped))
	}
	for _, rule := range bb.compiledPathRules {
		for _, value := range pathValues {
			if strings.HasPrefix(value, rule.Value) {
				return requestRuleMatch{Source: rule.Source, Type: "path_prefix"}, true
			}
		}
	}

	rawQuery := strings.ToLower(r.URL.RawQuery)
	decodedQuery := ""
	if r.URL.RawQuery != "" {
		if unescaped, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
			decodedQuery = strings.ToLower(unescaped)
		}
	}
	for _, rule := range bb.compiledQueryRules {
		if strings.Contains(rawQuery, rule.Value) || (decodedQuery != "" && strings.Contains(decodedQuery, rule.Value)) {
			return requestRuleMatch{Source: rule.Source, Type: "query_substring"}, true
		}
	}

	for _, rule := range bb.compiledHeaderRules {
		for _, value := range r.Header.Values(rule.Name) {
			if strings.Contains(strings.ToLower(value), rule.Needle) {
				return requestRuleMatch{Source: rule.Source, Type: "header_substring", HeaderName: rule.Name}, true
			}
		}
	}

	return requestRuleMatch{}, false
}

func (bb *CaddyProtector) serveChallenge(w http.ResponseWriter, r *http.Request) error {
	state, err := bb.createReturnState(bb.getOriginalPath(r), time.Now())
	if err != nil {
		bb.logger.Error("Return-State konnte nicht erstellt werden", zap.Error(err))
		http.Error(w, "Challenge-Seite konnte nicht gerendert werden", http.StatusInternalServerError)
		return nil
	}

	configJSON, err := json.Marshal(map[string]any{
		"verifyPath": bb.VerifyPath,
		"state":      state,
	})
	if err != nil {
		bb.logger.Error("Challenge-Konfiguration konnte nicht serialisiert werden", zap.Error(err))
		http.Error(w, "Challenge-Seite konnte nicht gerendert werden", http.StatusInternalServerError)
		return nil
	}

	data := map[string]any{
		"VerifyPath":      bb.VerifyPath,
		"CapWidgetScript": bb.capAssetURL("widget.js"),
		"CapAPIEndpoint":  bb.capAPIEndpoint(),
		"CapWASMURL":      bb.capAssetURL("cap_wasm_bg.wasm"),
		"ConfigJSON":      template.JS(string(configJSON)),
	}

	setNoStoreHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Bot-Barrier", "challenge")

	if !bb.DisableCSPHeader {
		cspNonce, err := generateCSPNonce()
		if err != nil {
			bb.logger.Error("CSP-Nonce konnte nicht erzeugt werden", zap.Error(err))
			http.Error(w, "Challenge-Seite konnte nicht gerendert werden", http.StatusInternalServerError)
			return nil
		}
		w.Header().Set("Content-Security-Policy", bb.challengePageCSP(cspNonce))
		data["CSPNonce"] = template.HTMLAttr(cspNonce)
	}

	if err := bb.renderChallengePage(w, data); err != nil {
		bb.logger.Error("Challenge-Seite konnte nicht gerendert werden", zap.Error(err))
		http.Error(w, "Challenge-Seite konnte nicht gerendert werden", http.StatusInternalServerError)
		return nil
	}

	return nil
}

func (bb *CaddyProtector) loadChallengeTemplate() (*template.Template, error) {
	if bb.TemplatePath == "" {
		return template.New("default").Parse(defaultHTML)
	}

	bb.logger.Debug("Benutzerdefiniertes Template wird geladen", zap.String("template_path", bb.TemplatePath))
	return template.ParseFiles(bb.TemplatePath)
}

func (bb *CaddyProtector) renderChallengePage(w http.ResponseWriter, data map[string]any) error {
	tmpl := bb.challengeTemplate
	if tmpl == nil {
		var err error
		tmpl, err = bb.loadChallengeTemplate()
		if err != nil {
			return fmt.Errorf("template konnte nicht geladen werden: %w", err)
		}
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("template konnte nicht gerendert werden: %w", err)
	}
	return nil
}

func generateCSPNonce() (string, error) {
	nonceBytes := make([]byte, 18)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonceBytes), nil
}

func (bb *CaddyProtector) capAPIEndpoint() string {
	return strings.TrimRight(bb.CapAPIURL, "/") + "/" + strings.Trim(bb.CapSiteKey, "/") + "/"
}

func (bb *CaddyProtector) capAssetURL(assetName string) string {
	return strings.TrimRight(bb.CapAPIURL, "/") + "/assets/" + strings.TrimLeft(assetName, "/")
}

func (bb *CaddyProtector) capSiteVerifyURL() string {
	return strings.TrimRight(bb.CapAPIURL, "/") + "/" + strings.Trim(bb.CapSiteKey, "/") + "/siteverify"
}

func (bb *CaddyProtector) challengePageCSP(cspNonce string) string {
	capOrigin := strings.TrimRight(bb.CapAPIURL, "/")
	jsDelivrOrigin := "https://cdn.jsdelivr.net"

	scriptSrc := strings.Join([]string{
		"'nonce-" + cspNonce + "'",
		"'unsafe-eval'",
		"'wasm-unsafe-eval'",
		capOrigin,
		jsDelivrOrigin,
	}, " ")
	styleSrc := strings.Join([]string{
		"'nonce-" + cspNonce + "'",
		"'unsafe-inline'",
	}, " ")
	connectSrc := strings.Join([]string{
		"'self'",
		capOrigin,
		jsDelivrOrigin,
	}, " ")
	workerSrc := strings.Join([]string{
		"'self'",
		"blob:",
		capOrigin,
		jsDelivrOrigin,
	}, " ")
	frameSrc := strings.Join([]string{
		"'self'",
		"blob:",
	}, " ")

	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + scriptSrc,
		"style-src " + styleSrc,
		"connect-src " + connectSrc,
		"img-src 'self' data:",
		"worker-src " + workerSrc,
		"child-src " + frameSrc,
		"frame-src " + frameSrc,
		"base-uri 'none'",
		"form-action 'self'",
		"object-src 'none'",
	}, "; ") + ";"
}

func setNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeBlacklistedResponse(w http.ResponseWriter) {
	controller := http.NewResponseController(w)
	if controller != nil {
		conn, _, err := controller.Hijack()
		if err == nil {
			_ = conn.Close()
			return
		}
	}

	if hijacker, ok := w.(http.Hijacker); ok {
		conn, _, err := hijacker.Hijack()
		if err == nil {
			_ = conn.Close()
			return
		}
	}

	panic(http.ErrAbortHandler)
}

func decodeVerifyRequest(r io.Reader) (verifyRequest, verifyDecodeInfo, error) {
	body, err := io.ReadAll(r)
	info := verifyDecodeInfo{
		BodyLength:  len(body),
		BodyPreview: shortValue(string(body), 512),
	}
	if err != nil {
		return verifyRequest{}, info, err
	}

	var req verifyRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		info.OriginalDecodeError = err.Error()
		return verifyRequest{}, info, fmt.Errorf("json konnte nicht decodiert werden: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return verifyRequest{}, info, fmt.Errorf("json enthält mehrere Werte")
	}
	return req, info, nil
}

func shortValue(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "…"
}

func deriveMACKey(context string, secret []byte) []byte {
	key := make([]byte, 32)
	blake3.DeriveKey(context, secret, key)
	return key
}

func parseSameSiteMode(raw string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return 0, fmt.Errorf("cookie_same_site muss Lax, Strict oder None sein")
	}
}

func (bb *CaddyProtector) createReturnState(returnPath string, now time.Time) (string, error) {
	return bb.signValue(returnStateClaims{
		Version:    tokenVersion,
		ReturnPath: safeReturnPathFrom(returnPath),
		ExpiresAt:  now.Add(returnStateValidFor).Unix(),
	}, bb.returnStateMACKey)
}

func (bb *CaddyProtector) verifyReturnState(raw string, now time.Time) (returnStateClaims, error) {
	var claims returnStateClaims
	if err := bb.verifySignedValue(raw, bb.returnStateMACKey, &claims); err != nil {
		return returnStateClaims{}, err
	}
	if claims.Version != tokenVersion {
		return returnStateClaims{}, fmt.Errorf("unerwartete Return-State-Version")
	}
	if claims.ExpiresAt <= now.Unix() {
		return returnStateClaims{}, fmt.Errorf("return_state ist abgelaufen")
	}
	if claims.ReturnPath == "" || safeReturnPathFrom(claims.ReturnPath) == "/" && claims.ReturnPath != "/" {
		return returnStateClaims{}, fmt.Errorf("return_state enthaelt ungueltiges return_to")
	}
	return claims, nil
}

func (bb *CaddyProtector) writeAllowCookie(w http.ResponseWriter, now time.Time) error {
	value, err := bb.signValue(allowCookieClaims{
		Version:   tokenVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Duration(bb.AllowFor)).Unix(),
	}, bb.cookieMACKey)
	if err != nil {
		return err
	}
	sameSite, err := parseSameSiteMode(bb.CookieSameSite)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     bb.CookieName,
		Value:    value,
		Path:     bb.CookiePath,
		Domain:   bb.CookieDomain,
		HttpOnly: bb.cookieHTTPOnlyValue(),
		Secure:   bb.cookieSecureValue(),
		SameSite: sameSite,
		Expires:  now.Add(time.Duration(bb.AllowFor)),
		MaxAge:   int(time.Duration(bb.AllowFor).Seconds()),
	})
	return nil
}

func boolPtr(v bool) *bool {
	return &v
}

func (bb *CaddyProtector) cookieSecureValue() bool {
	return bb.CookieSecure != nil && *bb.CookieSecure
}

func (bb *CaddyProtector) cookieHTTPOnlyValue() bool {
	return bb.CookieHTTPOnly != nil && *bb.CookieHTTPOnly
}

func (bb *CaddyProtector) hasValidAllowCookie(r *http.Request) bool {
	cookie, err := r.Cookie(bb.CookieName)
	if err != nil {
		return false
	}
	var claims allowCookieClaims
	if err := bb.verifySignedValue(cookie.Value, bb.cookieMACKey, &claims); err != nil {
		return false
	}
	if claims.Version != tokenVersion {
		return false
	}
	now := time.Now().Unix()
	return claims.ExpiresAt > now && claims.IssuedAt <= now
}

func (bb *CaddyProtector) signValue(payload any, key []byte) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac, err := keyedMAC(key, []byte(payloadPart))
	if err != nil {
		return "", err
	}
	return payloadPart + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func (bb *CaddyProtector) verifySignedValue(raw string, key []byte, out any) error {
	payloadPart, macPart, ok := strings.Cut(raw, ".")
	if !ok || payloadPart == "" || macPart == "" {
		return fmt.Errorf("signierter Wert hat ungültiges Format")
	}
	expectedMAC, err := keyedMAC(key, []byte(payloadPart))
	if err != nil {
		return err
	}
	mac, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil {
		return fmt.Errorf("MAC konnte nicht dekodiert werden: %w", err)
	}
	if subtle.ConstantTimeCompare(expectedMAC, mac) != 1 {
		return fmt.Errorf("MAC ist ungültig")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return fmt.Errorf("Payload konnte nicht dekodiert werden: %w", err)
	}
	if err := json.Unmarshal(payloadJSON, out); err != nil {
		return fmt.Errorf("Payload konnte nicht dekodiert werden: %w", err)
	}
	return nil
}

func keyedMAC(key, data []byte) ([]byte, error) {
	hasher, err := blake3.NewKeyed(key)
	if err != nil {
		return nil, err
	}
	if _, err := hasher.Write(data); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func validateIPListConfig(kind string, inline []string, _ string, rawURL string, refresh caddy.Duration) error {
	if rawURL != "" {
		if err := validateRemoteURL(kind+"_url", rawURL); err != nil {
			return err
		}
	}
	if refresh < 0 {
		return fmt.Errorf("%s_refresh muss groesser oder gleich 0 sein", kind)
	}
	for i, entry := range inline {
		if _, err := parseAllowlistEntry(kind+":inline", i+1, entry); err != nil {
			return err
		}
	}
	return nil
}

func validateCountryConfig(whitelist, blacklist []string, rawURL string, refresh caddy.Duration) error {
	if rawURL != "" {
		if err := validateRemoteURL("country_url", rawURL); err != nil {
			return err
		}
	}
	if refresh < 0 {
		return fmt.Errorf("country_url_refresh muss groesser oder gleich 0 sein")
	}
	if len(whitelist) == 0 && len(blacklist) == 0 {
		return nil
	}
	if rawURL == "" {
		return fmt.Errorf("country_url muss gesetzt sein, wenn whitelist_country oder blacklist_country verwendet wird")
	}
	return nil
}

func validateRemoteURL(fieldName, rawURL string) error {
	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("%s muss eine gueltige absolute URL sein", fieldName)
	}

	switch parsedURL.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(parsedURL.Hostname()) {
			return nil
		}
		return fmt.Errorf("%s muss https verwenden; http ist nur fuer localhost oder Loopback-Adressen erlaubt", fieldName)
	default:
		return fmt.Errorf("%s muss https verwenden; http ist nur fuer localhost oder Loopback-Adressen erlaubt", fieldName)
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeCountryCodes(kind string, codes []string) ([]string, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(codes))
	normalized := make([]string, 0, len(codes))
	for _, raw := range codes {
		code := strings.ToUpper(strings.TrimSpace(raw))
		if !isValidCountryCode(code) {
			return nil, fmt.Errorf("%s enthaelt einen ungueltigen Country-Code: %q", kind, raw)
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		normalized = append(normalized, code)
	}
	return normalized, nil
}

func isValidCountryCode(code string) bool {
	if len(code) != 2 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < 'A' || code[i] > 'Z' {
			return false
		}
	}
	return true
}

func countryCodeSet(codes []string) map[string]struct{} {
	if len(codes) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		set[code] = struct{}{}
	}
	return set
}

func (bb *CaddyProtector) currentAllowlist() *ipAllowlist {
	loaded := bb.allowlist.Load()
	return currentIPList(loaded)
}

func (bb *CaddyProtector) currentBlacklist() *ipAllowlist {
	return currentIPList(bb.blacklist.Load())
}

func (bb *CaddyProtector) isAllowlisted(addr netip.Addr) bool {
	return ipListContains(bb.currentAllowlist(), addr)
}

func (bb *CaddyProtector) isBlacklisted(addr netip.Addr) bool {
	return ipListContains(bb.currentBlacklist(), addr)
}

func (bb *CaddyProtector) isCountryWhitelisted(code string) bool {
	_, ok := bb.whitelistCountrySet[code]
	return ok
}

func (bb *CaddyProtector) isCountryBlacklisted(code string) bool {
	_, ok := bb.blacklistCountrySet[code]
	return ok
}

func (bb *CaddyProtector) lookupCountryCode(addr netip.Addr, addrErr error) (string, bool) {
	if bb.testCountryLookup != nil {
		return bb.testCountryLookup(addr)
	}
	if addrErr != nil {
		return "", false
	}

	bb.countryDBMu.RLock()
	defer bb.countryDBMu.RUnlock()

	if bb.countryDB == nil || bb.countryDB.reader == nil {
		return "", false
	}

	var record geoIPCountryRecord
	if err := bb.countryDB.reader.Lookup(addr).Decode(&record); err != nil {
		return "", false
	}

	code := strings.ToUpper(strings.TrimSpace(record.Country.ISOCode))
	if !isValidCountryCode(code) {
		return "", false
	}
	return code, true
}

func currentIPList(loaded any) *ipAllowlist {
	if loaded == nil {
		return &ipAllowlist{exactIPs: make(map[netip.Addr]struct{})}
	}
	ipList, ok := loaded.(*ipAllowlist)
	if !ok || ipList == nil {
		return &ipAllowlist{exactIPs: make(map[netip.Addr]struct{})}
	}
	return ipList
}

func ipListContains(ipList *ipAllowlist, addr netip.Addr) bool {
	if _, ok := ipList.exactIPs[addr]; ok {
		return true
	}
	for _, prefix := range ipList.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (bb *CaddyProtector) loadAllowlist(ctx context.Context) (*ipAllowlist, error) {
	return bb.loadIPList(ctx, "whitelist", bb.WhitelistIPs, bb.WhitelistFile, bb.WhitelistURL)
}

func (bb *CaddyProtector) loadBlacklist(ctx context.Context) (*ipAllowlist, error) {
	return bb.loadIPList(ctx, "blacklist", bb.BlacklistIPs, bb.BlacklistFile, bb.BlacklistURL)
}

func (bb *CaddyProtector) loadIPList(ctx context.Context, kind string, inline []string, filePath, rawURL string) (*ipAllowlist, error) {
	result := &allowlistParseResult{
		exactIPs: make(map[netip.Addr]struct{}),
		prefixes: make(map[string]netip.Prefix),
	}

	if err := bb.parseAllowlistLines(result, kind+":inline", strings.Join(inline, "\n")); err != nil {
		return nil, err
	}
	if filePath != "" {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("%s_file konnte nicht gelesen werden: %w", kind, err)
		}
		if err := bb.parseAllowlistLines(result, kind+":file:"+filePath, string(content)); err != nil {
			return nil, err
		}
	}
	if rawURL != "" {
		content, err := bb.fetchIPListURL(ctx, kind, rawURL)
		if err != nil {
			return nil, err
		}
		if err := bb.parseAllowlistLines(result, kind+":url:"+rawURL, content); err != nil {
			return nil, err
		}
	}

	prefixes := make([]netip.Prefix, 0, len(result.prefixes))
	for _, prefix := range result.prefixes {
		prefixes = append(prefixes, prefix)
	}

	return &ipAllowlist{
		exactIPs: result.exactIPs,
		prefixes: prefixes,
		sources:  append([]string(nil), result.sources...),
		entries:  result.entries,
	}, nil
}

func (bb *CaddyProtector) parseAllowlistLines(result *allowlistParseResult, source, content string) error {
	result.sources = append(result.sources, source)
	if strings.TrimSpace(content) == "" {
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		entry, err := parseAllowlistEntry(source, lineNo, scanner.Text())
		if err != nil {
			return err
		}
		if entry == nil {
			continue
		}
		if entry.prefix.IsValid() {
			if _, ok := result.prefixes[entry.prefix.String()]; !ok {
				result.entries++
			}
			result.prefixes[entry.prefix.String()] = entry.prefix
			continue
		}
		if _, ok := result.exactIPs[entry.addr]; !ok {
			result.entries++
		}
		result.exactIPs[entry.addr] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("%s konnte nicht gelesen werden: %w", source, err)
	}
	return nil
}

func parseAllowlistEntry(source string, lineNo int, raw string) (*allowlistEntry, error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return nil, nil
	}
	if strings.Contains(line, "/") {
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("ungueltiger Allowlist-Eintrag in %s Zeile %d: %q", source, lineNo, raw)
		}
		return &allowlistEntry{prefix: prefix.Masked()}, nil
	}

	addr, err := netip.ParseAddr(line)
	if err != nil {
		return nil, fmt.Errorf("ungueltiger Allowlist-Eintrag in %s Zeile %d: %q", source, lineNo, raw)
	}
	return &allowlistEntry{addr: addr}, nil
}

func (bb *CaddyProtector) fetchIPListURL(ctx context.Context, kind, rawURL string) (string, error) {
	body, err := bb.fetchURLBytes(ctx, kind, rawURL)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (bb *CaddyProtector) fetchURLBytes(ctx context.Context, kind, rawURL string) ([]byte, error) {
	limit := maxIPListBytes
	if kind == "country" {
		limit = maxCountryDBBytes
	}
	return bb.fetchURLBytesLimited(ctx, kind, rawURL, int64(limit))
}

func (bb *CaddyProtector) fetchURLBytesLimited(ctx context.Context, kind, rawURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%s_url konnte nicht erstellt werden: %w", kind, err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s_url konnte nicht geladen werden: %w", kind, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s_url lieferte HTTP %d", kind, resp.StatusCode)
	}

	if maxBytes <= 0 {
		return nil, fmt.Errorf("%s_url hat ein ungueltiges Groessenlimit", kind)
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("%s_url ist zu gross: %d Bytes, erlaubt sind maximal %d Bytes", kind, resp.ContentLength, maxBytes)
	}

	limited := io.LimitReader(resp.Body, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%s_url konnte nicht gelesen werden: %w", kind, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%s_url ist zu gross: erlaubt sind maximal %d Bytes", kind, maxBytes)
	}
	return body, nil
}

func (bb *CaddyProtector) runIPListRefreshLoop(kind string, refresh time.Duration, stop chan struct{}, done chan struct{}, load func(context.Context) (*ipAllowlist, error), store func(any)) {
	defer close(done)

	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			ipList, err := load(ctx)
			cancel()
			if err != nil {
				bb.logger.Warn("IP-Listen-Refresh fehlgeschlagen", zap.String("list", kind), zap.Error(err))
				continue
			}
			store(ipList)
			bb.logIPListLoaded("refresh", kind, ipList)
		case <-stop:
			return
		}
	}
}

func (bb *CaddyProtector) loadCountryDB(ctx context.Context) (*countryDB, error) {
	if bb.testCountryLoader != nil {
		return bb.testCountryLoader(ctx, bb.CountryURL)
	}

	body, err := bb.fetchURLBytes(ctx, "country", bb.CountryURL)
	if err != nil {
		return nil, err
	}

	reader, err := maxminddb.OpenBytes(body)
	if err != nil {
		return nil, fmt.Errorf("country_url enthaelt keine gueltige MMDB: %w", err)
	}

	return &countryDB{
		reader: reader,
		source: "country:url:" + bb.CountryURL,
		size:   len(body),
	}, nil
}

func (bb *CaddyProtector) setCountryDB(next *countryDB) {
	bb.countryDBMu.Lock()
	prev := bb.countryDB
	bb.countryDB = next
	bb.countryDBMu.Unlock()

	if prev != nil && prev.reader != nil {
		_ = prev.reader.Close()
	}
}

func (bb *CaddyProtector) runCountryRefreshLoop(refresh time.Duration, stop chan struct{}, done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			db, err := bb.loadCountryDB(ctx)
			cancel()
			if err != nil {
				bb.logger.Warn("Country-DB-Refresh fehlgeschlagen", zap.Error(err))
				continue
			}
			bb.setCountryDB(db)
			bb.logCountryDBLoaded("refresh", db)
		case <-stop:
			return
		}
	}
}

func (bb *CaddyProtector) logCountryDBLoaded(mode string, db *countryDB) {
	if db == nil {
		return
	}
	bb.logger.Info("Country-DB geladen",
		zap.String("mode", mode),
		zap.String("source", db.source),
		zap.Int("size_bytes", db.size),
	)
}

func (bb *CaddyProtector) logAllowlistLoaded(mode string, allowlist *ipAllowlist) {
	bb.logIPListLoaded(mode, "allowlist", allowlist)
}

func (bb *CaddyProtector) logIPListLoaded(mode, kind string, ipList *ipAllowlist) {
	if ipList == nil {
		return
	}
	bb.logger.Info("IP-Liste geladen",
		zap.String("mode", mode),
		zap.String("list", kind),
		zap.Int("entries", ipList.entries),
		zap.Int("exact_ips", len(ipList.exactIPs)),
		zap.Int("prefixes", len(ipList.prefixes)),
		zap.Strings("sources", ipList.sources),
	)
}

func (bb *CaddyProtector) handleVerify(w http.ResponseWriter, r *http.Request) error {
	setNoStoreHeaders(w)
	clientIP := getClientIP(r.Context(), r.RemoteAddr)
	logger := bb.logger.With(
		zap.String("event", "caddy_protector_verify"),
		zap.String("client_ip", clientIP),
		zap.String("method", r.Method),
		zap.String("requested_url", redactURLForLog(r.URL)),
		zap.String("user_agent", r.UserAgent()),
		zap.String("content_type", r.Header.Get("Content-Type")),
		zap.String("origin", r.Header.Get("Origin")),
		zap.String("referer", redactHeaderURLForLog(r.Header.Get("Referer"))),
		zap.Int64("content_length", r.ContentLength),
	)

	if !isJSONContentType(r.Header.Get("Content-Type")) {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Content-Type ist nicht application/json")
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return nil
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxVerifyBodyBytes)
	defer func() {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}()

	req, decodeInfo, err := decodeVerifyRequest(r.Body)
	if err != nil {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Request-Body ist kein gültiges JSON",
			zap.Int("body_length", decodeInfo.BodyLength),
			zap.String("json_error", decodeInfo.OriginalDecodeError),
			zap.String("hint", `Der Browser muss echtes JSON wie {"token":"...","state":"..."} mit Content-Type application/json senden.`),
			zap.Error(err),
		)
		http.Error(w, "ungueltige anfrage", http.StatusBadRequest)
		return nil
	}
	if strings.TrimSpace(req.Token) == "" {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Cap-Token fehlt")
		http.Error(w, "token fehlt", http.StatusBadRequest)
		return nil
	}
	if strings.TrimSpace(req.State) == "" {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Return-State fehlt")
		http.Error(w, "state fehlt", http.StatusBadRequest)
		return nil
	}

	now := time.Now()
	stateClaims, err := bb.verifyReturnState(req.State, now)
	if err != nil {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Return-State ist ungültig", zap.Error(err))
		http.Error(w, "challenge abgelaufen", http.StatusForbidden)
		return nil
	}

	ok, err := bb.verifyCapToken(r.Context(), req.Token)
	if err != nil {
		logger.Error("Cap-Siteverify fehlgeschlagen", zap.Error(err))
		http.Error(w, "cap verification failed", http.StatusBadGateway)
		return nil
	}
	if !ok {
		logger.Warn("Cap-Siteverify hat das Token abgelehnt")
		http.Error(w, "ungueltige verifikation", http.StatusForbidden)
		return nil
	}

	returnTo := safeReturnPathFrom(stateClaims.ReturnPath)
	if err := bb.writeAllowCookie(w, now); err != nil {
		logger.Error("Freigabe-Cookie konnte nicht gesetzt werden", zap.Error(err))
		http.Error(w, "Freigabe-Cookie konnte nicht gesetzt werden", http.StatusInternalServerError)
		return nil
	}

	logger.Info("CaddyProtector-Verify erfolgreich",
		zap.String("return_to", redactPathForLog(returnTo)),
		zap.Time("allowed_until", now.Add(time.Duration(bb.AllowFor))),
	)

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"returnTo": returnTo,
	})
}

func (bb *CaddyProtector) verifyCapToken(ctx context.Context, token string) (bool, error) {
	payload, err := json.Marshal(map[string]string{
		"secret":   bb.CapSecretKey,
		"response": token,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bb.capSiteVerifyURL(), bytes.NewReader(payload))
	if err != nil {
		return false, fmt.Errorf("siteverify request konnte nicht erstellt werden: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return false, fmt.Errorf("siteverify request fehlgeschlagen: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, fmt.Errorf("siteverify lieferte HTTP %d: %s", resp.StatusCode, shortValue(string(body), 256))
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result); err != nil {
		return false, fmt.Errorf("siteverify response konnte nicht gelesen werden: %w", err)
	}
	return result.Success, nil
}

// getClientIP liest die Client-IP direkt aus dem Caddy-Kontext.
func getClientIP(ctx context.Context, remoteAddr string) string {
	if vars, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any); ok {
		if clientIP, ok := vars["client_ip"].(string); ok && clientIP != "" {
			return clientIP
		}
	}

	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return clientIP
}

// Interface-Guards für die benötigten Interfaces.
var (
	_ caddy.Module                = (*CaddyProtector)(nil)
	_ caddy.Provisioner           = (*CaddyProtector)(nil)
	_ caddy.Validator             = (*CaddyProtector)(nil)
	_ caddy.CleanerUpper          = (*CaddyProtector)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyProtector)(nil)
)

func (bb *CaddyProtector) Cleanup() error {
	if bb.allowlistStop != nil {
		close(bb.allowlistStop)
		<-bb.allowlistDone
		bb.allowlistStop = nil
		bb.allowlistDone = nil
	}
	if bb.blacklistStop != nil {
		close(bb.blacklistStop)
		<-bb.blacklistDone
		bb.blacklistStop = nil
		bb.blacklistDone = nil
	}
	if bb.countryStop != nil {
		close(bb.countryStop)
		<-bb.countryDone
		bb.countryStop = nil
		bb.countryDone = nil
	}
	bb.setCountryDB(nil)
	return nil
}
