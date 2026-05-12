package caddyprotector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/bits"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strconv"
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

//go:embed tools/challenge-src/dist/challenge.bundle.js
var embeddedBundle string

const (
	defaultComplexity           = "16"
	defaultVerifyPath           = "/__caddy_protector/verify"
	defaultValidFor             = 120 * time.Second
	defaultAllowFor             = 1800 * time.Second
	defaultMaxChallengeAttempts = 10
	defaultMaxPendingChallenges = 100000
	defaultBlockFor             = 1800 * time.Second
	maxVerifyBodyBytes          = 4096
	maxVerifyAttempts           = 3
	challengeSeedLength         = 32
	maxNonceLength              = 64
	blake3HashBits              = 256
)

type pendingChallenge struct {
	Key        string
	Seed       []byte
	ExpiresAt  time.Time
	Attempts   int
	ReturnPath string
}

type challengeAttemptCounter struct {
	Count        int
	FirstSeen    time.Time
	BlockedUntil time.Time
}

type verifyRequest struct {
	Seed  string `json:"seed"`
	Nonce string `json:"nonce"`
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

// CaddyProtector ist ein Caddy-Middleware-Modul, das vor dem Zugriff auf HTTP-Ressourcen
// das Lösen einer Rechen-Challenge verlangt.
type CaddyProtector struct {
	// Complexity definiert die Anzahl benötigter führender Null-Bits in
	// BLAKE3(seed || nonce).
	Complexity string `json:"complexity,omitempty"`

	// ValidFor bestimmt die Gültigkeitsdauer einer offenen Challenge.
	ValidFor caddy.Duration `json:"valid_for,omitempty"`

	// TemplatePath ist der Pfad zu einem benutzerdefinierten HTML-Template.
	TemplatePath string `json:"template,omitempty"`

	// CSPScriptSrc definiert zusaetzliche Quellen, die in der script-src CSP-Direktive erlaubt werden.
	CSPScriptSrc []string `json:"csp_script_src,omitempty"`

	// DisableCSPHeader deaktiviert den von CaddyProtector gesetzten CSP-Header.
	DisableCSPHeader bool `json:"disable_csp_header,omitempty"`

	// AllowFor bestimmt, wie lange ein erfolgreicher Client freigegeben bleibt.
	AllowFor caddy.Duration `json:"allow_for,omitempty"`

	// VerifyPath ist der interne POST-Endpunkt für die Verifikation.
	VerifyPath string `json:"verify_path,omitempty"`

	// MaxChallengeAttempts bestimmt, wie viele Challenge-Seiten ein Client
	// abrufen darf, bevor er temporär blockiert wird.
	MaxChallengeAttempts int `json:"max_challenge_attempts,omitempty"`

	// MaxPendingChallenges begrenzt die Anzahl serverseitig gespeicherter,
	// noch nicht gelöster Challenges.
	MaxPendingChallenges int `json:"max_pending_challenges,omitempty"`

	// BlockFor bestimmt, wie lange ein Client nach zu vielen Challenge-Abrufen
	// blockiert bleibt.
	BlockFor caddy.Duration `json:"block_for,omitempty"`

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

	mu                  sync.Mutex
	pending             map[string]pendingChallenge
	allowed             map[string]time.Time
	challengeAttempts   map[string]challengeAttemptCounter
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
	cleanupStop         chan struct{}
	cleanupDone         chan struct{}
	whitelistCountrySet map[string]struct{}
	blacklistCountrySet map[string]struct{}
	hasCountryRules     bool
	hasCountryWhitelist bool
	testCountryLookup   func(netip.Addr) (string, bool)
	testCountryLoader   func(context.Context, string) (*countryDB, error)
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

	if bb.Complexity == "" {
		bb.Complexity = defaultComplexity
	}
	if bb.ValidFor == 0 {
		bb.ValidFor = caddy.Duration(defaultValidFor)
	}
	if bb.AllowFor == 0 {
		bb.AllowFor = caddy.Duration(defaultAllowFor)
	}
	if bb.VerifyPath == "" {
		bb.VerifyPath = defaultVerifyPath
	}
	if bb.MaxChallengeAttempts == 0 {
		bb.MaxChallengeAttempts = defaultMaxChallengeAttempts
	}
	if bb.MaxPendingChallenges == 0 {
		bb.MaxPendingChallenges = defaultMaxPendingChallenges
	}
	if bb.BlockFor == 0 {
		bb.BlockFor = caddy.Duration(defaultBlockFor)
	}
	if bb.pending == nil {
		bb.pending = make(map[string]pendingChallenge)
	}
	if bb.allowed == nil {
		bb.allowed = make(map[string]time.Time)
	}
	if bb.challengeAttempts == nil {
		bb.challengeAttempts = make(map[string]challengeAttemptCounter)
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

	// Periodischer Cleanup abgelaufener Einträge im Hintergrund
	bb.cleanupStop = make(chan struct{})
	bb.cleanupDone = make(chan struct{})
	go bb.runCleanupLoop(bb.cleanupInterval(), bb.cleanupStop, bb.cleanupDone)

	bb.logger.Info("CaddyProtector-Modul erfolgreich initialisiert",
		zap.String("complexity", bb.Complexity),
		zap.Duration("valid_for", time.Duration(bb.ValidFor)),
		zap.Duration("allow_for", time.Duration(bb.AllowFor)),
		zap.String("verify_path", bb.VerifyPath),
		zap.Int("max_challenge_attempts", bb.MaxChallengeAttempts),
		zap.Int("max_pending_challenges", bb.MaxPendingChallenges),
		zap.Duration("block_for", time.Duration(bb.BlockFor)),
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
	if bb.Complexity == "" {
		return fmt.Errorf("complexity muss eine Ganzzahl oder ein Placeholder wie {vars.complexity} sein, gefunden: %s", bb.Complexity)
	}
	if bb.Complexity[0] != '{' {
		if _, err := parseComplexityValue(bb.Complexity); err != nil {
			return err
		}
	}
	if time.Duration(bb.ValidFor) <= 0 {
		return fmt.Errorf("valid_for muss größer als 0 sein")
	}
	if time.Duration(bb.AllowFor) <= 0 {
		return fmt.Errorf("allow_for muss größer als 0 sein")
	}
	if bb.VerifyPath == "" || bb.VerifyPath[0] != '/' {
		return fmt.Errorf("verify_path muss mit '/' beginnen")
	}
	if bb.MaxChallengeAttempts < 1 {
		return fmt.Errorf("max_challenge_attempts muss mindestens 1 sein")
	}
	if bb.MaxPendingChallenges < 1 {
		return fmt.Errorf("max_pending_challenges muss mindestens 1 sein")
	}
	if time.Duration(bb.BlockFor) <= 0 {
		return fmt.Errorf("block_for muss größer als 0 sein")
	}
	return nil
}

// ServeHTTP prüft den Challenge-Status oder liefert eine Challenge-Seite aus.
func (bb *CaddyProtector) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := getClientIP(r.Context(), r.RemoteAddr)
	key := clientKey(clientIP, r.UserAgent())

	logger := bb.logger.With(
		zap.String("client_ip", clientIP),
		zap.String("method", r.Method),
		zap.String("requested_url", redactURLForLog(r.URL)),
	)

	complexity := bb.resolveComplexity(r, logger)
	if r.Method == http.MethodPost && r.URL.Path == bb.VerifyPath {
		if complexity == 0 {
			logger.Warn("Verify-Endpunkt wurde trotz deaktivierter Challenge aufgerufen")
			http.Error(w, "challenge deaktiviert", http.StatusNotFound)
			return nil
		}
		return bb.handleVerify(w, r, key, complexity)
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

	if complexity == 0 {
		logger.Info("Complexity ist 0, Challenge wird übersprungen")
		return next.ServeHTTP(w, r)
	}

	if bb.isAllowed(key) {
		logger.Debug("Client ist bereits freigegeben")
		return next.ServeHTTP(w, r)
	}

	if blocked, retryAfter := bb.registerChallengeAttempt(key); blocked {
		logger.Warn("Client wird wegen zu vieler Challenge-Abrufe temporär blockiert",
			zap.Int("max_challenge_attempts", bb.MaxChallengeAttempts),
			zap.Duration("retry_after", retryAfter),
		)
		writeBlockedResponse(w, retryAfter)
		return nil
	}

	logger.Info("Challenge-Seite wird ausgeliefert")
	return bb.serveChallenge(w, r, key, complexity)
}

func parseComplexityValue(value string) (int, error) {
	complexity, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("complexity muss eine Ganzzahl oder ein Placeholder wie {vars.complexity} sein, gefunden: %s", value)
	}
	if complexity < 0 {
		return 0, fmt.Errorf("complexity muss mindestens 0 sein, gefunden: %d", complexity)
	}
	if complexity > blake3HashBits {
		return 0, fmt.Errorf("complexity darf höchstens %d sein, weil BLAKE3-256 nur %d Hash-Bits liefert, gefunden: %d", blake3HashBits, blake3HashBits, complexity)
	}
	return complexity, nil
}

func (bb *CaddyProtector) resolveComplexity(r *http.Request, logger *zap.Logger) int {
	complexityStr := bb.Complexity
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok && repl != nil {
		complexityStr = repl.ReplaceAll(bb.Complexity, defaultComplexity)
	}

	complexity, err := parseComplexityValue(complexityStr)
	if err != nil {
		logger.Error("Ungültiger Complexity-Wert nach Placeholder-Ersetzung, es wird der Standardwert verwendet", zap.String("complexity", complexityStr), zap.Error(err))
		complexity, _ = parseComplexityValue(defaultComplexity)
		return complexity
	}
	return complexity
}

func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func safeReturnPath(r *http.Request) string {
	returnPath := r.URL.RequestURI()
	if returnPath == "" || returnPath[0] != '/' || strings.HasPrefix(returnPath, "//") {
		return "/"
	}
	// Pfad-Traversal verhindern mit path.Clean
	parts := strings.SplitN(returnPath, "?", 2)
	rawPath := parts[0]
	cleanPath := path.Clean(rawPath)
	if cleanPath == "." || !strings.HasPrefix(cleanPath, "/") {
		return "/"
	}
	if len(parts) > 1 {
		return cleanPath + "?" + parts[1]
	}
	return cleanPath
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

func (bb *CaddyProtector) serveChallenge(w http.ResponseWriter, r *http.Request, key string, complexity int) error {
	seedHex, err := bb.createPendingChallenge(key, safeReturnPath(r))
	if err != nil {
		bb.logger.Error("Challenge konnte nicht erstellt werden", zap.Error(err))
		http.Error(w, "Seed-Erzeugung fehlgeschlagen", http.StatusInternalServerError)
		return nil
	}

	data := map[string]any{
		"Seed":        seedHex,
		"Complexity":  complexity,
		"VerifyPath":  bb.VerifyPath,
		"ChallengeJS": template.JS(embeddedBundle),
	}

	configJSON, err := json.Marshal(map[string]any{
		"seed":       seedHex,
		"complexity": complexity,
		"verifyPath": bb.VerifyPath,
	})
	if err != nil {
		bb.logger.Error("Challenge-Konfiguration konnte nicht serialisiert werden", zap.Error(err))
		http.Error(w, "Challenge-Seite konnte nicht gerendert werden", http.StatusInternalServerError)
		return nil
	}
	data["ConfigJSON"] = template.JS(string(configJSON))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Bot-Barrier", "challenge")

	if !bb.DisableCSPHeader {
		cspNonce, err := generateCSPNonce()
		if err != nil {
			bb.logger.Error("CSP-Nonce konnte nicht erzeugt werden", zap.Error(err))
			http.Error(w, "Challenge-Seite konnte nicht gerendert werden", http.StatusInternalServerError)
			return nil
		}
		scriptSrc := fmt.Sprintf("'nonce-%s'", cspNonce)
		for _, src := range bb.CSPScriptSrc {
			scriptSrc += " " + src
		}
		w.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; script-src %s; style-src 'nonce-%s'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none';", scriptSrc, cspNonce))
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

func clientKey(ip, userAgent string) string {
	return ip + "\x00" + userAgent
}

func (bb *CaddyProtector) isAllowed(key string) bool {
	now := time.Now()

	bb.mu.Lock()
	defer bb.mu.Unlock()

	exp, ok := bb.allowed[key]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(bb.allowed, key)
		return false
	}
	return true
}

func (bb *CaddyProtector) markAllowed(key string) {
	bb.mu.Lock()
	defer bb.mu.Unlock()

	bb.allowed[key] = time.Now().Add(time.Duration(bb.AllowFor))
	delete(bb.challengeAttempts, key)
}

func (bb *CaddyProtector) registerChallengeAttempt(key string) (bool, time.Duration) {
	now := time.Now()
	blockFor := time.Duration(bb.BlockFor)

	bb.mu.Lock()
	defer bb.mu.Unlock()

	counter := bb.challengeAttempts[key]
	if !counter.BlockedUntil.IsZero() {
		if now.Before(counter.BlockedUntil) {
			return true, counter.BlockedUntil.Sub(now)
		}
		counter = challengeAttemptCounter{}
	}
	if counter.FirstSeen.IsZero() || now.Sub(counter.FirstSeen) > blockFor {
		counter = challengeAttemptCounter{FirstSeen: now}
	}

	counter.Count++
	if counter.Count > bb.MaxChallengeAttempts {
		counter.BlockedUntil = now.Add(blockFor)
		bb.challengeAttempts[key] = counter
		return true, blockFor
	}

	bb.challengeAttempts[key] = counter
	return false, 0
}

func writeBlockedResponse(w http.ResponseWriter, retryAfter time.Duration) {
	retryAfterSeconds := int(retryAfter.Round(time.Second).Seconds())
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	w.Header().Set("X-Bot-Barrier", "blocked")
	http.Error(w, "Too Many Requests: zu viele Challenge-Abrufe, bitte später erneut versuchen", http.StatusTooManyRequests)
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

func (bb *CaddyProtector) createPendingChallenge(key, returnPath string) (string, error) {
	seed := make([]byte, challengeSeedLength)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}

	seedHex := hex.EncodeToString(seed)
	now := time.Now()

	bb.mu.Lock()
	defer bb.mu.Unlock()

	if len(bb.pending) >= bb.MaxPendingChallenges {
		return "", fmt.Errorf("zu viele offene Challenges")
	}
	bb.pending[seedHex] = pendingChallenge{
		Key:        key,
		Seed:       append([]byte(nil), seed...),
		ExpiresAt:  now.Add(time.Duration(bb.ValidFor)),
		Attempts:   0,
		ReturnPath: returnPath,
	}

	return seedHex, nil
}

// cleanupInterval berechnet das optimale Intervall für den periodischen Cleanup.
func (bb *CaddyProtector) cleanupInterval() time.Duration {
	interval := time.Duration(bb.ValidFor) / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 60*time.Second {
		interval = 60 * time.Second
	}
	return interval
}

// runCleanupLoop führt periodisch den Cleanup abgelaufener Einträge im Hintergrund durch.
func (bb *CaddyProtector) runCleanupLoop(refresh time.Duration, stop chan struct{}, done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bb.mu.Lock()
			bb.cleanupExpiredLocked(time.Now())
			bb.mu.Unlock()
		case <-stop:
			return
		}
	}
}

func (bb *CaddyProtector) cleanupExpiredLocked(now time.Time) {
	for seed, pending := range bb.pending {
		if now.After(pending.ExpiresAt) {
			delete(bb.pending, seed)
		}
	}
	for key, exp := range bb.allowed {
		if now.After(exp) {
			delete(bb.allowed, key)
		}
	}
	for key, counter := range bb.challengeAttempts {
		if !counter.BlockedUntil.IsZero() {
			if now.After(counter.BlockedUntil) {
				delete(bb.challengeAttempts, key)
			}
			continue
		}
		if !counter.FirstSeen.IsZero() && now.Sub(counter.FirstSeen) > time.Duration(bb.BlockFor) {
			delete(bb.challengeAttempts, key)
		}
	}
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

func validateIPListConfig(kind string, inline []string, _ string, rawURL string, refresh caddy.Duration) error {
	if rawURL != "" {
		parsedURL, err := url.Parse(rawURL)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			return fmt.Errorf("%s_url muss eine gueltige absolute URL sein", kind)
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
		parsedURL, err := url.Parse(rawURL)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			return fmt.Errorf("country_url muss eine gueltige absolute URL sein")
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s_url konnte nicht gelesen werden: %w", kind, err)
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

func (bb *CaddyProtector) handleVerify(w http.ResponseWriter, r *http.Request, key string, complexity int) error {
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
		zap.Int("complexity", complexity),
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
			zap.String("hint", `Der Browser muss echtes JSON wie {"seed":"...","nonce":"..."} mit Content-Type application/json senden.`),
			zap.Error(err),
		)
		http.Error(w, "ungültige Anfrage", http.StatusBadRequest)
		return nil
	}

	logger = logger.With(
		zap.String("seed", shortValue(req.Seed, 16)),
		zap.Int("seed_hex_length", len(req.Seed)),
		zap.Int("nonce_hex_length", len(req.Nonce)),
	)

	seedBytes, err := hex.DecodeString(req.Seed)
	if err != nil || len(seedBytes) != challengeSeedLength {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Seed ist ungültig",
			zap.Int("decoded_seed_length", len(seedBytes)),
			zap.Int("expected_seed_length", challengeSeedLength),
			zap.Error(err),
		)
		http.Error(w, "ungültiger Seed", http.StatusBadRequest)
		return nil
	}

	nonceBytes, err := hex.DecodeString(req.Nonce)
	if err != nil || len(nonceBytes) == 0 || len(nonceBytes) > maxNonceLength {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Nonce ist ungültig",
			zap.Int("decoded_nonce_length", len(nonceBytes)),
			zap.Int("max_nonce_length", maxNonceLength),
			zap.Error(err),
		)
		http.Error(w, "ungültige Nonce", http.StatusBadRequest)
		return nil
	}

	now := time.Now()

	bb.mu.Lock()

	pending, ok := bb.pending[req.Seed]
	keyMatches := ok && pending.Key == key
	seedMatches := ok && bytes.Equal(pending.Seed, seedBytes)
	challengeExpired := ok && now.After(pending.ExpiresAt)
	if !ok || !keyMatches || !seedMatches || challengeExpired {
		if ok {
			delete(bb.pending, req.Seed)
		}
		bb.mu.Unlock()
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Challenge passt nicht zum aktuellen Client oder ist abgelaufen",
			zap.Bool("pending_found", ok),
			zap.Bool("client_key_matches", keyMatches),
			zap.Bool("seed_bytes_match", seedMatches),
			zap.Bool("challenge_expired", challengeExpired),
			zap.Time("pending_expires_at", pending.ExpiresAt),
			zap.Duration("pending_time_remaining", time.Until(pending.ExpiresAt)),
			zap.Int("pending_attempts", pending.Attempts),
			zap.String("return_path", redactPathForLog(pending.ReturnPath)),
		)
		http.Error(w, "challenge abgelaufen", http.StatusForbidden)
		return nil
	}

	pending.Attempts++
	if pending.Attempts > maxVerifyAttempts {
		delete(bb.pending, req.Seed)
		bb.mu.Unlock()
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: zu viele Verify-Versuche",
			zap.Int("attempts", pending.Attempts),
			zap.Int("max_attempts", maxVerifyAttempts),
			zap.String("return_path", redactPathForLog(pending.ReturnPath)),
		)
		http.Error(w, "zu viele Versuche", http.StatusTooManyRequests)
		return nil
	}

	bb.pending[req.Seed] = pending
	bb.mu.Unlock()

	input := make([]byte, 0, len(seedBytes)+len(nonceBytes))
	input = append(input, seedBytes...)
	input = append(input, nonceBytes...)

	sum := blake3.Sum256(input)
	leadingZeroBits := countLeadingZeroBits(sum[:])
	if leadingZeroBits < complexity {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Proof-of-Work-Lösung erfüllt die Complexity nicht",
			zap.Int("leading_zero_bits", leadingZeroBits),
			zap.Int("required_zero_bits", complexity),
			zap.String("hash_prefix", hex.EncodeToString(sum[:4])),
			zap.Int("attempts", pending.Attempts),
			zap.String("return_path", redactPathForLog(pending.ReturnPath)),
		)
		http.Error(w, "ungültige Lösung", http.StatusForbidden)
		return nil
	}

	allowedUntil := now.Add(time.Duration(bb.AllowFor))
	bb.mu.Lock()
	delete(bb.pending, req.Seed)
	bb.allowed[key] = allowedUntil
	delete(bb.challengeAttempts, key)
	returnTo := pending.ReturnPath
	bb.mu.Unlock()

	logger.Info("CaddyProtector-Verify erfolgreich",
		zap.Int("leading_zero_bits", leadingZeroBits),
		zap.Int("attempts", pending.Attempts),
		zap.String("return_to", redactPathForLog(returnTo)),
		zap.Time("allowed_until", allowedUntil),
	)

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"returnTo": returnTo,
	})
}

// countLeadingZeroBits zählt führende Null-Bits in einem Byte-Slice.
func countLeadingZeroBits(data []byte) int {
	count := 0
	for _, b := range data {
		if b == 0 {
			count += 8
			continue
		}
		return count + bits.LeadingZeros8(uint8(b))
	}
	return count
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
	if bb.cleanupStop != nil {
		close(bb.cleanupStop)
		<-bb.cleanupDone
		bb.cleanupStop = nil
		bb.cleanupDone = nil
	}
	bb.setCountryDB(nil)
	return nil
}
