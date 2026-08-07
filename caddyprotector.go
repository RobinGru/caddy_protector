package caddyprotector

import (
	"context"
	"html/template"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/maxminddb-golang/v2"
	"go.uber.org/zap"
)

const (
	defaultVerifyPath            = "/__caddy_protector/verify"
	defaultAllowFor              = 1800 * time.Minute
	defaultCookieName            = "caddy_protector"
	maxVerifyBodyBytes           = 4096
	maxIPListBytes               = 100 << 20
	maxCountryDBBytes            = 100 << 20
	tokenVersion                 = 1
	returnStateValidFor          = 15 * time.Minute
	returnStateContext           = "caddy_protector:return_state:v1"
	cookieMACContext             = "caddy_protector:cookie_mac:v1"
	configRuleSource             = "config"
	cspSelfSource                = "'self'"
	verifyRateLimitBurst         = 15
	verifyRateLimitRefill        = 3 * time.Second
	verifyRateLimitEntryLifetime = verifyRateLimitBurst * verifyRateLimitRefill
	maxVerifyRateLimitEntries    = 10000
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

type verifyRateLimitEntry struct {
	tokens     int
	lastRefill time.Time
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

// HeaderSubstringRule describes a header name and a substring to deny.
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

// CaddyProtector is a Caddy middleware module that protects requests with a
// preliminary Cap verification and sets a signed allow cookie after verification.
type CaddyProtector struct {
	// TemplatePath is the path to a custom HTML template.
	TemplatePath string `json:"template,omitempty"`

	// DisableCSPHeader disables the CSP header set by CaddyProtector.
	DisableCSPHeader bool `json:"disable_csp_header,omitempty"`

	// AllowFor determines how long a successfully verified client remains allowed.
	AllowFor caddy.Duration `json:"allow_for,omitempty"`

	// VerifyPath is the internal POST endpoint for verification.
	VerifyPath string `json:"verify_path,omitempty"`

	// CapAPIURL is the public base URL of the Cap instance.
	CapAPIURL string `json:"cap_api_url,omitempty"`

	// CapSiteKey is the site key of the Cap instance.
	CapSiteKey string `json:"cap_site_key,omitempty"`

	// CapSecretKey is the secret key for server-side /siteverify requests.
	CapSecretKey string `json:"cap_secret_key,omitempty"`

	// CookieName is the name of the allow cookie.
	CookieName string `json:"cookie_name,omitempty"`

	// CookiePath is the path of the allow cookie.
	CookiePath string `json:"cookie_path,omitempty"`

	// CookieDomain optionally sets the domain of the allow cookie.
	CookieDomain string `json:"cookie_domain,omitempty"`

	// CookieSecure controls the Secure flag of the allow cookie.
	CookieSecure *bool `json:"cookie_secure,omitempty"`

	// CookieHTTPOnly controls the HttpOnly flag of the allow cookie.
	CookieHTTPOnly *bool `json:"cookie_http_only,omitempty"`

	// CookieSameSite controls the SameSite attribute of the allow cookie.
	CookieSameSite string `json:"cookie_same_site,omitempty"`

	// DenyPathPrefixes denies requests with matching path prefixes.
	DenyPathPrefixes []string `json:"deny_path_prefix,omitempty"`

	// DenyQuerySubstrings denies requests with matching query substrings.
	DenyQuerySubstrings []string `json:"deny_query_substring,omitempty"`

	// DenyHeaderSubstrings denies requests with matching header substrings.
	DenyHeaderSubstrings []HeaderSubstringRule `json:"deny_header_substring,omitempty"`

	// WhitelistIPs are IPs or CIDR prefixes allowed without a challenge.
	WhitelistIPs []string `json:"whitelist_ip,omitempty"`

	// WhitelistFile points to a file with IP or CIDR entries.
	WhitelistFile string `json:"whitelist_file,omitempty"`

	// WhitelistURL points to a URL with IP or CIDR entries.
	WhitelistURL string `json:"whitelist_url,omitempty"`

	// WhitelistRefresh determines the refresh interval for file and URL sources.
	WhitelistRefresh caddy.Duration `json:"whitelist_refresh,omitempty"`

	// WhitelistCountries limits requests to specific ISO-3166-1 alpha-2 countries.
	WhitelistCountries []string `json:"whitelist_country,omitempty"`

	// BlacklistIPs are IPs or CIDR prefixes denied immediately.
	BlacklistIPs []string `json:"blacklist_ip,omitempty"`

	// BlacklistFile points to a file with IP or CIDR entries.
	BlacklistFile string `json:"blacklist_file,omitempty"`

	// BlacklistURL points to a URL with IP or CIDR entries.
	BlacklistURL string `json:"blacklist_url,omitempty"`

	// BlacklistRefresh determines the refresh interval for file and URL sources.
	BlacklistRefresh caddy.Duration `json:"blacklist_refresh,omitempty"`

	// BlacklistCountries denies requests from specific ISO-3166-1 alpha-2 countries.
	BlacklistCountries []string `json:"blacklist_country,omitempty"`

	// CountryURL points to a MaxMind MMDB for country lookups.
	CountryURL string `json:"country_url,omitempty"`

	// CountryRefresh determines the refresh interval for the country MMDB.
	CountryRefresh caddy.Duration `json:"country_url_refresh,omitempty"`

	challengeTemplate     *template.Template
	logger                *zap.Logger
	allowlist             atomic.Value
	blacklist             atomic.Value
	countryDBMu           sync.RWMutex
	countryDB             *countryDB
	allowlistStop         chan struct{}
	allowlistDone         chan struct{}
	blacklistStop         chan struct{}
	blacklistDone         chan struct{}
	countryStop           chan struct{}
	countryDone           chan struct{}
	whitelistCountrySet   map[string]struct{}
	blacklistCountrySet   map[string]struct{}
	hasCountryRules       bool
	hasCountryWhitelist   bool
	testCountryLookup     func(netip.Addr) (string, bool)
	testCountryLoader     func(context.Context, string) (*countryDB, error)
	testOutboundTransport http.RoundTripper
	returnStateMACKey     []byte
	cookieMACKey          []byte
	compiledPathRules     []compiledStringRule
	compiledQueryRules    []compiledStringRule
	compiledHeaderRules   []compiledHeaderRule
	verifyRateLimitMu     sync.Mutex
	verifyRateLimits      map[netip.Addr]verifyRateLimitEntry
	testNow               func() time.Time
}
