package caddyprotector

import (
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	_ "embed"
)

//go:embed challenge_template.html
var defaultHTML string

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
	var countryCode string
	var countryFound bool
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
