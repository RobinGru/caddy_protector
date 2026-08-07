package caddyprotector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/maxminddb-golang/v2"
	"go.uber.org/zap"
)

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
		if _, _, err := parseAllowlistEntry(kind+":inline", i+1, entry); err != nil {
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
	case httpsScheme:
		return nil
	case httpScheme:
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
		// The Caddy administrator explicitly configures this local list source.
		content, err := os.ReadFile(filePath) // #nosec G304 -- operator-configured allowlist source.
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
		entry, skip, err := parseAllowlistEntry(source, lineNo, scanner.Text())
		if err != nil {
			return err
		}
		if skip {
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

func parseAllowlistEntry(source string, lineNo int, raw string) (*allowlistEntry, bool, error) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, true, nil
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if line == "" {
		return nil, true, nil
	}
	if strings.Contains(line, "/") {
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, false, fmt.Errorf("ungueltiger Allowlist-Eintrag in %s Zeile %d: %q", source, lineNo, raw)
		}
		return &allowlistEntry{prefix: prefix.Masked()}, false, nil
	}

	addr, err := netip.ParseAddr(line)
	if err != nil {
		return nil, false, fmt.Errorf("ungueltiger Allowlist-Eintrag in %s Zeile %d: %q", source, lineNo, raw)
	}
	return &allowlistEntry{addr: addr}, false, nil
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

	client, err := bb.newOutboundHTTPClient(kind, rawURL, false, 30*time.Second)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, redactOutboundError(kind, err)
	}
	defer func() { _ = resp.Body.Close() }()

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
