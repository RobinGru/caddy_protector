package caddyprotector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

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

	now := bb.now()
	stateClaims, err := bb.verifyReturnState(req.State, now)
	if err != nil {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Return-State ist ungültig", zap.Error(err))
		http.Error(w, "challenge abgelaufen", http.StatusForbidden)
		return nil
	}

	clientAddr, err := netip.ParseAddr(clientIP)
	if err != nil {
		logger.Warn("CaddyProtector-Verify fehlgeschlagen: Client-IP ist ungültig")
		http.Error(w, "ungueltige client ip", http.StatusBadRequest)
		return nil
	}
	if allowed, retryAfter := bb.allowVerifyAttempt(clientAddr.Unmap(), now); !allowed {
		logger.Warn("CaddyProtector-Verify lokal begrenzt", zap.Duration("retry_after", retryAfter))
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
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

func (bb *CaddyProtector) now() time.Time {
	if bb.testNow != nil {
		return bb.testNow()
	}
	return time.Now()
}

func (bb *CaddyProtector) resetVerifyRateLimits() {
	bb.verifyRateLimitMu.Lock()
	defer bb.verifyRateLimitMu.Unlock()
	bb.verifyRateLimits = make(map[netip.Addr]verifyRateLimitEntry)
}

func (bb *CaddyProtector) allowVerifyAttempt(clientAddr netip.Addr, now time.Time) (bool, time.Duration) {
	bb.verifyRateLimitMu.Lock()
	defer bb.verifyRateLimitMu.Unlock()

	if bb.verifyRateLimits == nil {
		bb.verifyRateLimits = make(map[netip.Addr]verifyRateLimitEntry)
	}
	for addr, entry := range bb.verifyRateLimits {
		if now.Sub(entry.lastRefill) >= verifyRateLimitEntryLifetime {
			delete(bb.verifyRateLimits, addr)
		}
	}

	entry, exists := bb.verifyRateLimits[clientAddr]
	if !exists {
		if len(bb.verifyRateLimits) >= maxVerifyRateLimitEntries {
			return false, verifyRateLimitRefill
		}
		entry = verifyRateLimitEntry{tokens: verifyRateLimitBurst, lastRefill: now}
	}

	if elapsed := now.Sub(entry.lastRefill); elapsed >= verifyRateLimitRefill {
		refills := int(elapsed / verifyRateLimitRefill)
		entry.tokens = min(verifyRateLimitBurst, entry.tokens+refills)
		entry.lastRefill = entry.lastRefill.Add(time.Duration(refills) * verifyRateLimitRefill)
	}
	if entry.tokens == 0 {
		return false, entry.lastRefill.Add(verifyRateLimitRefill).Sub(now)
	}

	entry.tokens--
	bb.verifyRateLimits[clientAddr] = entry
	return true, 0
}

func retryAfterSeconds(retryAfter time.Duration) int {
	if retryAfter <= 0 {
		return 1
	}
	return int((retryAfter + time.Second - 1) / time.Second)
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

	client, err := bb.newOutboundHTTPClient("siteverify", bb.capSiteVerifyURL(), true, 15*time.Second)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, redactOutboundError("siteverify", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("siteverify lieferte HTTP %d", resp.StatusCode)
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result); err != nil {
		return false, fmt.Errorf("siteverify response konnte nicht gelesen werden: %w", err)
	}
	return result.Success, nil
}
