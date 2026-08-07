package caddyprotector

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zeebo/blake3"
	"go.uber.org/zap"
)

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
		// configJSON is produced by encoding/json, which escapes HTML-sensitive characters.
		"ConfigJSON": template.JS(string(configJSON)), // #nosec G203 -- safe JSON for an inline script.
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
		// cspNonce is a server-generated base64 value with no HTML-significant characters.
		data["CSPNonce"] = template.HTMLAttr(cspNonce) // #nosec G203 -- trusted CSP nonce.
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
		cspSelfSource,
		capOrigin,
		jsDelivrOrigin,
	}, " ")
	workerSrc := strings.Join([]string{
		cspSelfSource,
		"blob:",
		capOrigin,
		jsDelivrOrigin,
	}, " ")
	frameSrc := strings.Join([]string{
		cspSelfSource,
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
