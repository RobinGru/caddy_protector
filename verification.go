package caddyprotector

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zeebo/blake3"
)

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
	// Cookie security attributes are intentionally configurable by the Caddy administrator.
	// #nosec G124
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
		return fmt.Errorf("payload konnte nicht dekodiert werden: %w", err)
	}
	if err := json.Unmarshal(payloadJSON, out); err != nil {
		return fmt.Errorf("payload konnte nicht dekodiert werden: %w", err)
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
