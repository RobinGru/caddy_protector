package caddyprotector

import (
	"context"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

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

// Cleanup beendet alle Hintergrund-Refreshes und gibt die Country-Datenbank frei.
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
	bb.resetVerifyRateLimits()
	return nil
}
