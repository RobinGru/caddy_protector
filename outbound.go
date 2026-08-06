package caddyprotector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const maxOutboundRedirects = 3

type outboundPolicy struct {
	kind            string
	origin          *url.URL
	capVerification bool
}

type redirectRejection struct {
	kind   string
	reason string
}

func (e *redirectRejection) Error() string {
	return e.kind + " redirect rejected: " + e.reason
}

func (bb *CaddyProtector) newOutboundHTTPClient(kind, rawURL string, capVerification bool, timeout time.Duration) (*http.Client, error) {
	origin, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%s_url could not be parsed", kind)
	}
	policy := outboundPolicy{kind: kind, origin: origin, capVerification: capVerification}
	if err := policy.validateInitialURL(); err != nil {
		return nil, err
	}

	transport := bb.testOutboundTransport
	if transport == nil {
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("%s outbound transport is unavailable", kind)
		}
		transport = defaultTransport.Clone()
		transport.(*http.Transport).DialContext = policy.dialContext
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxOutboundRedirects {
				return &redirectRejection{kind: kind, reason: fmt.Sprintf("redirect limit of %d exceeded", maxOutboundRedirects)}
			}
			return policy.validateRedirectURL(req.URL)
		},
	}, nil
}

func (p outboundPolicy) validateInitialURL() error {
	return p.validateURL(p.origin, true)
}

func (p outboundPolicy) validateRedirectURL(target *url.URL) error {
	if p.capVerification {
		if p.origin.Scheme == "https" && target.Scheme != "https" {
			return &redirectRejection{kind: p.kind, reason: "HTTPS redirect to HTTP is not allowed"}
		}
		if !sameOrigin(p.origin, target) {
			return &redirectRejection{kind: p.kind, reason: "cross-origin redirect is not allowed"}
		}
	}
	if err := p.validateURL(target, false); err != nil {
		return &redirectRejection{kind: p.kind, reason: err.Error()}
	}
	return nil
}

func (p outboundPolicy) validateURL(target *url.URL, initial bool) error {
	if target == nil || target.Scheme == "" || target.Host == "" {
		return fmt.Errorf("redirect target is not an absolute URL")
	}

	isOriginalLocalOrigin := p.origin.Scheme == "http" && isLoopbackHost(p.origin.Hostname()) && sameOrigin(p.origin, target)
	switch target.Scheme {
	case "https":
		if err := validateLiteralPublicAddress(target.Hostname()); err != nil {
			return err
		}
	case "http":
		if !isOriginalLocalOrigin {
			return fmt.Errorf("redirect target must use HTTPS")
		}
	default:
		return fmt.Errorf("redirect target must use HTTP(S)")
	}

	if initial && target.Scheme == "http" && !isOriginalLocalOrigin {
		return fmt.Errorf("configured URL must use HTTPS unless it is a loopback development origin")
	}
	return nil
}

func (p outboundPolicy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	allowLoopback := p.origin.Scheme == "http" && isLoopbackHost(p.origin.Hostname())
	for _, address := range addresses {
		if allowLoopback && address.IsLoopback() {
			continue
		}
		if !isPublicAddress(address) {
			return nil, fmt.Errorf("%s destination resolves to a non-public address", p.kind)
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("%s destination did not resolve to an address", p.kind)
	}

	return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
}

func validateLiteralPublicAddress(host string) error {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	if !isPublicAddress(address) {
		return fmt.Errorf("redirect target uses a non-public address")
	}
	return nil
}

func isPublicAddress(address netip.Addr) bool {
	return address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func redactOutboundError(kind string, err error) error {
	var rejected *redirectRejection
	if errors.As(err, &rejected) {
		return fmt.Errorf("%s redirect rejected: %s", kind, rejected.reason)
	}
	return fmt.Errorf("%s outbound request failed", kind)
}
