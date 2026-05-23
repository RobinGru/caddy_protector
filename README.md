[Deutsch](README.de.md)

# Caddy Protector

`caddy_protector` is an HTTP middleware module for Caddy. It protects upstreams with a browser-side proof-of-work challenge and only allows clients through for a configurable period after successful verification.

Access is granted via a signed `HttpOnly` cookie. The challenge token and cookie are protected server-side using a BLAKE3 keyed MAC; the secret never leaves the server.

Important: this module is a hurdle for bots, scrapers, and simple abuse, but it is not a replacement for authentication, authorization, rate limiting, or a WAF.

## How It Works

The request flow is:

1. `POST` requests to `verify_path` are always handled internally and are never passed to the upstream.
2. Simple request rules for obvious scanner targets and coarse exploit indicators are evaluated before everything else.
3. Blacklist entries are dropped immediately; the connection is closed without a regular HTTP response.
4. Allowlist entries pass through the middleware directly.
5. If `complexity` resolves to `0` for a request, the challenge is disabled for that request.
6. Requests with a valid access cookie are allowed through until `allow_for` expires.
7. Other clients receive a challenge page with a signed challenge token and browser bundle.
8. The browser extracts the seed from the challenge token and searches for a `nonce` such that `BLAKE3(seed || nonce)` has enough leading zero bits.
9. The solution is sent as JSON with `challengeToken` and `nonce` to `verify_path`.
10. The server first validates the token MAC and token lifetime, then validates the PoW solution.
11. On success, the server sets a signed `HttpOnly` cookie for `allow_for` minutes.

## Features

- signed challenge tokens
- signed access cookies
- stateless request filters for obvious scanner and exploit patterns
- configurable difficulty via static value or Caddy placeholder
- allowlist and blacklist via inline IP, file, or URL
- country filters via GeoIP MMDB with whitelist and blacklist rules
- periodic refresh for file and URL sources
- embedded challenge page including a locally built browser bundle
- default CSP header for the challenge page

## Installation

The module is intended for a custom Caddy build, for example with `xcaddy`:

```bash
xcaddy build --with github.com/RobinGru/caddy_protector
```

Alternatively, the module can be included in an existing custom Caddy build.

## Configuration

### Directives

| Directive | Description | Default |
| --- | --- | --- |
| `complexity` | Number of leading zero bits required in `BLAKE3(seed \|\| nonce)`. Also supports placeholders such as `{vars.caddy_protector_complexity}`. `0` disables the challenge for the request. | `18` |
| `valid_for` | Lifetime of an open challenge in minutes. | `120` |
| `allow_for` | Access duration for successfully verified clients in minutes. | `1800` |
| `secret` | Secret used to derive the BLAKE3 MAC keys. Alternative to `secret_file`. | - |
| `secret_file` | File containing the secret used to derive the BLAKE3 MAC keys. Alternative to `secret`. | - |
| `cookie_name` | Name of the access cookie. | `caddy_protector` |
| `cookie_path` | Path attribute of the access cookie. | `/` |
| `cookie_domain` | Optional domain attribute of the access cookie. | - |
| `cookie_secure` | Sets the `Secure` flag on the access cookie. | `true` |
| `cookie_http_only` | Sets the `HttpOnly` flag on the access cookie. | `true` |
| `cookie_same_site` | `Lax`, `Strict`, or `None` for the access cookie. | `Lax` |
| `built_in_rules` | Enables simple built-in rules for obvious scanner targets and coarse exploit indicators. | `true` |
| `aggressive_built_in_rules` | Enables broader built-in rules with a higher false-positive risk, for example for `/graphql`, `/api/v4`, or `/wp-content`. | `false` |
| `verify_path` | Internal `POST` endpoint for verification. | `/__caddy_protector/verify` |
| `deny_path_prefix` | Blocks requests with a matching path prefix. Case-insensitive. Can be specified multiple times. | - |
| `deny_query_substring` | Blocks requests with a matching query substring. Checks both the raw query and a URL-decoded variant. Case-insensitive. Can be specified multiple times. | - |
| `deny_header_substring` | Blocks requests if a header value contains a substring. Syntax: `<header-name> <value>`. Case-insensitive. Can be specified multiple times. | - |
| `whitelist_ip` | Adds a single IP or CIDR prefix to the allowlist. Can be specified multiple times. | - |
| `whitelist_file` | Loads additional allowlist entries from a file. | - |
| `whitelist_url` | Loads additional allowlist entries from a URL. | - |
| `whitelist_refresh` | Periodically refreshes file and URL allowlist sources in minutes. | disabled |
| `whitelist_country` | Only allows requests from the specified ISO-3166-1-alpha-2 countries to continue into the normal protection logic. Multiple codes per directive are allowed. | - |
| `blacklist_ip` | Adds a single IP or CIDR prefix to the blacklist. Can be specified multiple times. | - |
| `blacklist_file` | Loads additional blacklist entries from a file. | - |
| `blacklist_url` | Loads additional blacklist entries from a URL. | - |
| `blacklist_refresh` | Periodically refreshes file and URL blacklist sources in minutes. | disabled |
| `blacklist_country` | Immediately blocks requests from the specified ISO-3166-1-alpha-2 countries. Multiple codes per directive are allowed. | - |
| `country_url` | Loads a MaxMind MMDB for country lookups. | - |
| `country_url_refresh` | Periodically refreshes the MMDB in minutes. | disabled |
| `template` | Path to a custom HTML template. | built-in template |
| `disable_csp_header` | Disables the CSP header set by the middleware. | disabled |

### Important Rules

- Time values are specified as positive whole minutes, for example `120` or `120m`.
- `verify_path` must start with `/`.
- `complexity` must be between `0` and `256`.
- Exactly one of `secret` or `secret_file` must be set.
- `cookie_path` must start with `/`.
- `cookie_same_site` must be `Lax`, `Strict`, or `None`.
- `built_in_rules` and `aggressive_built_in_rules` accept `true` or `false`.
- `deny_path_prefix`, `deny_query_substring`, and `deny_header_substring` reject empty values.
- `deny_header_substring` requires exactly two arguments: header name and substring.
- Substrings with spaces must be quoted in the Caddyfile, for example `deny_query_substring "union select"`.
- `whitelist_country` and `blacklist_country` expect ISO-3166-1-alpha-2 codes such as `DE` or `RU`.
- If country rules are used, `country_url` must be set.

### Simple Request Rules

The request rules are intentionally coarse and cheap. They are meant to reject obvious scanner targets and primitive exploit strings early. They are not a full WAF and not a replacement for CRS.

If `built_in_rules true` is enabled, additional built-in heuristics are loaded. The default list stays focused on relatively clear scanner targets and exploit indicators:

- path prefixes such as `/.git`, `/.env`, `/wp-admin`, `/phpmyadmin`, `/cgi-bin`, `/manager/html`, `/vendor/phpunit`, or `/h2-console`
- query indicators such as `../`, `%2e%2e%2f`, `<script`, `union select`, `${jndi:`, `or 1=1`, `/etc/passwd`, `cmd.exe`, `php://`, or `gopher://`
- header indicators such as `User-Agent: sqlmap`, `nuclei`, `nikto`, `gobuster`, or rewrite headers containing `../`

`aggressive_built_in_rules true` adds broader path and query matches such as `/graphql`, `/api/v4`, `/wp-content`, or `exec(`. That can make sense for pure public websites, but it should be tested deliberately for APIs, WordPress frontends, or admin surfaces.

Matches are treated like the IP blacklist: the request is silently dropped before challenge, cookie, allowlist, or upstream handling.

### Allowlist and Blacklist

Accepted formats:

- single IPv4 address such as `1.2.3.4`
- single IPv6 address such as `2001:db8::1`
- IPv4 CIDR such as `1.2.3.0/24`
- IPv6 CIDR such as `2001:db8::/32`
- comment lines starting with `#`
- inline comments such as `66.249.64.0/19 # Googlebot`

Behavior:

- Allowlist entries bypass the challenge completely.
- Blacklist entries are checked before allowlist and challenge.
- Blacklisted clients intentionally do not receive a normal HTTP status code.
- The internal `verify_path` always remains internal, even for allowlisted or blacklisted clients.
- If file or URL sources cannot be read or parsed during startup, initialization fails.
- If a later refresh fails, the last valid list remains active.
- URL sources are only loaded via `http` or `https` and have internal size limits so broken or compromised sources cannot consume unbounded memory.

## Example

```caddyfile
example.com {
  encode zstd gzip

  @private {
    remote_ip private_ranges
  }

  vars caddy_protector_complexity 18
  vars @private caddy_protector_complexity 0

  caddy_protector {
    complexity {vars.caddy_protector_complexity}
    valid_for 120
    allow_for 1800
    secret please-change-me
    cookie_name caddy_protector
    cookie_secure true
    cookie_http_only true
    cookie_same_site Lax
    built_in_rules true
    aggressive_built_in_rules false
    verify_path /__caddy_protector/verify

    deny_path_prefix /internal/debug
    deny_query_substring "union select"
    deny_header_substring User-Agent sqlmap

    whitelist_ip 66.249.64.0/19
    whitelist_file /etc/caddy/goodbots.ips
    whitelist_url https://raw.githubusercontent.com/AnTheMaker/GoodBots/main/all.ips
    whitelist_refresh 720
    whitelist_country DE AT NL

    blacklist_ip 203.0.113.0/24
    blacklist_url https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/ip_blacklist.txt
    blacklist_refresh 60
    blacklist_country RU CN

    country_url https://git.io/GeoLite2-Country.mmdb
    country_url_refresh 2880
  }

  reverse_proxy 127.0.0.1:8081
}
```

Example for `/etc/caddy/goodbots.ips`:

```text
# trusted crawlers
66.249.64.0/19
157.55.39.0/24
2001:db8::/32
```

## Templates and CSP

The built-in challenge page uses inline styles and embedded JavaScript with a per-response nonce. By default, the middleware sets this CSP header:

```text
default-src 'none'; script-src 'nonce-<nonce>'; style-src 'nonce-<nonce>'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none';
```

If a custom template is used, it should process these values:

- `.Complexity`
- `.VerifyPath`
- `.ChallengeJS`
- `.ConfigJSON`
- `.CSPNonce`

`disable_csp_header` should only be used if an equivalent CSP is set elsewhere.

## Cookies and Proxies

CaddyProtector sets its own signed access cookie. Anyone with a valid cookie is allowed through until it expires. `cookie_secure true` should therefore only be used over HTTPS and should practically always remain enabled.

The challenge token and access cookie are protected server-side with a BLAKE3 keyed MAC. The browser never knows the secret.

When running behind reverse proxies, load balancers, or CDNs, it is still important that Caddy only trusts real client IPs from trusted proxy headers. That affects allowlist, blacklist, and country rules.

## Browser Bundle

The browser challenge source code lives under `tools/challenge-src`. After changes to `tools/challenge-src/src/challenge.js`, the bundle must be rebuilt:

```bash
cd tools/challenge-src
npm install
npm run build
```

The generated `dist/challenge.bundle.js` is embedded into the module via `go:embed`; no CDN is required at runtime.

## Development

Recommended checks:

```bash
go test ./...
go test -race ./...
go vet ./...
cd tools/challenge-src && npm ci && npm test && npm run build
```

Notes:

- `go test -race ./...` requires `CGO` and a suitable C compiler.
- In restrictive environments, `GOCACHE`, `GOPATH`, and `GOMODCACHE` should point to writable paths.
- For additional security checks, `govulncheck ./...` is a good fit for CI.

## License

The full license text is available in [LICENSE](LICENSE).
