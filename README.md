# Caddy Protector

`caddy_protector` ist ein HTTP-Middleware-Modul für Caddy. Es schützt Upstreams mit einer browserseitigen Proof-of-Work-Challenge und gibt Clients erst nach erfolgreicher Verifikation für eine konfigurierbare Zeit frei.

Die aktuelle Implementierung arbeitet ohne Cookies:

- kein Setzen oder Lesen von Cookies
- kein HMAC-Flow
- kein Client-Secret im Browser
- serverseitige Freigabe auf Basis von `Client-IP + User-Agent`

Wichtig: Das Modul ist eine Hürde gegen Bots, Scraper und einfachen Abuse, aber kein Ersatz für Authentifizierung, Autorisierung, Rate Limiting oder eine WAF.

## Funktionsweise

Der Ablauf pro Request ist:

1. Die Middleware ermittelt den Client-Schlüssel aus IP-Adresse und `User-Agent`.
2. `POST`-Requests auf `verify_path` werden immer intern verarbeitet und nie an den Upstream weitergereicht.
3. Blacklist-Einträge werden sofort verworfen; die Verbindung wird ohne reguläre HTTP-Antwort beendet.
4. Allowlist-Einträge passieren die Middleware direkt.
5. Wenn `complexity` für den Request auf `0` aufgelöst wird, ist die Challenge deaktiviert.
6. Bereits freigegebene Clients dürfen bis zum Ablauf von `allow_for` passieren.
7. Andere Clients erhalten eine Challenge-Seite mit Seed und Browser-Bundle.
8. Der Browser sucht einen `nonce`, für den `BLAKE3(seed || nonce)` genügend führende Null-Bits hat.
9. Die Lösung wird als JSON an `verify_path` gesendet.
10. Bei Erfolg wird die Pending-Challenge entfernt und der Client für `allow_for` Sekunden freigegeben.

## Features

- serverseitig verwaltete Pending-Challenges
- serverseitige Freigabeliste mit Ablaufzeit
- konfigurierbare Schwierigkeit über statischen Wert oder Caddy-Placeholder
- temporäre Sperre bei zu vielen Challenge-Abrufen
- globale Obergrenze für offene Challenges
- Allowlist und Blacklist per Inline-IP, Datei oder URL
- Country-Filter per GeoIP-MMDB mit Whitelist- und Blacklist-Regeln
- periodischer Refresh von Datei- und URL-Quellen
- eingebettete Challenge-Seite inklusive lokal gebautem Browser-Bundle
- standardmäßig gesetzter CSP-Header für die Challenge-Seite

## Installation

Das Modul ist für einen Custom-Caddy-Build gedacht, zum Beispiel mit `xcaddy`:

```bash
xcaddy build --with github.com/RobinGru/caddy_protector
```

Alternativ kann das Modul in einen bestehenden eigenen Caddy-Build eingebunden werden.

## Konfiguration

### Direktiven

| Direktive | Beschreibung | Standard |
| --- | --- | --- |
| `complexity` | Anzahl führender Null-Bits in `BLAKE3(seed \|\| nonce)`. Unterstützt auch Placeholders wie `{vars.caddy_protector_complexity}`. `0` deaktiviert die Challenge für den Request. | `16` |
| `valid_for` | Gültigkeitsdauer einer offenen Challenge in Sekunden. | `120` |
| `allow_for` | Freigabedauer für erfolgreich verifizierte Clients in Sekunden. | `1800` |
| `max_challenge_attempts` | Anzahl Challenge-Seitenabrufe innerhalb von `block_for`, bevor ein Client mit `429` blockiert wird. | `10` |
| `block_for` | Sperrdauer nach zu vielen Challenge-Abrufen in Sekunden. | `1800` |
| `max_pending_challenges` | Globale Obergrenze für serverseitig gespeicherte offene Challenges. | `100000` |
| `verify_path` | Interner `POST`-Endpunkt für die Verifikation. | `/__caddy_protector/verify` |
| `whitelist_ip` | Fügt eine einzelne IP oder ein CIDR-Präfix zur Allowlist hinzu. Kann mehrfach angegeben werden. | - |
| `whitelist_file` | Lädt zusätzliche Allowlist-Einträge aus einer Datei. | - |
| `whitelist_url` | Lädt zusätzliche Allowlist-Einträge von einer URL. | - |
| `whitelist_refresh` | Aktualisiert Datei- und URL-Quellen der Allowlist periodisch in Sekunden. | deaktiviert |
| `whitelist_country` | Erlaubt nur Requests aus den angegebenen ISO-3166-1-Alpha-2-Ländern, in die bestehende Schutzlogik weiterzulaufen. Mehrere Codes pro Direktive sind erlaubt. | - |
| `blacklist_ip` | Fügt eine einzelne IP oder ein CIDR-Präfix zur Blacklist hinzu. Kann mehrfach angegeben werden. | - |
| `blacklist_file` | Lädt zusätzliche Blacklist-Einträge aus einer Datei. | - |
| `blacklist_url` | Lädt zusätzliche Blacklist-Einträge von einer URL. | - |
| `blacklist_refresh` | Aktualisiert Datei- und URL-Quellen der Blacklist periodisch in Sekunden. | deaktiviert |
| `blacklist_country` | Sperrt Requests aus den angegebenen ISO-3166-1-Alpha-2-Ländern sofort. Mehrere Codes pro Direktive sind erlaubt. | - |
| `country_url` | Lädt eine MaxMind-MMDB für Country-Lookups. | - |
| `country_url_refresh` | Aktualisiert die MMDB periodisch in Sekunden. | deaktiviert |
| `csp_script_src` | Fügt eine Quelle zur `script-src`-CSP-Direktive hinzu, z.B. für Cloudflare Rocket Loader. Kann mehrfach angegeben werden. | - |
| `template` | Pfad zu einem eigenen HTML-Template. | eingebautes Template |
| `disable_csp_header` | Deaktiviert den von der Middleware gesetzten CSP-Header. | deaktiviert |

### Wichtige Regeln

- Zeitwerte werden als positive ganze Sekunden angegeben, zum Beispiel `120` oder `120s`.
- `verify_path` muss mit `/` beginnen.
- `complexity` darf zwischen `0` und `256` liegen.
- `whitelist_country` und `blacklist_country` erwarten ISO-3166-1-Alpha-2-Codes wie `DE` oder `RU`.
- Wenn Country-Regeln verwendet werden, muss `country_url` gesetzt sein.
- `max_challenge_attempts` und `max_pending_challenges` müssen mindestens `1` sein.
- Alte Cookie-bezogene Optionen wie `secret`, `seed_cookie_name`, `solution_cookie_name` und `mac_cookie_name` werden nicht unterstützt.

### Allowlist und Blacklist

Akzeptierte Formate:

- einzelne IPv4-Adresse wie `1.2.3.4`
- einzelne IPv6-Adresse wie `2001:db8::1`
- IPv4-CIDR wie `1.2.3.0/24`
- IPv6-CIDR wie `2001:db8::/32`
- Kommentarzeilen mit `#`
- Inline-Kommentare wie `66.249.64.0/19 # Googlebot`

Verhalten:

- Allowlist-Einträge umgehen die Challenge vollständig.
- Blacklist-Einträge werden vor Allowlist und Challenge geprüft.
- Blacklisted Clients erhalten bewusst keinen normalen HTTP-Statuscode.
- Der interne `verify_path` bleibt immer intern, auch für allowlisted oder blacklisted Clients.
- Wenn Datei- oder URL-Quellen beim Start nicht lesbar oder nicht parsebar sind, schlägt die Initialisierung fehl.
- Wenn ein späterer Refresh fehlschlägt, bleibt die letzte gültige Liste aktiv.

## Beispiel

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
    max_challenge_attempts 10
    max_pending_challenges 100000
    block_for 1800
    verify_path /__caddy_protector/verify

    whitelist_ip 66.249.64.0/19
    whitelist_file /etc/caddy/goodbots.ips
    whitelist_url https://raw.githubusercontent.com/AnTheMaker/GoodBots/main/all.ips
    whitelist_refresh 43200
    whitelist_country DE AT NL

    blacklist_ip 203.0.113.0/24
    blacklist_url https://raw.githubusercontent.com/fabriziosalmi/caddy-waf/refs/heads/main/ip_blacklist.txt
    blacklist_refresh 3600
    blacklist_country RU CN

    country_url https://git.io/GeoLite2-Country.mmdb
    country_url_refresh 172800
  }

  reverse_proxy 127.0.0.1:8081
}
```

Beispiel für `/etc/caddy/goodbots.ips`:

```text
# trusted crawlers
66.249.64.0/19
157.55.39.0/24
2001:db8::/32
```

## Templates und CSP

Die eingebaute Challenge-Seite nutzt Inline-Styles und eingebettetes JavaScript mit einer pro Response erzeugten Nonce. Standardmäßig setzt die Middleware diesen CSP-Header:

```text
default-src 'none'; script-src 'nonce-<nonce>'; style-src 'nonce-<nonce>'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; object-src 'none';
```

Wenn zusätzliche Skript-Quellen über `csp_script_src` konfiguriert wurden, werden diese an die `script-src`-Direktive angehängt, z.B.:

```text
script-src 'nonce-<nonce>' https://5wn.de
```

Wenn ein eigenes Template verwendet wird, sollte es diese Daten verarbeiten:

- `.Seed`
- `.Complexity`
- `.VerifyPath`
- `.ChallengeJS`
- `.ConfigJSON`
- `.CSPNonce`

`disable_csp_header` sollte nur verwendet werden, wenn an anderer Stelle eine gleichwertige CSP gesetzt wird.

## Browser-Bundle

Der Quellcode für die Browser-Challenge liegt unter `tools/challenge-src`. Nach Änderungen an `tools/challenge-src/src/challenge.js` muss das Bundle neu gebaut werden:

```bash
cd tools/challenge-src
npm install
npm run build
```

Das erzeugte `dist/challenge.bundle.js` wird per `go:embed` in das Modul eingebettet; zur Laufzeit ist kein CDN erforderlich.

## Entwicklung

Empfohlene Prüfungen:

```bash
go test ./...
go test -race ./...
go vet ./...
cd tools/challenge-src && npm ci && npm test && npm run build
```

Hinweise:

- `go test -race ./...` benötigt `CGO` und einen passenden C-Compiler.
- In restriktiven Umgebungen sollten `GOCACHE`, `GOPATH` und `GOMODCACHE` auf beschreibbare Pfade zeigen.
- Für zusätzliche Sicherheitsprüfungen bietet sich in CI `govulncheck ./...` an.

## Lizenz

Der vollständige Lizenztext steht in [LICENSE](LICENSE).