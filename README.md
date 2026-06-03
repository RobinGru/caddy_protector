[English](README.md)

# Caddy Protector

`caddy_protector` ist ein HTTP-Middleware-Modul für Caddy. Es schützt Upstreams mit einer Cap-basierten Browser-Verifikation und gibt Clients nach erfolgreicher Prüfung für eine konfigurierbare Zeit frei.

Die Freigabe erfolgt über ein signiertes `HttpOnly`-Cookie. Cap übernimmt die externe Browser-Verifikation, während `caddy_protector` weiterhin Request-Filter, Allowlists, Blacklists, Country-Regeln und das lokale Freigabe-Cookie verwaltet.

Cap musst du selbst hosten. Dieses Repository stellt keinen gehosteten Cap-Dienst bereit und muss gegen deine eigene Cap-Instanz konfiguriert werden.

Wichtig: Das Modul ist eine Hürde gegen Bots, Scraper und einfachen Abuse, aber kein Ersatz für Authentifizierung, Autorisierung, Rate Limiting oder eine WAF.

## Funktionsweise

Der Ablauf pro Request ist:

1. `POST`-Requests auf `verify_path` werden immer intern verarbeitet und nie an den Upstream weitergereicht.
2. Einfache Request-Regeln für offensichtliche Scanner-Ziele und grobe Exploit-Indikatoren werden vor allen weiteren Prüfungen ausgewertet.
3. Country-Regeln werden vor IP-Allowlist und Freigabe-Cookie ausgewertet.
4. Blacklist-Einträge werden sofort verworfen; die Verbindung wird ohne reguläre HTTP-Antwort beendet.
5. Allowlist-Einträge passieren die Middleware direkt.
6. Requests mit gültigem Freigabe-Cookie dürfen bis zum Ablauf von `allow_for` passieren.
7. Andere Clients erhalten eine nicht cachebare Challenge-Seite mit Cap-Widget.
8. Der Browser löst die Cap-Challenge gegen `cap_api_url` mit `cap_site_key`.
9. Das Widget sendet das erzeugte Token zusammen mit einem signierten Return-State an `verify_path`.
10. Der Server verifiziert das Token über `POST <cap_api_url>/<cap_site_key>/siteverify` mit `cap_secret_key`.
11. Bei Erfolg setzt der Server ein signiertes `HttpOnly`-Cookie für `allow_for` Minuten und liefert den ursprünglichen Zielpfad zurück.

## Features

- Cap-basierte Browser-Verifikation über `cap_api_url`, `cap_site_key` und `cap_secret_key`
- signierte lokale Freigabe-Cookies
- stateless Request-Filter für offensichtliche Scanner- und Exploit-Muster
- Allowlist und Blacklist per Inline-IP, Datei oder URL
- Country-Filter per GeoIP-MMDB mit Whitelist- und Blacklist-Regeln
- periodischer Refresh von Datei- und URL-Quellen
- eingebaute Challenge-Seite mit Cap-Widget
- standardmäßig gesetzter CSP-Header für die Challenge-Seite

## Installation

Das Modul ist für einen Custom-Caddy-Build gedacht, zum Beispiel mit `xcaddy`:

```bash
xcaddy build --with github.com/RobinGru/caddy_protector
```

## Konfiguration

### Direktiven

| Direktive | Beschreibung | Standard |
| --- | --- | --- |
| `allow_for` | Freigabedauer für erfolgreich verifizierte Clients in Minuten. | `1800` |
| `cap_api_url` | Öffentliche Basis-URL deiner Cap-Instanz, z. B. `https://cap.example.com`. | - |
| `cap_site_key` | Site-Key deiner Cap-Instanz. | - |
| `cap_secret_key` | Secret-Key für `/siteverify`. Daraus werden auch die lokalen MAC-Schlüssel für Cookie und Return-State abgeleitet. | - |
| `cookie_name` | Name des Freigabe-Cookies. | `caddy_protector` |
| `cookie_path` | Path-Attribut des Freigabe-Cookies. | `/` |
| `cookie_domain` | Optionales Domain-Attribut des Freigabe-Cookies. | - |
| `cookie_secure` | Setzt das `Secure`-Flag des Freigabe-Cookies. | `true` |
| `cookie_http_only` | Setzt das `HttpOnly`-Flag des Freigabe-Cookies. | `true` |
| `cookie_same_site` | `Lax`, `Strict` oder `None` für das Freigabe-Cookie. | `Lax` |
| `verify_path` | Interner `POST`-Endpunkt für die Verifikation. | `/__caddy_protector/verify` |
| `deny_path_prefix` | Sperrt Requests mit passendem Pfad-Präfix. Case-insensitive. Kann mehrfach angegeben werden. | - |
| `deny_query_substring` | Sperrt Requests mit passendem Query-Teilstring. Prüft Raw Query und eine URL-dekodierte Variante. Case-insensitive. Kann mehrfach angegeben werden. | - |
| `deny_header_substring` | Sperrt Requests, wenn ein Header-Wert einen Teilstring enthält. Syntax: `<header-name> <value>`. Case-insensitive. Kann mehrfach angegeben werden. | - |
| `whitelist_ip` | Fügt eine einzelne IP oder ein CIDR-Präfix zur Allowlist hinzu. Kann mehrfach angegeben werden. | - |
| `whitelist_file` | Lädt zusätzliche Allowlist-Einträge aus einer Datei. | - |
| `whitelist_url` | Lädt zusätzliche Allowlist-Einträge von einer URL. | - |
| `whitelist_refresh` | Aktualisiert Datei- und URL-Quellen der Allowlist periodisch in Minuten. | deaktiviert |
| `whitelist_country` | Erlaubt nur Requests aus den angegebenen ISO-3166-1-Alpha-2-Ländern, in die normale Schutzlogik weiterzulaufen. | - |
| `blacklist_ip` | Fügt eine einzelne IP oder ein CIDR-Präfix zur Blacklist hinzu. Kann mehrfach angegeben werden. | - |
| `blacklist_file` | Lädt zusätzliche Blacklist-Einträge aus einer Datei. | - |
| `blacklist_url` | Lädt zusätzliche Blacklist-Einträge von einer URL. | - |
| `blacklist_refresh` | Aktualisiert Datei- und URL-Quellen der Blacklist periodisch in Minuten. | deaktiviert |
| `blacklist_country` | Sperrt Requests aus den angegebenen ISO-3166-1-Alpha-2-Ländern sofort. | - |
| `country_url` | Lädt eine MaxMind-MMDB für Country-Lookups. | - |
| `country_url_refresh` | Aktualisiert die MMDB periodisch in Minuten. | deaktiviert |
| `template` | Pfad zu einem eigenen HTML-Template. | eingebautes Template |
| `disable_csp_header` | Deaktiviert den von der Middleware gesetzten CSP-Header. | deaktiviert |

### Wichtige Regeln

- Zeitwerte werden als positive ganze Minuten angegeben, zum Beispiel `120` oder `120m`.
- `verify_path` muss mit `/` beginnen.
- `cap_api_url` muss eine absolute URL sein und produktiv `https` verwenden. Reines `http` ist nur für `localhost` oder Loopback-Adressen in lokalen Dev-/Test-Setups erlaubt.
- `cap_site_key` und `cap_secret_key` dürfen nicht leer sein.
- `cookie_path` muss mit `/` beginnen.
- `cookie_same_site` muss `Lax`, `Strict` oder `None` sein.
- `deny_header_substring` erwartet genau zwei Argumente: Header-Name und Teilstring.
- Wenn Country-Regeln verwendet werden, muss `country_url` gesetzt sein.
- `whitelist_url`, `blacklist_url` und `country_url` sollten ebenfalls `https` verwenden. Reines `http` ist auch hier nur für `localhost` oder Loopback-Adressen in lokalen Dev-/Test-Setups erlaubt.
- Country-Regeln haben Vorrang vor IP-Allowlist und bereits gesetzten Freigabe-Cookies.

## Beispiel

```caddyfile
example.com {
  encode zstd gzip

  caddy_protector {
    allow_for 1800
    cap_api_url https://cap.example.com
    cap_site_key your-site-key
    cap_secret_key your-secret-key

    cookie_name caddy_protector
    cookie_secure true
    cookie_http_only true
    cookie_same_site Lax
    verify_path /__caddy_protector/verify

    deny_path_prefix /internal/debug
    deny_query_substring "union select"
    deny_header_substring User-Agent sqlmap

    whitelist_ip 66.249.64.0/19
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

## Templates und CSP

Die eingebaute Challenge-Seite nutzt Inline-Styles und JavaScript mit einer pro Response erzeugten Nonce und lädt das Cap-Widget über JSDelivr. Challenge- und Verify-Antworten werden zusätzlich mit `Cache-Control: no-store` ausgeliefert, damit keine abgelaufenen Return-States aus Caches wiederverwendet werden.

Wenn ein eigenes Template verwendet wird, sollte es diese Werte verarbeiten:

- `.VerifyPath`
- `.CapWidgetScript`
- `.CapAPIEndpoint`
- `.ConfigJSON`
- `.CSPNonce`

`disable_csp_header` sollte nur verwendet werden, wenn an anderer Stelle eine gleichwertige CSP gesetzt wird.

## Cookies und Proxies

`caddy_protector` setzt ein eigenes signiertes Freigabe-Cookie. Jeder mit gültigem Cookie wird bis zum Ablauf durchgelassen. `cookie_secure true` sollte daher nur über HTTPS genutzt werden und praktisch immer aktiv bleiben.

Wenn Caddy hinter Reverse Proxies, Load Balancern oder CDNs läuft, muss Caddy weiterhin nur echte Client-IPs aus vertrauenswürdigen Proxy-Headern akzeptieren. Das beeinflusst Allowlist, Blacklist und Country-Regeln.
