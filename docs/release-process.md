# Release-Prozess

## Kompatibilität

Produktive Releases unterstützen:

- Go `>= 1.26.5`
- Caddy `>= v2.11.4, < v3.0.0`

Der erste stabile Release ist `v1.0.0`. Releases bestehen ausschließlich aus Quellcode: Es werden ein Git-Tag und ein GitHub Release veröffentlicht, aber keine vorgebauten Caddy-Binaries oder projektspezifischen Prüfsummen.

## Installation

Installiere einen Produktiv-Release mit einer exakten Modulversion:

```sh
xcaddy build --with github.com/RobinGru/caddy_protector@v1.0.0
```

Ein Build aus `main` ist ausschließlich eine instabile Entwicklungsoption:

```sh
xcaddy build --with github.com/RobinGru/caddy_protector@main
```

## Veröffentlichungs-Checkliste

1. Wähle einen semantischen Versions-Tag im Format `vMAJOR.MINOR.PATCH`.
2. Stelle sicher, dass die Zielrevision jeden erforderlichen CI-Job bestanden hat: Lint, Vet, Race-Tests, Coverage, den Caddy-Integrationstest, Build, Tidy-Prüfung und `govulncheck`.
3. Erstelle und pushe den Tag. Der CI-Workflow läuft erneut für Tags, die auf `v*` passen.
4. Warte auf einen erfolgreichen Tag-Workflow, bevor du den GitHub Release veröffentlichst.
5. Erstelle den GitHub Release aus genau diesem Tag und nutze `.github/RELEASE_TEMPLATE.md`.
6. Prüfe, dass der GitHub Release Tag, Zielrevision, unterstützte Go- und Caddy-Bereiche sowie notwendige Migrationsschritte ausweist.

## Versionierung und Release Notes

Verwende semantische Versionierung. Eine rückwärtsinkompatible Änderung an einer öffentlichen Go-API, einem JSON-Feld, einer Caddyfile-Direktive, einem Default oder dem Request-Verhalten benötigt das passende Major-Versionssignal. Nutze für jeden Release die Vorlage, um sicherheitsrelevante Änderungen, Konfigurationsänderungen, Verhaltensänderungen, Deprecations und Migrationen einzuordnen. Trage `Keine` ein, wenn eine Kategorie keine Einträge enthält.

## Rückzug oder Ablösung

Lösche keinen veröffentlichten Release-Tag. Markiere den betroffenen GitHub Release als zurückgezogen oder abgelöst, erläutere die Auswirkung und nenne die empfohlene Ersatzversion. Falls es keinen sicheren Ersatz gibt, halte dies ausdrücklich fest und beschreibe die Minderung oder den Rollback-Schritt.
