# CI-Verifikationsrichtlinie

Jeder Pull Request muss folgende Checks bestehen:

- `Lint (golangci-lint)`
- `Vet`
- `Test (ubuntu, 1.26.5)` mit Race Detector und Coverage
- `Integration (Caddy)`
- `Build`
- `Mod tidy check`
- `govulncheck`

Repository-Maintainer müssen diese Checks als Required Checks für `main` konfigurieren. Alle normalen CI-Jobs verwenden ausschließlich `contents: read` und erhalten keine Repository-Secrets.

## Coverage

Die Race-fähige Testsuite läuft einmal pro Go-Version und erzeugt zugleich das Coverage-Profil. Die absolute Mindestabdeckung beträgt 70%. Dieser bewusst leichte Grenzwert toleriert kleine Schwankungen, schlägt aber bei einem Ergebnis unter 70% fehl. Das Profil wird nur hochgeladen, wenn es tatsächlich erzeugt wurde, damit ein Testfehler nicht durch einen fehlenden Artefaktfehler verdeckt wird.

## Vulnerability-Prüfung

`govulncheck` ist auf `v1.6.0` gepinnt. Ein erkannter Ausfall des externen Vulnerability-Service wird einmal wiederholt. Bleibt derselbe Infrastrukturfehler bestehen, meldet CI eine sichtbare Warnung und blockiert den Merge nicht. Eine erkannte Schwachstelle oder ein nicht klassifizierter Fehler bleibt blockierend.

## Ausführungszeitpunkt

Die vollständige Check-Matrix einschließlich der Caddy-Integration läuft für jeden Pull Request, jeden Push auf `main` und jeden Release-Tag mit Präfix `v`.
