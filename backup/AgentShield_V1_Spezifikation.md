# AgentShield – Spezifikation für Version 1

Status: Implementierungsvorgabe  
Zielplattform primär: macOS  
Weitere Zielplattformen: Linux und Windows  
Arbeitsname: **AgentShield** (kann später geändert werden)

## 1. Auftrag an Junie

Implementiere eine lokal laufende Anwendung, die als kontrollierender Reverse Proxy zwischen einem Coding-Agent und externen LLM-Providern arbeitet. Sie muss ausgehende Requests und eingehende Responses untersuchen, sensible Inhalte anhand konfigurierbarer Regeln erkennen und abhängig von einer Policy erlauben, protokollieren, pseudonymisieren, zur manuellen Freigabe vorlegen oder blockieren.

Die Anwendung besteht aus:

- einem asynchronen Python-Backend,
- einem OpenAI- und Anthropic-kompatiblen LLM-Proxy,
- einer vom Backend bereitgestellten Browseroberfläche,
- einer lokalen Datenbank für Konfiguration und datensparsame Audit-Ereignisse,
- einer erweiterbaren Detector- und Policy-Engine.

Die Implementierung soll inkrementell in der unter Abschnitt 19 angegebenen Reihenfolge erfolgen. Nach jedem Meilenstein müssen alle bestehenden Tests weiterhin erfolgreich sein.

## 2. Produktziel

AgentShield soll für Entwickler sichtbar und kontrollierbar machen, welche Daten ein Coding-Agent an ein externes LLM überträgt. Die Anwendung soll insbesondere verhindern, dass Zugangsdaten, personenbezogene Daten oder projektspezifische vertrauliche Begriffe versehentlich an nicht freigegebene Provider gesendet werden.

Version 1 ist ein **kooperativer LLM-Reverse-Proxy**. Sie kontrolliert nur Requests, die über AgentShield geleitet werden. Sie behauptet nicht, sämtlichen Netzwerkverkehr eines Prozesses oder Rechners erzwingen zu können.

## 3. Abgrenzung von Version 1

### 3.1 Bestandteil von Version 1

- OpenAI Responses API
- OpenAI Chat Completions API, soweit mit vertretbarem Zusatzaufwand möglich
- Anthropic Messages API
- nicht-streamende und SSE-streamende Requests
- strukturierte Tool Calls und Tool Results innerhalb der Provider-Payloads
- Untersuchung von Requests und Responses
- Erkennung von Secrets, PII und projektspezifischen Begriffen
- Aktionen `ALLOW`, `WARN`, `REDACT`, `REQUIRE_APPROVAL` und `BLOCK`
- lokale manuelle Freigabe über die Browseroberfläche
- konsistente, bei geeigneten Datenklassen reversible Pseudonymisierung
- drei vordefinierte Sicherheitsprofile
- datensparsames Auditprotokoll
- Konfigurationshilfe für Codex und Claude Code
- Diagnose- und Rollback-Funktionen
- macOS-Unterstützung; plattformneutraler Code für Linux und Windows

### 3.2 Nicht Bestandteil von Version 1

- transparente TLS-Interception oder Installation einer eigenen Root-CA
- garantierte Unterbindung von direktem Netzwerkzugriff außerhalb des Proxys
- Manipulation der Betriebssystem-Firewall
- vollständiger Forward Proxy für beliebigen Internetverkehr
- vollständiger MCP-Proxy
- Sandbox oder Container-Isolation des Coding-Agents
- Tauri-Desktop-App, Menüleisten-App oder automatischer Updater
- Rust-Netzwerkkern
- Mehrbenutzerbetrieb, RBAC, SSO oder zentrale Teamverwaltung
- Cloud-Hosting
- PostgreSQL als notwendige Laufzeitabhängigkeit
- automatische semantische Klassifikation des gesamten Quellcodes durch ein LLM
- Unterstützung von Bildern, Audio und beliebigen Binärdateien

Nicht unterstützte binäre oder multimodale Inhalte müssen im strikten Profil blockiert und in den anderen Profilen deutlich gemeldet werden.

## 4. Sicherheitsmodell

### 4.1 Zu schützende Daten

- API-Keys und Personal Access Tokens
- Passwörter und Bearer Tokens
- private Schlüssel und Zugangsdaten
- personenbezogene Daten
- interne Projekt-, Kunden- und Produktnamen
- konfigurierbare Paket-, Klassen-, Tabellen- und Feldnamen
- andere durch projektspezifische Regeln definierte Inhalte

### 4.2 Vertrauensgrenzen

- Backend, lokale Datenbank und Betriebssystem-Schlüsselbund gelten als vertrauenswürdig.
- Coding-Agent, LLM-Provider, Webseiteninhalte und spätere MCP-Server gelten nicht automatisch als vertrauenswürdig.
- Das React-Frontend ist keine Sicherheitsgrenze. Alle Entscheidungen müssen im Backend durchgesetzt werden.
- Die Verbindung vom Proxy zum Provider muss mit normaler TLS-Zertifikatsprüfung erfolgen. Das Abschalten der Zertifikatsprüfung darf nicht angeboten werden.

### 4.3 Bekannte Grenzen

- Ein Agent kann AgentShield umgehen, wenn er direkten Netzwerkzugriff besitzt und nicht den konfigurierten Proxy verwendet.
- Automatische Detectoren können False Positives und False Negatives erzeugen.
- AgentShield stellt allein keine DSGVO-Konformität oder vollständige Verhinderung von Datenabfluss sicher.
- Diese Grenzen sind in `THREAT_MODEL.md` und in der Benutzeroberfläche verständlich darzustellen.

## 5. Technologie-Stack

Verwende jeweils stabile, nicht als Preview gekennzeichnete Versionen und sperre die konkret aufgelösten Versionen in Lockfiles.

### 5.1 Backend

- Python 3.14
- FastAPI
- Pydantic und Pydantic Settings
- Uvicorn
- HTTPX für asynchrone Provider-Kommunikation
- SQLAlchemy 2
- Alembic
- SQLite mit WAL-Modus
- Microsoft Presidio als PII-Detector
- `keyring` für den Zugriff auf native Schlüsselbünde
- strukturierte JSON-Logs
- OpenTelemetry-Schnittstellen, aber keine externe Telemetrie als Pflicht
- `uv` für Python-, Dependency- und Workspace-Verwaltung
- Ruff für Formatierung und Linting
- Pyright im Strict Mode
- pytest, pytest-asyncio und HTTPX TestClient/ASGITransport

### 5.2 Frontend

- React 19
- TypeScript mit `strict: true`
- Vite
- React Router oder TanStack Router
- TanStack Query
- TanStack Table
- Tailwind CSS
- shadcn/ui beziehungsweise Radix-basierte Komponenten
- Monaco Editor für Payload- und Diff-Anzeige
- Vitest und Testing Library
- Playwright für End-to-End-Tests
- pnpm mit Lockfile

### 5.3 API-Vertrag

- FastAPI erzeugt die kanonische OpenAPI-Spezifikation.
- Der TypeScript-Client wird aus der OpenAPI-Spezifikation generiert.
- Im Frontend dürfen keine handgeschriebenen Duplikate der Backend-DTOs gepflegt werden.

## 6. Repository-Struktur

Verwende ein Monorepo als modularen Monolithen:

```text
agent-shield/
├── backend/
│   ├── pyproject.toml
│   ├── uv.lock
│   ├── migrations/
│   ├── src/agentshield/
│   │   ├── api/
│   │   ├── proxy/
│   │   │   ├── openai/
│   │   │   └── anthropic/
│   │   ├── filtering/
│   │   │   ├── detectors/
│   │   │   ├── redaction/
│   │   │   └── models/
│   │   ├── policies/
│   │   ├── approvals/
│   │   ├── audit/
│   │   ├── integrations/
│   │   ├── persistence/
│   │   └── security/
│   └── tests/
├── frontend/
│   ├── package.json
│   ├── pnpm-lock.yaml
│   ├── src/
│   └── tests/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   └── adr/
├── scripts/
├── .github/workflows/
├── README.md
├── SECURITY.md
└── LICENSE (Lizenzentscheidung vor Veröffentlichung treffen)
```

Domänenlogik, Detectoren und Policy-Entscheidungen dürfen nicht von FastAPI-Klassen abhängig sein. Dadurch müssen sie separat testbar und später in andere Laufzeitumgebungen übertragbar sein.

## 7. Laufzeit und Bedienung

### 7.1 Entwicklungsmodus

- Backend und Vite-Entwicklungsserver dürfen getrennt laufen.
- CORS darf ausschließlich für den konkret konfigurierten lokalen Entwicklungs-Origin freigegeben werden.
- Provider-Schlüssel aus `.env` sind ausschließlich im Entwicklungsmodus erlaubt und müssen eine sichtbare Warnung erzeugen.

### 7.2 Produktionsmodus

- Das Backend stellt das gebaute React-Frontend unter demselben Origin bereit.
- Der Dienst bindet standardmäßig ausschließlich an `127.0.0.1`.
- Standardport ist `8765`; bei Kollision wird entweder mit verständlicher Fehlermeldung abgebrochen oder ein freier Port gewählt und angezeigt.
- CLI-Einstiegspunkte:

```bash
agentshield start
agentshield doctor
agentshield configure codex
agentshield configure claude-code
agentshield rollback codex
agentshield rollback claude-code
```

- `start` startet Backend und UI und kann optional den Standardbrowser öffnen.
- Der Start muss mehrfach aufgerufen werden können, ohne mehrere konkurrierende Instanzen zu erzeugen.

## 8. Lokale Authentifizierung und Secrets

- Beim ersten Start wird ein kryptografisch zufälliges lokales Admin-Token erzeugt.
- Management-API und Proxy-API verwenden getrennte lokale Tokens.
- Tokens dürfen nicht in URLs vorkommen.
- Der Browser verwendet für die Management-API eine sichere lokale Session beziehungsweise ein geeignetes Bearer-Verfahren mit Schutz gegen fremde Origins.
- `Host`- und `Origin`-Header müssen strikt geprüft werden.
- Eine pauschale CORS-Freigabe mit `*` ist verboten.
- Reale Provider-API-Keys werden im nativen Betriebssystem-Schlüsselbund gespeichert.
- Das Coding-Agent-Profil erhält nur das lokale Proxy-Token. Dieses darf niemals an den Provider weitergeleitet werden.
- Das Backend ersetzt lokale Authentifizierungsdaten durch die passenden Provider-Credentials.
- Provider-Secrets dürfen niemals an das Frontend, in Exceptions, Logs, Auditdatensätze oder OpenTelemetry-Attribute gelangen.
- Fehlt auf einer Plattform ein verwendbarer Schlüsselbund, muss die Anwendung sicher und verständlich abbrechen. Eine unverschlüsselte automatische Fallback-Speicherung ist verboten.

## 9. Proxy-Endpunkte

Mindestens folgende Endpunkte implementieren:

```text
POST /proxy/openai/v1/responses
POST /proxy/openai/v1/chat/completions
POST /proxy/anthropic/v1/messages
```

### 9.1 Anforderungen an die Weiterleitung

- Request-Body und relevante Header müssen vor dem Upstream-Aufruf verarbeitet werden.
- Hop-by-hop-Header werden nicht weitergeleitet.
- Lokale Authentifizierungsheader werden niemals weitergeleitet.
- Provider-spezifische notwendige Header und unbekannte Payload-Felder werden soweit sicher möglich erhalten.
- Upstream-Statuscode und relevante Response-Header werden semantisch unverändert zurückgegeben.
- Fehlerantworten des Providers dürfen nicht pauschal in HTTP 500 umgewandelt werden.
- Client-Abbruch muss den Upstream-Request abbrechen.
- Automatische Retries sind für nicht eindeutig idempotente LLM-Requests standardmäßig deaktiviert.
- Timeouts und maximale Request-/Response-Größen sind konfigurierbar.
- Komprimierte Inhalte werden nur verarbeitet, wenn sie sicher dekomprimiert und gegen ein Dekompressionslimit geprüft werden können.
- Proxy-Schleifen müssen erkannt und blockiert werden.

### 9.2 Streaming

- SSE muss ohne vollständiges Puffern der Antwort weitergeleitet werden.
- Response-Scanner dürfen einen begrenzten Rolling Buffer verwenden.
- Der Proxy muss Backpressure respektieren.
- Time-to-first-byte und zusätzlicher Proxy-Overhead sollen messbar sein.
- Wird ein blockierender Fund während eines Streams erkannt, wird der Stream beendet und das Ereignis auditiert.
- Unvollständige oder fragmentierte JSON-/SSE-Daten dürfen nicht fälschlich als vollständige Ereignisse interpretiert werden.

## 10. Einheitliches internes Datenmodell

Implementiere mindestens folgende Domänenmodelle, unabhängig von FastAPI:

```python
class Finding:
    id: UUID
    category: FindingCategory
    severity: Severity
    detector: str
    confidence: float
    location: FindingLocation
    start: int | None
    end: int | None
    fingerprint: str
    suggested_replacement: str | None
    metadata: dict[str, str]

class PolicyDecision:
    action: PolicyAction
    findings: list[Finding]
    matched_rule_ids: list[str]
    reason: str
    policy_version: str
```

`PolicyAction` enthält:

```text
ALLOW
WARN
REDACT
REQUIRE_APPROVAL
BLOCK
```

Priorität bei mehreren Treffern:

```text
BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW
```

Ein Detector liefert nur Findings. Er trifft keine endgültige Freigabeentscheidung. Diese Trennung ist verbindlich.

## 11. Detector-Engine

### 11.1 Schnittstelle

Alle Detectoren implementieren eine gemeinsame asynchrone Schnittstelle. Sie erhalten einen normalisierten Scan-Kontext und liefern Findings. Detectoren müssen einzeln aktivierbar, konfigurierbar und testbar sein.

### 11.2 Secret-Detectoren

Version 1 erkennt mindestens:

- OpenAI- und Anthropic-artige API-Keys
- AWS Access Key IDs und typische Secret-Zuweisungen
- GitHub Personal Access Tokens
- Bearer Tokens
- JWTs
- PEM-kodierte private Schlüssel
- Passwörter in typischen Konfigurationszuweisungen
- generische hoch-entropische Werte nur zusammen mit geeignetem Kontext

Tests verwenden ausschließlich eindeutig synthetische Testwerte.

### 11.3 PII-Detectoren

Mindestens:

- E-Mail-Adressen
- Telefonnummern
- IBAN
- IP-Adressen, konfigurierbar
- Personen- und Organisationsnamen über Presidio, soweit das konfigurierte Sprachmodell dies unterstützt
- deutsche und englische Texte

Die Benutzeroberfläche muss Confidence und Detector anzeigen. Die Dokumentation muss darauf hinweisen, dass PII-Erkennung unvollständig sein kann.

### 11.4 Projektspezifische Detectoren

- exakte Begriffe
- Begriffe ohne Beachtung der Groß-/Kleinschreibung
- reguläre Ausdrücke
- optional Wortgrenzen
- Zuordnung einer Datenklasse und Standardaktion
- Import und Export als YAML

Beispiele sind Kundennamen, interne Projektnamen, Java-Package-Präfixe, Tabellennamen und Fachbegriffe.

### 11.5 Payload-Verarbeitung

- Alle relevanten Textfelder im JSON-Body werden rekursiv untersucht, einschließlich verschachtelter Tool-Argumente und Tool-Ergebnisse.
- Nicht-String-Werte und die JSON-Struktur bleiben erhalten.
- Provider-Steuerfelder wie Modellname oder Stream-Flag werden nicht unkontrolliert verändert.
- Nicht unterstützte Inhalte werden als eigener Finding-Typ gemeldet.
- Request-Header werden selektiv auf unerwartete Secrets geprüft; bekannte lokale Authentifizierungsheader werden separat behandelt und nie protokolliert.

## 12. Redaction und Pseudonymisierung

### 12.1 Platzhalter

Verwende typisierte, kollisionsarme Platzhalter, beispielsweise:

```text
<AS:PERSON:0001>
<AS:ORGANIZATION:0001>
<AS:INTERNAL_CLASS:0001>
```

Gleiche Werte erhalten innerhalb einer Sitzung denselben Platzhalter. Unterschiedliche Werte dürfen nicht denselben Platzhalter erhalten.

### 12.2 Rehydrierung

- Nur ausdrücklich als reversibel konfigurierte Datenklassen dürfen rehydriert werden.
- Secrets, Passwörter, Tokens und private Schlüssel werden niemals rehydriert.
- Es werden ausschließlich exakte, vom Proxy selbst erzeugte Platzhalter ersetzt.
- Zuordnungen werden lokal, verschlüsselt oder nur im Speicher und mit konfigurierbarer TTL gehalten.
- Beim Ablauf einer Zuordnung wird nicht geraten; unbekannte Platzhalter bleiben unverändert und erzeugen eine Warnung.
- Die Ersetzung darf JSON-Escaping und Unicode nicht beschädigen.

### 12.3 Standardverhalten

- Secrets: `BLOCK`
- PII: im Profil `balanced` standardmäßig `REDACT`
- projektspezifische Begriffe: konfigurierbar
- nicht unterstützte Binärinhalte: im Profil `strict` `BLOCK`

## 13. Policy-Engine

### 13.1 Profile

Implementiere drei initiale Profile:

#### `audit`

- keine automatische Inhaltsblockierung außer bei internem Sicherheitsfehler, der eine sichere Weiterleitung unmöglich macht
- Findings und hypothetische Entscheidung werden protokolliert
- deutlich sichtbarer Hinweis, dass keine Verhinderung stattfindet

#### `balanced`

- Secrets blockieren
- PII pseudonymisieren
- unbekannte sensible Begriffe warnen oder zur Freigabe vorlegen
- nicht unterstützte Inhalte warnen

#### `strict`

- Secrets blockieren
- nur freigegebene Provider und Modelle erlauben
- unbekannte sensible Inhalte zur Freigabe vorlegen oder blockieren
- nicht unterstützte Inhalte blockieren
- bei Ausfall eines erforderlichen Detectors blockieren

### 13.2 Regeln

Regeln können mindestens berücksichtigen:

- Agent/Integration
- Projekt
- Provider
- Modell
- Endpunkt
- Richtung `REQUEST` oder `RESPONSE`
- Finding-Kategorie
- Severity
- Detector

Policies werden versioniert. Jede Entscheidung referenziert eine unveränderliche Policy-Version. Import und Export als YAML sind vorzusehen; SQLite bleibt die Laufzeitquelle.

## 14. Manuelle Freigaben

- Bei `REQUIRE_APPROVAL` wird der Provider noch nicht aufgerufen.
- Das Backend erzeugt einen Freigabevorgang mit zufälliger ID und Ablaufzeit.
- Das Dashboard wird über SSE oder WebSocket informiert.
- Angezeigt werden nur die für die Entscheidung erforderlichen Inhalte; Secrets bleiben maskiert.
- Der Benutzer kann einmalig erlauben oder ablehnen.
- Eine einmalige Freigabe gilt nur für den konkreten Request-Fingerprint.
- Standard-Timeout: 60 Sekunden, konfigurierbar.
- Timeout oder Abbruch des Coding-Agents führt zu `BLOCK` beziehungsweise `CANCELLED`.
- Nach einem Client-Abbruch darf der Request nicht verspätet an den Provider gesendet werden.
- Für wiederkehrende Freigaben kann der Benutzer separat eine neue Policy-Regel anlegen; dies darf nicht implizit geschehen.

## 15. Persistenz und Audit

### 15.1 Zu speichernde Auditdaten

- UUID und Zeitstempel
- Korrelations- und optionale Sitzungs-ID
- Agent und Projekt
- Provider, Modell und Endpunkt
- Richtung
- Request-/Response-Größe
- Laufzeit und Proxy-Overhead
- Finding-Kategorien und Anzahl
- Detectoren und Confidence
- ausgeführte Policy-Regeln und Policy-Version
- Entscheidung und technischer Status
- SHA-256-Fingerprint des normalisierten Inhalts
- Fehlerklasse ohne vertrauliche Fehlermeldungsinhalte

### 15.2 Nicht standardmäßig zu speichern

- vollständige Prompts
- vollständige LLM-Antworten
- Provider-Keys
- lokale Proxy-Tokens
- gefundene Secret-Werte
- reversible Pseudonymisierungszuordnungen über ihre TTL hinaus

Ein expliziter Diagnosemodus darf temporär zusätzliche Inhalte speichern, muss vor Aktivierung deutlich warnen, automatisch ablaufen und die gespeicherten Inhalte weiterhin redigieren.

### 15.3 Auditexport

- Export als JSON
- Export als eigenständiger HTML-Bericht
- Exporte enthalten standardmäßig keine Raw Payloads
- Benutzeroberfläche zeigt aktive Filter und Exportzeitraum

## 16. Management-API und Benutzeroberfläche

### 16.1 Management-API

Mindestens:

```text
GET  /api/v1/health
GET  /api/v1/status
GET  /api/v1/events
GET  /api/v1/events/{id}
GET  /api/v1/approvals
POST /api/v1/approvals/{id}/approve
POST /api/v1/approvals/{id}/deny
GET  /api/v1/policies
POST /api/v1/policies
PUT  /api/v1/policies/{id}
GET  /api/v1/detectors
GET  /api/v1/settings
PUT  /api/v1/settings
POST /api/v1/audit/export
```

Pagination, Sortierung und Filterung werden serverseitig implementiert. Fehler verwenden ein einheitliches, dokumentiertes Problem-Details-Format ohne vertrauliche Inhalte.

### 16.2 UI-Seiten

#### Dashboard

- Dienststatus
- aktives Sicherheitsprofil
- Requests nach Entscheidung
- Findings nach Kategorie
- mittlere zusätzliche Latenz
- aktuelle Warnungen

#### Live Traffic

- laufende und abgeschlossene Requests
- Filter nach Agent, Projekt, Provider, Modell, Aktion und Zeitraum
- Detailansicht mit Findings
- Original/Bereinigt-Diff nur, wenn der Inhalt im Arbeitsspeicher noch verfügbar und die Anzeige zulässig ist

#### Approvals

- ausstehende Freigaben prominent anzeigen
- Restlaufzeit
- maskierte Findings
- Erlauben/Ablehnen

#### Policies

- Profile auswählen
- Regeln anzeigen, erstellen, bearbeiten und deaktivieren
- Konflikte und resultierende Priorität anzeigen
- Import/Export

#### Integrations

- Codex und Claude Code
- erkannte Konfiguration
- Änderungsvorschau
- Installieren, testen und zurückrollen

#### Audit

- datensparsame Ereignistabelle
- Details der Entscheidung
- JSON-/HTML-Export

#### Settings

- Provider-Konfiguration ohne Anzeige vorhandener Secrets
- Ports, Timeouts, Größenlimits und Retention
- Detectorstatus
- deutliche Anzeige der bekannten Schutzgrenzen

## 17. Agent-Konfiguration und Diagnose

### 17.1 Integrationsprinzip

- Bestehende Konfigurationsdateien dürfen nie blind überschrieben werden.
- Vor Änderungen wird eine Sicherung angelegt.
- Die geplante Änderung wird angezeigt.
- Änderungen erfolgen atomar.
- Rollback stellt exakt die zuvor gesicherte Konfiguration wieder her.
- AgentShield darf keine nicht zugehörigen Benutzereinstellungen entfernen.

Da sich Codex- und Claude-Code-Konfigurationsformate ändern können, müssen die Integrationen als Adapter implementiert und separat getestet werden. Unterstützte Versionen und erkannte Abweichungen sind anzuzeigen.

### 17.2 `agentshield doctor`

Prüft mindestens:

- Python- und Plattformvoraussetzungen
- Portverfügbarkeit
- Schreibzugriff auf das lokale Datenverzeichnis
- SQLite- und Migrationsstatus
- Verfügbarkeit des nativen Schlüsselbundes
- Vorhandensein der Provider-Credentials, ohne sie auszugeben
- Agent-Konfiguration und Proxy-Endpunkt
- Erreichbarkeit des Providers über AgentShield
- Proxy-Schleifen
- Frontend-Build
- aktive Sicherheitsprofile und Detectorstatus
- Hinweis auf möglichen direkten Egress außerhalb des Proxys

Die Ausgabe enthält keine Secret-Werte und liefert einen sinnvollen Exit-Code.

## 18. Qualitäts- und Sicherheitsanforderungen

### 18.1 Backend

- vollständige Typannotationen für Anwendungscode
- Pyright Strict ohne Fehler
- Ruff Check und Format ohne Fehler
- keine Catch-all-Exception-Behandlung ohne sichere Protokollierung und definierte Reaktion
- keine vertraulichen Werte in `repr`, Exceptions oder Logs
- Dependency Injection für Provider-Clients, Uhr und Persistenz in Tests

### 18.2 Frontend

- TypeScript Strict ohne Fehler
- zugängliche Tastaturbedienung
- keine Darstellung von Raw Secrets im DOM
- sichere Behandlung langer und binär wirkender Payloads
- Error Boundary und verständliche Fehlerzustände

### 18.3 Tests

Mindestens:

- Unit-Tests für jeden Detector
- Unit-Tests für Policy-Priorität
- Roundtrip-Tests für reversible Pseudonymisierung
- Tests, dass Secrets niemals rehydriert werden
- Provider-Vertragstests mit lokalen Mockservern
- SSE-Tests mit fragmentierten Events und fragmentierten Findings
- Client-Abbruch während Streaming und Approval
- Provider-Fehler, Rate Limits und Timeouts
- parallele Requests und getrennte Sitzungszuordnungen
- große Payloads und Größenlimits
- Base64-, URL-, Unicode-, Homoglyph- und Zero-Width-Testfälle
- False-Positive-Testkorpus
- Test, dass Logs und Auditdaten keine synthetischen Secrets enthalten
- API-Security-Tests für Host, Origin, CORS und lokale Tokens
- Playwright-End-to-End-Test für Blockierung, Redaction und Approval
- CI-Matrix für macOS, Linux und Windows, soweit die verwendete CI dies unterstützt

Alle Provider-Tests müssen ohne echte Provider-Zugänge und ohne kostenpflichtige API-Aufrufe laufen.

### 18.4 Performanceziele

Auf einem aktuellen Entwicklerrechner, ohne schweren NLP-Detector:

- zusätzlicher Median-Overhead vor dem Upstream-Aufruf: Ziel unter 30 ms für kleine Textrequests
- kein vollständiges Puffern von SSE-Responses
- konfigurierbares hartes Request-Limit, initial 10 MiB
- keine unbeschränkten Queues oder Buffer

Performanceziele werden gemessen und dokumentiert; sie sind keine Rechtfertigung, Security-Prüfungen still zu überspringen.

## 19. Implementierungsreihenfolge

### Meilenstein 1 – Fundament

- Monorepo und Tooling
- FastAPI-Backend, React-Frontend und gemeinsamer Build
- SQLite, SQLAlchemy und Alembic
- Health-/Status-Endpunkte
- sichere Konfigurationsstruktur
- CI, Linting, Typprüfung und Basistests

### Meilenstein 2 – Nicht-streamender LLM-Proxy

- OpenAI Responses API
- Anthropic Messages API
- lokale und Upstream-Authentifizierung
- Provider-Mockserver und Vertragstests
- korrektes Fehler- und Abbruchverhalten

### Meilenstein 3 – Detectoren und Policies

- Domänenmodelle
- Secret-, PII- und Custom-Term-Detectoren
- Policy-Engine und Profile
- Request-Scanning
- `ALLOW`, `WARN`, `REDACT` und `BLOCK`

### Meilenstein 4 – Streaming und Rehydrierung

- SSE-Passthrough
- Rolling Response Scan
- reversible Pseudonymisierung
- Rehydrierung erlaubter Datenklassen
- Streaming-, Abbruch- und Backpressure-Tests

### Meilenstein 5 – Dashboard und Approval

- generierter TypeScript-Client
- Dashboard und Live Traffic
- Monaco-Diff
- Approval-Lifecycle
- Policies und Settings

### Meilenstein 6 – Audit und Integrationen

- datensparsames Audit
- JSON-/HTML-Export
- Codex- und Claude-Code-Adapter
- Konfigurationsvorschau, Backup und Rollback
- `agentshield doctor`

### Meilenstein 7 – Härtung und Dokumentation

- Threat Model und Security-Dokumentation
- Angriffstestkorpus
- Cross-Platform-Tests
- Performancebericht
- SBOM und Dependency Scan
- Installations- und Demoanleitung

## 20. Definition of Done für Version 1

Version 1 gilt als fertig, wenn alle folgenden Bedingungen erfüllt sind:

1. Ein lokaler Mock-Coding-Agent kann OpenAI- und Anthropic-Requests über die dokumentierten Proxy-Endpunkte senden; die Dokumentation behauptet keine Kontrolle über Verbindungen außerhalb dieser Endpunkte.
2. Normale nicht-streamende und streamende Requests erreichen den Mock-Provider semantisch korrekt.
3. Synthetische Secrets werden zuverlässig blockiert und gelangen nachweislich weder zum Provider noch in Logs, Audit oder Frontend.
4. Konfigurierte PII und interne Begriffe können pseudonymisiert und geeignete Platzhalter korrekt rehydriert werden.
5. Secrets werden unter keinen Umständen rehydriert.
6. `REQUIRE_APPROVAL` hält einen Request vor dem Provider-Aufruf an und behandelt Freigabe, Ablehnung, Timeout und Client-Abbruch korrekt.
7. Die UI zeigt Live-Ereignisse, Findings, Entscheidungen, Policies, Integrationsstatus und Auditdaten.
8. Provider-Credentials befinden sich im Betriebssystem-Schlüsselbund und werden nicht an den Coding-Agent oder das Frontend ausgegeben.
9. Auditexporte enthalten standardmäßig keine Raw Payloads oder Secret-Werte.
10. Konfigurationsänderungen für unterstützte Agents besitzen Vorschau, Backup, Test und Rollback.
11. `agentshield doctor` erkennt die wesentlichen Fehlkonfigurationen, ohne vertrauliche Daten auszugeben.
12. Backend- und Frontend-Linting, Typprüfung, Unit-, Integrations- und End-to-End-Tests sind erfolgreich.
13. `THREAT_MODEL.md`, `ARCHITECTURE.md`, `SECURITY.md`, Installationsanleitung und Demoablauf sind vorhanden.
14. Die Benutzeroberfläche und Dokumentation weisen sichtbar darauf hin, dass direkter Egress außerhalb des Proxys in Version 1 nicht erzwungen blockiert wird.

## 21. Demonstrationsszenario

Die README enthält ein vollständig lokales, reproduzierbares Demo ohne echte LLM-Kosten:

1. AgentShield starten.
2. Mock-Provider starten.
3. Profil `balanced` auswählen.
4. Normalen Code-Request senden und erfolgreiche Weiterleitung sehen.
5. Request mit synthetischem API-Key senden und Blockierung sehen.
6. Request mit Personen- und internem Klassennamen senden.
7. Pseudonymisierung im Monaco-Diff sehen.
8. Rehydrierte Mock-Antwort erhalten.
9. Regel mit `REQUIRE_APPROVAL` auslösen und im Dashboard freigeben.
10. Auditbericht exportieren und zeigen, dass er keine vertraulichen Werte enthält.

## 22. Dokumentationsartefakte

Zusätzlich zur README müssen entstehen:

- `docs/ARCHITECTURE.md`: Komponenten, Datenfluss, Sequenzen und Erweiterungspunkte
- `docs/THREAT_MODEL.md`: Assets, Angreifer, Trust Boundaries, Risiken, Mitigations und bekannte Grenzen
- `SECURITY.md`: Meldeweg, sichere Konfiguration, Logging-Regeln und unterstützte Versionen
- ADR für Python/FastAPI
- ADR für React/Vite
- ADR für kooperativen Reverse Proxy statt TLS-Interception
- ADR für SQLite und datensparsames Audit
- OpenAPI-Dokumentation
- Beispielkonfigurationen ohne echte Secrets
- kurze Demoanleitung für ein Kundengespräch

## 23. Regeln für Implementierungsentscheidungen

- Keine Funktion darf durch stilles Abschalten von TLS-Prüfung, Authentifizierung oder Scannerfehlern „zum Laufen gebracht“ werden.
- Keine echten Zugangsdaten in Quellcode, Fixtures, Screenshots oder Dokumentation.
- Keine externen API-Aufrufe in der automatisierten Testsuite.
- Keine unnötigen Microservices, Message Broker oder Cloud-Abhängigkeiten.
- Sicherheit und fachliche Logik müssen ohne UI testbar sein.
- Neue Provider, Detectoren und Agent-Integrationen müssen über klar definierte Adapter ergänzt werden können.
- Bei einer Abweichung von dieser Spezifikation ist eine kurze Architecture Decision Record anzulegen und die Abweichung zu begründen.
- Bei Unklarheiten zuerst die sicherere und einfachere Variante implementieren und die Annahme dokumentieren.

## 24. Empfohlene Übergabe an Junie

Nicht die gesamte Version 1 in einem einzigen unkontrollierten Lauf implementieren lassen. Für den ersten Auftrag folgenden Prompt zusammen mit dieser Datei verwenden:

```text
Lies AgentShield_V1_Spezifikation.md vollständig. Implementiere zunächst nur
Meilenstein 1 – Fundament. Prüfe vorher den vorhandenen Repository-Zustand und
erstelle einen kurzen konkreten Implementierungsplan. Halte alle Vorgaben der
Spezifikation ein, erfinde keine Cloud-Abhängigkeiten und verwende ausschließlich
stabile Dependency-Versionen mit Lockfiles. Führe anschließend Linting,
Typprüfung und Tests aus. Dokumentiere getroffene Annahmen und offene Punkte,
aber beginne noch nicht mit Meilenstein 2.
```

Nach erfolgreicher Prüfung erhält Junie jeweils nur den nächsten Meilenstein als Auftrag. Vor Beginn eines neuen Meilensteins muss Junie die vollständige Spezifikation sowie den aktuellen Repository-Zustand erneut berücksichtigen und alle bisherigen Tests ausführen.
