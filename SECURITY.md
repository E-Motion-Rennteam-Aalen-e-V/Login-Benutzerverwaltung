# Sicherheitskonzept — credentials-repo

Dieses Dokument beschreibt das Bedrohungsmodell, die getroffenen
Sicherheitsentscheidungen und die Betriebspflichten für dieses private
Credentials-Repository. Es richtet sich an alle, die dieses Repo betreiben,
den Zugriffs-Token oder Verschlüsselungsschlüssel verwalten, oder Code
schreiben, der über `CredentialsClient` darauf zugreift.

## 1. Schutzziele

| Ziel | Umsetzung |
|---|---|
| **Vertraulichkeit** der Admin-Zugangsdaten | AES-256-GCM-Verschlüsselung der gesamten Nutzdaten, Schlüssel getrennt vom Repo |
| **Integrität** | GCM-Auth-Tag erkennt jede Manipulation am Ciphertext; zod-Schema-Validierung nach Entschlüsselung |
| **Nachvollziehbarkeit** | Jede Änderung erzeugt einen Git-Commit + strukturierten Audit-Log-Eintrag (Zeitstempel, Akteur, Aktion) |
| **Verfügbarkeit** | Stale-Cache-Fallback bei GitHub-Ausfall für Lesevorgänge; Schreibvorgänge scheitern bewusst statt inkonsistente Daten zu erzeugen |
| **Konsistenz bei Nebenläufigkeit** | Atomare Mehrdatei-Commits über die Git-Data-API + Optimistic-Concurrency (Fast-Forward-Check) |

## 2. Architekturprinzip: zwei getrennte Geheimnisse

Das zentrale Designprinzip dieses Repos: **Zugriff auf das Repo ≠ Zugriff auf die Daten.**

- Ein GitHub-Token gewährt Lese-/Schreibzugriff auf das Repo — aber die
  Datei, die er liest, ist Ciphertext. Ohne den Verschlüsselungsschlüssel ist
  sie wertlos.
- Der Verschlüsselungsschlüssel (`CREDENTIALS_ENCRYPTION_KEY`) liegt
  **niemals im Repo selbst** — weder im aktuellen Stand noch in der
  Historie. Er lebt ausschließlich in `.env` (lokal, gitignored) bzw. im
  Secret-Store der konsumierenden App (Vercel Environment Variables, GitHub
  Actions Secrets, o.ä.).

Konsequenz: Ein Angreifer braucht **beide** Geheimnisse gleichzeitig, um
Zugangsdaten zu kompromittieren. Ein geleaktes Token allein (z.B. über einen
falsch konfigurierten CI-Log) liefert nur Ciphertext.

Zusätzlich empfehlen wir, das Token, mit dem die **App zur Laufzeit** auf
`admins.json` zugreift (Contents: Read/Write), von einem eventuellen zweiten
Token zu trennen, mit dem dieses Repo **als npm-Paket installiert** wird
(nur Lesezugriff auf Code, siehe [README.md](README.md#nutzung-aus-der-haupt-app)).
So kann ein in einer Build-Pipeline geleaktes Install-Token niemals
Zugangsdaten lesen oder verändern.

## 3. Bedrohungsmodell

| # | Bedrohung | Auswirkung ohne Mitigation | Mitigation in diesem Repo |
|---|---|---|---|
| T1 | GitHub-Token geleakt (z.B. in Logs, Client-Bundle, kompromittierter CI-Runner) | Voller Lese-/Schreibzugriff aufs Repo | Fine-grained PAT, beschränkt auf **genau dieses Repo**, nur `Contents`-Permission; Daten selbst bleiben ohne Schlüssel verschlüsselt; Token-Rotation (Ablaufdatum erzwingen) |
| T2 | Verschlüsselungsschlüssel geleakt (z.B. Secret-Store-Fehlkonfiguration) | Ciphertext im Repo wird lesbar — aber nur mit zusätzlichem Repo-Zugriff | Schlüssel nie im Repo; `keyId` erlaubt Rotation ohne Ambiguität; sofortige Rotation via `npm run rotate-key` |
| T3 | Repo-Sichtbarkeit versehentlich auf "public" gestellt | Ciphertext für alle einsehbar | Envelope enthält keine Klartext-Metadaten (auch nicht Usernamen); trotzdem: Repo MUSS privat bleiben (organisatorische Kontrolle, siehe Abschnitt 8) |
| T4 | Insider mit Repo-Lesezugriff (z.B. Entwickler) ohne Schlüssel | Kann Ciphertext sehen, aber nicht entschlüsseln | Schlüsselverteilung nur an Prozesse/Personen, die ihn operativ brauchen (App-Runtime, superadmin-CLI-Nutzer) |
| T5 | Offline-Bruteforce auf geleakte Passwort-Hashes | Schwache Passwörter fallen | bcrypt (Cost-Faktor 12, adaptiv erhöhbar), Mindestlänge + Zeichenklassen-Policy, Ausschluss häufiger Passwörter |
| T6 | Online-Bruteforce / Credential-Stuffing gegen Login | Kontoübernahme | Lockout mit exponentiell wachsender Sperrzeit ab 5 Fehlversuchen, generische Fehlermeldung, Dummy-Hash-Vergleich gegen User-Enumeration |
| T7 | Timing-Seitenkanal beim Login (Antwortzeit verrät, ob Username existiert) | User-Enumeration | `bcrypt.compare` auch bei unbekanntem Username gegen festen Dummy-Hash; `keyId`-Vergleich mit `timingSafeEqual` |
| T8 | Manipulation des Ciphertexts in der Git-Historie (z.B. per Force-Push) | Unbemerkt korrumpierte Daten würden geladen | GCM-Auth-Tag macht jede Manipulation erkennbar (`DecryptionError`); Branch-Protection sollte Force-Push auf `main` verbieten (siehe Abschnitt 8) |
| T9 | Race Condition: zwei Prozesse ändern gleichzeitig | Lost Update, inkonsistenter Zustand | Git-Fast-Forward-Check via `git.updateRef` (kein `force`) erzwingt echte Serialisierung; automatischer Retry mit frischem Stand |
| T10 | Versehentlicher Klartext-Commit (z.B. manuelles Debuggen) | Passwort-Hash/Username dauerhaft in Git-Historie | CI-Gate `check-no-plaintext` validiert `admins.json` strikt gegen das Envelope-Schema (lehnt jedes Zusatzfeld ab); Secret-Scanning (gitleaks) in CI |
| T11 | Denial of Service über absichtlich riesige Passwort-Eingaben | Teure bcrypt-Berechnung bindet Ressourcen | Maximallänge 128 Zeichen in der Passwort-Policy |
| T12 | Rate-Limiting/Ausfall der GitHub-API | App nicht mehr benutzbar | Exponentielles Backoff mit Jitter für transiente Fehler; Stale-Cache-Fallback für Lesevorgänge (Schreibvorgänge fallen NIE auf Stale-Daten zurück) |
| T13 | Letzter `superadmin` wird versehentlich degradiert/gelöscht/deaktiviert | Aussperrung aus dem eigenen System | `assertLastSuperadminNotRemoved`-Guard blockiert diese Aktion serverseitig |

## 4. Verschlüsselung im Detail

- **Algorithmus:** AES-256-GCM (authenticated encryption — liefert
  Vertraulichkeit UND Integrität in einem Schritt).
- **Schlüsselerzeugung:** `openssl rand -base64 32` bzw.
  `generateEncryptionKey()` — volle 256 Bit Entropie aus einer
  kryptographisch sicheren Quelle (`node:crypto.randomBytes`). Bewusst
  **keine** passwortbasierte Schlüsselableitung (KDF): Der Schlüssel wird
  nie von einem Menschen erdacht, daher bringt eine KDF hier keinen
  Sicherheitsgewinn, nur zusätzliche Komplexität.
- **IV:** 12 zufällige Bytes pro Verschlüsselungsvorgang (NIST-Empfehlung
  für GCM), nie wiederverwendet.
- **`keyId`:** jeder Envelope trägt die ID des verwendeten Schlüssels.
  Entschlüsselung schlägt kontrolliert fehl (`DecryptionError`), wenn die
  bereitgestellte `keyId` nicht passt — verhindert stille Fehlentschlüsselung
  nach einer Rotation.
- **Was NICHT verschlüsselt im Repo liegt:** nur Metadaten des Envelopes
  selbst (`keyId`, `iv`, `updatedAt`, Algorithmus-Name) — keine Rückschlüsse
  auf Benutzernamen, Passwörter oder Rollen möglich.

### Schlüsselrotation

Empfohlener Rhythmus: alle 6–12 Monate, sowie **sofort** bei jedem Verdacht
auf Kompromittierung.

```bash
npm run rotate-key -- --new-key-id v2
```

Das Skript entschlüsselt mit dem aktuellen Schlüssel, verschlüsselt mit
einem neu generierten Schlüssel unter neuer `keyId` und schreibt beides
atomar zurück. **Danach zwingend:** den ausgegebenen neuen Schlüssel im
Secret-Store der App aktualisieren — vorher ist die App nicht mehr in der
Lage, die Daten zu lesen (bewusst fail-closed, keine automatische
Schlüssel-Synchronisierung, um genau diese Klasse von Fehlkonfiguration
sichtbar statt still zu machen).

## 5. Zugriffskontrolle & Token-Scoping

- **Fine-grained Personal Access Token**, nicht Classic-PAT: beschränkbar auf
  ein einzelnes Repository.
- **Permission:** ausschließlich `Contents: Read and write`. Keine weiteren
  Rechte (keine Admin-, Actions-, Webhook- oder Org-Rechte).
- **Ablaufdatum setzen** (max. 90 Tage empfohlen) statt "No expiration" —
  erzwingt regelmäßige Rotation und begrenzt den Schaden eines
  unentdeckten Leaks.
- **Getrennte Tokens** für unterschiedliche Zwecke (Laufzeit-Datenzugriff
  vs. Paket-Installation), siehe Abschnitt 2.
- **Autorisierung ist Sache der aufrufenden App:** Diese Bibliothek prüft
  bewusst NICHT, ob der eingeloggte Nutzer berechtigt ist, `createAdmin`,
  `setRoles` etc. aufzurufen — das wäre doppelte, potenziell inkonsistente
  Autorisierungslogik. Die App MUSS vor jedem sicherheitsrelevanten Aufruf
  selbst prüfen, dass der aktuelle Nutzer die Rolle `superadmin` trägt.

## 6. Passwort-Sicherheit

- **Hashing:** bcrypt, Cost-Faktor 12 (konfigurierbar), zufälliges Salt pro
  Passwort (bcrypt-intern).
- **Policy:** mindestens 11 Zeichen, mindestens 3 von 4 Zeichenklassen
  (Groß-/Kleinbuchstaben, Ziffern, Sonderzeichen), Ablehnung häufiger
  Passwörter, Passwort darf Benutzernamen nicht enthalten.
- **Ausnahme für temporäre Erst-Passwörter:** Wird ein Admin mit
  `mustChangePassword: true` angelegt, wird die "Passwort enthält
  Benutzernamen nicht"-Regel für dieses eine Passwort ausgesetzt (alle
  anderen Regeln bleiben aktiv). Begründung: Das Passwort ist ausschließlich
  für den einen ersten Login gültig, der Nutzer wird beim Einloggen
  zwingend zur Passwortänderung geführt — die App-Schicht MUSS
  `admin.mustChangePassword` auswerten und den Nutzer vor jeder weiteren
  Aktion zur Passwortänderung zwingen.
- **Lockout:** ab 5 Fehlversuchen exponentiell wachsende Sperrzeit (1, 2, 4,
  … Minuten, gedeckelt bei 60 Minuten), pro Nutzer.
- **Keine Nutzer-Enumeration:** identische, generische Fehlermeldung bei
  unbekanntem Username und bei falschem Passwort; konstante Rechenzeit durch
  `bcrypt.compare` gegen einen festen Dummy-Hash im Enumeration-Fall.

## 7. Audit-Trail

Jede sicherheitsrelevante Aktion erzeugt einen Eintrag in `audit-log.jsonl`
**im selben atomaren Commit** wie die zugehörige Datenänderung:

- `admin.create`, `admin.update`, `admin.password_change`, `admin.role_change`,
  `admin.disable`, `admin.enable`, `admin.delete`
- `admin.login_success` (bei **jedem** erfolgreichen Login, nicht nur bei
  Zurücksetzung eines Lockout-Zählers — vollständiger Login-Audit-Trail ist
  Voraussetzung für spätere Sicherheitsvorfall-Analysen)
- `admin.login_failure`, `admin.lockout`
- `key.rotate`

**Bewusster Trade-off:** Da jeder Login-Erfolg einen Git-Commit auslöst,
erzeugt ein sehr aktiv genutztes Admin-Panel entsprechend viele Commits. Für
ein internes CMS mit einer Handvoll Admins ist das unkritisch. Sollte das
Login-Volumen deutlich wachsen, sollte die App zusätzlich eigene
Access-Logs führen und `admin.login_success` ggf. auf sicherheitsrelevante
Fälle (z.B. Login nach Lockout, Login von neuem Kontext) beschränken —
dieses Repo bleibt dann die Quelle der Wahrheit für
**Zugangsdaten-Lebenszyklus-Ereignisse**, nicht für hochfrequente
Zugriffstelemetrie.

**Redaktion:** `buildAuditEntry` entfernt automatisch jeden Metadata-Key,
der auf `password`, `hash`, `secret`, `token` oder `key` matcht (Wert wird
durch `[REDACTED]` ersetzt) — verhindert versehentliches Leaken sensibler
Werte über den Audit-Log-Pfad. Das CI-Gate `check-no-plaintext` verifiziert
das zusätzlich automatisiert.

**Unveränderlichkeit:** Git-Commit-Historie ist von Natur aus append-only
und mit Zeitstempel + Autor versehen. Für zusätzliche Manipulationssicherheit
empfehlen wir, `main` mit Branch-Protection zu versehen (siehe Abschnitt 8).

## 8. Empfohlene GitHub-Repo-Härtung (manuell einzurichten)

Diese Bibliothek kann GitHub-Repo-Einstellungen nicht selbst setzen — bitte
nach dem Erst-Push manuell aktivieren:

- **Repository-Sichtbarkeit: Private** (essenziell — ohne diese Einstellung
  ist die gesamte Verschlüsselung nur noch defense-in-depth, nicht die
  primäre Schutzschicht)
- **Secret scanning + Push protection** (GitHub Advanced Security /
  kostenlos für private Repos in vielen Plänen) — verhindert zusätzlich zum
  eigenen `check-no-plaintext`-Gate, dass erkennbare Secrets überhaupt
  gepusht werden
- **Branch Protection auf `main`:** Force-Push verbieten, Löschen des
  Branches verbieten
- **Dependabot** für Sicherheitsupdates der npm-Abhängigkeiten aktivieren
- **2FA-Pflicht** für alle Mitglieder mit Repo-Zugriff (Org-Einstellung)
- Zugriff auf das Repo nur für Personen/Service-Accounts, die es
  tatsächlich brauchen (Prinzip der geringsten Rechte auch auf
  Repo-Mitgliedschaftsebene, unabhängig vom Token-Scoping)

## 9. Fehlerverhalten: fail-open vs. fail-closed

Bewusste, unterschiedliche Strategien je nach Operation:

- **Lesen (`loadAdmins`):** fail-open mit Stale-Cache — wenn GitHub kurzzeitig
  nicht erreichbar ist, kann die App mit dem letzten bekannten Stand
  weiterlaufen (z.B. bereits eingeloggte Sessions bleiben nutzbar), statt
  komplett auszufallen. Der Stale-Zustand wird geloggt (`console.warn`).
- **Login:** ruft `loadAdmins({ forceRefresh: true })` auf — Logins prüfen
  **immer** gegen den frischesten erreichbaren Stand, nie gegen einen
  potenziell veralteten Cache (verhindert, dass ein bereits deaktivierter
  oder gelöschter Account sich noch einloggen kann, solange der Cache lebt).
- **Schreiben (`saveAdmins`):** fail-closed, kein Fallback. Ein
  fehlgeschlagener Schreibvorgang wirft einen Fehler und ändert nichts —
  lieber eine sichtbare Fehlermeldung in der App als ein stiller
  Datenverlust oder eine Race Condition.
- **Entschlüsselung:** fail-closed. Ein `DecryptionError` (falscher
  Schlüssel oder manipulierte Daten) wird niemals stillschweigend
  ignoriert oder mit Default-Daten überbrückt.

## 10. CI/CD-Sicherheitsmaßnahmen

- `npm run typecheck` — TypeScript strict mode
- `npm run lint` — ESLint
- `npm test` — Unit-/Integrationstests inkl. simuliertem
  Concurrency-Konflikt und Tamper-Erkennung
- `npm run check-no-plaintext` — schema-striktes Gate gegen versehentliche
  Klartext-Commits
- `gitleaks` — allgemeines Secret-Scanning über den gesamten Diff
- `CodeQL` — statische Sicherheitsanalyse (wöchentlich + bei jedem Push/PR)
- `npm audit` sollte regelmäßig (oder via Dependabot automatisiert) geprüft
  werden

## 11. Incident Response

**Bei Verdacht auf Token-Leak (T1):**
1. Token sofort in GitHub-Settings widerrufen.
2. Neues Token mit gleichem, minimalem Scope erzeugen, Secret-Store der App
   aktualisieren.
3. `audit-log.jsonl` auf unerwartete Einträge im fraglichen Zeitraum prüfen.
4. Da der Angreifer nur Ciphertext sah: Verschlüsselungsschlüssel muss NICHT
   zwingend rotiert werden, es sei denn Punkt "Verdacht auf Schlüssel-Leak"
   trifft ebenfalls zu.

**Bei Verdacht auf Schlüssel-Leak (T2):**
1. Sofort `npm run rotate-key` ausführen.
2. Neuen Schlüssel im Secret-Store der App aktualisieren.
3. Da Passwörter ohnehin nur als bcrypt-Hash gespeichert sind, ist ein
   direktes Passwort-Leak durch einen Schlüssel-Leak allein unwahrscheinlich
   — trotzdem: allen betroffenen Admins vorsorglich einen Passwortwechsel
   (`mustChangePassword: true`) auferlegen.

**Bei versehentlichem Klartext-Commit (T10):**
1. **Nicht pushen**, falls noch nicht geschehen — Commit lokal
   zurücknehmen/korrigieren.
2. Falls bereits gepusht: Token UND Verschlüsselungsschlüssel sofort als
   kompromittiert behandeln (siehe oben) — Git-Historie ist grundsätzlich
   nicht zuverlässig nachträglich bereinigbar (Caches, Forks, lokale Clones).
3. Historie mit `git filter-repo` (nicht `filter-branch`, veraltet) bereinigen
   und **Force-Push** nach Rücksprache/Freigabe, alle lokalen Klone der
   Beteiligten müssen neu geklont werden.
4. Alle betroffenen Passwörter zurücksetzen, unabhängig davon ob der Hash
   theoretisch brute-force-resistent ist — defense in depth.

## 12. Bekannte Grenzen (Out of Scope)

- **Keine Multi-Faktor-Authentifizierung** für Admin-Logins in dieser
  Bibliothek — falls benötigt, in der App-Schicht ergänzen (z.B. TOTP,
  zusätzliches Feld `mfaSecretEncrypted` folgt demselben
  Verschlüsselungsmuster).
- **Kein KMS/HSM-Anschluss** für den Verschlüsselungsschlüssel im
  Standard-Setup — der Schlüssel liegt als Umgebungsvariable im Secret-Store
  der App. Für höhere Anforderungen: Schlüssel stattdessen in einem
  Cloud-KMS halten und `loadEncryptionKey` durch einen KMS-Aufruf ersetzen
  (die Envelope-Struktur unterstützt das über `keyId` bereits).
  Wird bei Bedarf durch eine App-KMS-Anbindung ergänzt.
- **Kein Rate-Limiting auf Netzwerkebene** (z.B. pro IP) — das ist Aufgabe
  der App/des Reverse Proxys, nicht dieser Bibliothek.
- **`saveAdmins`-Retries sind pro Prozess sequenziell**, nicht global
  koordiniert — bei sehr hoher gleichzeitiger Schreiblast (untypisch für
  ein Admin-Panel) steigt die Wahrscheinlichkeit wiederholter Konflikte.
  Für dieses Nutzungsprofil (wenige Admins, seltene Änderungen) ausreichend.
