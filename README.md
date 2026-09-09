# credentials-repo

Privates, verschlüsseltes Repository für Admin-Benutzer, Passwort-Hashes und
Rollen einer separaten CMS/App. Wird von der App **nicht** direkt als
Datenbank gemountet, sondern über die GitHub-API mit einem eng begrenzten
Token gelesen/geschrieben — die App bindet dieses Repo als Bibliothek ein.

Für das vollständige Bedrohungsmodell und die Sicherheitsentscheidungen
siehe [SECURITY.md](SECURITY.md). Dieses Dokument ist der praktische
Setup-/Nutzungsguide.

## Architektur in Kürze

```
┌─────────────────┐        GitHub Contents/Git-Data API        ┌──────────────────────┐
│   Haupt-App      │  ───────────────────────────────────────▶  │  privates GitHub-Repo │
│  (CMS, separates  │  fine-grained PAT, nur dieses Repo,        │  "credentials-repo"   │
│   Projekt)        │  Contents: Read & Write                    │                        │
│                    │ ◀───────────────────────────────────────  │  admins.json           │
│  CredentialsClient │        (verschlüsselter Envelope)          │  (AES-256-GCM,         │
│  aus diesem Paket  │                                            │   niemals Klartext)    │
└─────────────────┘                                            │  audit-log.jsonl        │
                                                                  │  (Commit-Historie =     │
                                                                  │   Audit-Trail)          │
                                                                  └──────────────────────┘
```

Zwei getrennte Geheimnisse, zwei getrennte Verantwortlichkeiten:

1. **GitHub-Token** öffnet den Zugriff auf das Repo (Transportweg), sieht
   aber nur Chiffretext.
2. **Verschlüsselungsschlüssel** (`CREDENTIALS_ENCRYPTION_KEY`) macht den
   Chiffretext lesbar, lebt aber **nicht** im Repo, sondern ausschließlich im
   Secret-Store der App.

Ein kompromittiertes Token allein liefert einem Angreifer nur Ciphertext.
Ein kompromittierter Schlüssel allein (ohne Repo-Zugriff) liefert nichts.
Erst beides zusammen ist gefährlich — siehe [SECURITY.md](SECURITY.md#bedrohungsmodell).

## Erst-Setup

### 1. Privates GitHub-Repo anlegen

Auf github.com ein neues **privates** Repository anlegen (z.B.
`<org>/credentials-repo`). Dieses Verzeichnis wird der Inhalt davon.

### 2. Fine-grained Personal Access Token erzeugen

GitHub → Settings → Developer settings → Fine-grained tokens → Generate new token:

- **Repository access:** "Only select repositories" → nur dieses eine Repo
- **Permissions:** Contents → **Read and write** (sonst nichts)
- Ablaufdatum setzen (z.B. 90 Tage) und im Kalender fürs Rotieren vormerken

### 3. Lokale Konfiguration

```bash
cp .env.example .env
npm install
```

`.env` ausfüllen: `GITHUB_OWNER`, `GITHUB_REPO`, `GITHUB_TOKEN`. Den
Verschlüsselungsschlüssel (`CREDENTIALS_ENCRYPTION_KEY`) NICHT von Hand
setzen — er wird beim ersten `add-admin`-Aufruf automatisch generiert (siehe
unten) und in `.env` gespeichert (die Datei ist per `.gitignore` niemals Teil
des Repos).

### 4. Ersten Admin anlegen (Bootstrap)

Ohne gesetzte `GITHUB_*`-Variablen arbeitet das CLI lokal (Dateisystem) —
praktisch, um vor dem Erst-Push alle Admins bereits fertig verschlüsselt
vorzubereiten:

```bash
npm run add-admin -- --username denny --password "IhrStarkesPasswort1!" --roles superadmin --actor bootstrap
```

Das erzeugt lokal `admins.json` (verschlüsselt) und `audit-log.jsonl`. Diese
beiden Dateien werden anschließend einmalig ins private Repo committed und
gepusht:

```bash
git init
git add admins.json audit-log.jsonl
git commit -m "chore: initial credentials bootstrap"
git remote add origin git@github.com:<org>/credentials-repo.git
git push -u origin main
```

Ab jetzt: `GITHUB_OWNER`/`GITHUB_REPO`/`GITHUB_TOKEN` in `.env` setzen — alle
weiteren `manage-admin`-Aufrufe (und die App) sprechen direkt mit GitHub statt
mit der lokalen Datei.

## Weitere Admins verwalten (CLI)

```bash
# Admin mit temporärem Erst-Passwort anlegen (erzwingt Passwortwechsel beim ersten Login)
npm run add-admin -- --username linda --password "Temp-Passwort" --roles Admin --actor denny --must-change-password

npm run list-admins
npm run disable-admin -- --username linda --actor denny
npm run enable-admin -- --username linda --actor denny
npm run remove-admin -- --username linda --actor denny --yes
npm run rotate-key -- --new-key-id v2
```

## Nutzung aus der Haupt-App

### Paket einbinden

Zwei Optionen, **bewusst mit unterschiedlichem Token** von dem oben
erzeugten Laufzeit-Token getrennt (siehe SECURITY.md, Prinzip der
Aufgabentrennung):

**Option A — GitHub Packages (empfohlen):** dieses Repo per
`npm publish` an die private GitHub-Packages-Registry der Org veröffentlichen;
die App installiert es mit einem separaten Token, das nur
`read:packages`-Rechte hat (kann NICHT auf admins.json zugreifen).

**Option B — Git-Dependency:** in der App:

```json
{ "dependencies": { "credentials-repo": "git+https://github.com/<org>/credentials-repo.git#main" } }
```

mit einem Deploy-Token mit ausschließlich Lesezugriff auf dieses Repo (nicht
mit dem Contents-R/W-Token für die Laufzeit-Datenzugriffe verwechseln!).

### Code-Beispiel

```ts
import {
  CredentialsClient,
  loadEncryptionKey,
  login,
  createAdmin,
  InvalidCredentialsError,
  AccountLockedError,
} from "credentials-repo";

const client = new CredentialsClient({
  owner: process.env.GITHUB_OWNER!,
  repo: process.env.GITHUB_REPO!,
  token: process.env.GITHUB_TOKEN!, // Laufzeit-Token: Contents R/W, nur dieses Repo
  encryptionKey: loadEncryptionKey(
    process.env.CREDENTIALS_KEY_ID ?? "v1",
    process.env.CREDENTIALS_ENCRYPTION_KEY!,
  ),
});

try {
  const admin = await login(client, username, password);
  if (admin.mustChangePassword) {
    // UI zum Passwort-Setzen erzwingen, bevor die Session vollwertig wird
  }
} catch (err) {
  if (err instanceof InvalidCredentialsError) {
    /* generische Fehlermeldung anzeigen */
  }
  if (err instanceof AccountLockedError) {
    /* "Konto gesperrt" anzeigen, err.message enthaelt Zeitpunkt */
  }
}
```

Weitere Funktionen: `changePassword`, `setRoles`, `setDisabled`,
`removeAdmin` — jede benötigt einen `actor` (Username des ausführenden
superadmin) für den Audit-Trail. **Autorisierung ist Sache der App:** diese
Bibliothek prüft nicht, ob der aufrufende Nutzer berechtigt ist — die App
muss vor jedem Aufruf selbst sicherstellen, dass der eingeloggte Nutzer
`superadmin` ist.

## Entwicklung

```bash
npm run typecheck
npm run lint
npm test
npm run check-no-plaintext   # CI-Gate: admins.json ist ausschliesslich verschluesselt
```

`npm test` läuft komplett gegen Fakes (kein echter GitHub-Zugriff nötig) —
inklusive eines simulierten Concurrency-Konflikts, der den
Optimistic-Concurrency-Mechanismus (Git-Fast-Forward-Check) end-to-end prüft.

## Lizenz

Privates, internes Projekt (`UNLICENSED`).
