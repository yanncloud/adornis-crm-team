# Adornis CRM — Team-Pilot

Gemeinsames CRM mit Node.js/Express, PostgreSQL und daisyUI.

**Pilotstatus:** Der Render-Webservice ist veröffentlicht, aber die Datenbankverbindung und der initiale Administrator müssen in Render als Environment Variables eingerichtet werden. Bitte noch keine echten Kundendaten verwenden.

## Funktionsumfang

- Individuelle Logins und HTTP-only Sitzungen mit CSRF-Schutz
- Gemeinsame Unternehmen, Kontakte, Deals und Aufgaben in PostgreSQL
- Teamrollen: Admin, Manager, Mitarbeiter; serverseitige Datensatz-Zugriffsprüfungen
- Benutzerverwaltung und Änderungshistorie
- Dashboard und Vertriebspipeline

## Erstkonfiguration in Render

Web-Service: https://dashboard.render.com/web/srv-dbk7cm4s728c73cb4li0

Vorhandene Render-PostgreSQL-Datenbank: https://dashboard.render.com/d/dpg-dbk6utu7bikc739bepdg-a

1. Bei der Datenbank auf **Connect** gehen und die **Internal Database URL** kopieren (nur im Render-Dashboard, nicht per Chat oder GitHub teilen).
2. Beim Web-Service **Environment** öffnen und die folgenden Variablen hinterlegen:
   - `DATABASE_URL`: Internal Database URL der Datenbank
   - `ADMIN_EMAIL`: eigene Admin-E-Mail-Adresse
   - `ADMIN_PASSWORD`: zufälliges, neues, mindestens 16 Zeichen langes Admin-Passwort
   - `NODE_ENV`: `production` (bereits gesetzt)
3. **Save, rebuild and deploy** bzw. die Umgebungsvariablen speichern und neu deployen.
4. `https://adornis-crm-team.onrender.com/api/health` muss `{"status":"ready","team":true}` zurückgeben.
5. Anmelden und das temporäre Admin-Passwort sofort ändern. Danach in der Teamverwaltung Testbenutzer anlegen.

Zugangsdaten niemals in Repository, Chat oder Screenshots kopieren.

## Sicherheitsgrenzen

Pilot ohne MFA/SSO, Feld-Level-ABAC, PostgreSQL RLS, automatisierte Backups und Penetrationstest. Es liegt keine Prüfung der Datenschutzkonformität vor. Freie Render-Postgres-Instanz ist laut Render bis 02.12.2026 befristet; für dauerhaftes CRM vorher auf geeigneten Plan mit Backups umstellen.

**Branding:** Noch kein verifiziertes Adornis-Logo/CI; derzeit vorläufige Marke, daisyUI-UI.
