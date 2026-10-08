# Ares Anti Cheat migration

The application, website, operator console, mail templates, package and Unity clients use Ares Anti Cheat branding. The website uses a helmet/shield emblem and crimson/bronze palette instead of storm and lightning imagery.

Use `ARES_*` environment variables in new deployments. Older `ZEUS_*` variables remain accepted as compatibility aliases; an explicitly supplied `ARES_*` value wins. Existing `.zeus-data/zeus.db` and `.zeus-data/uploads` are reused automatically when no storage override is supplied, preserving local account, evidence and upload data. New installations use `.ares-data/`. Do not move SQLite files while a server is running.

Restart the service and rebuild the frontend. Session cookie and CSRF/operator header names now use the Ares prefix; users should sign in again, and clients must use the new headers. Existing production agent key derivation and telemetry schemas remain unchanged. Demo signing material has the new Ares name: restart both the demo server and Unity client together.

Unity source now lives in `unity/Assets/Ares/Scripts/` with `AresDemoAgent`, `AresIngestClient` and `AresWire`. Update script references when integrating into an existing Unity project.

Historical Git commits may retain the previous name. This migration updates current files without rewriting published history.
