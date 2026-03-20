# Legacy Code (Deprecated)

This folder contains legacy authentication and credential-handling code
that predates the Meika Zero Trust architecture.

These files are preserved for historical reference only.

They MUST NOT be:
- Imported by active code
- Extended or modified
- Used for authentication or authorization

All security enforcement in Meika must occur via:
app/security/

If legacy functionality is needed, it must be reimplemented
as proof ingestion under the Zero Trust enforcement pipeline.
