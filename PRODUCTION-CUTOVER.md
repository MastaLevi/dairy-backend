# Production cutover checklist

This checklist is preparation only. The current hosted database is a test database. No production database has been selected or changed by this work, and the new SMS migration has not been applied anywhere.

## Before production is approved

- [ ] Confirm who owns production operations, who can approve the cutover, and who can access worker and farmer data.
- [ ] Choose the production database provider, region, database name, recovery point objective, and backup retention period.
- [ ] Create a new database and a separate restricted database user. Do not copy the test database or its credentials as the starting production environment.
- [ ] Keep test and production environment variables in separate deployment services/environments. Populate production values from `.env.production.example` using the hosting provider's secret settings; do not commit secrets.
- [ ] Require verified TLS for the production DB connection and HTTPS for app/API traffic.
- [ ] Generate new production token/admin secrets. Create the intended admin row in the production `Admin` table using the repository's password-hash format; do not rely on an example password.
- [ ] Confirm the Android package ID and signing key intended for the eventual production APK. Preserve the signing key securely so a later APK can update the installed one.

## Database setup and data handling

- [ ] Take a pre-change backup before applying schema changes.
- [ ] Create the production schema from reviewed migrations. Apply `schema.sql`, `offline-migration.sql`, `route-migration.sql`, and `sms-delivery-log-migration.sql` only where their changes are not already present; confirm the actual hosted schema first because migrations are not all repeatable.
- [ ] Seed only verified production farmers, workers, and routes using an approved import process. Do not import test collections or test credentials.
- [ ] Confirm IDs, indexes, foreign keys, and duplicate-sync behavior against a copy of the production schema before the first live collection.
- [ ] Verify SMS provider credentials, sender setup, phone-number normalization, and recipient consent before enabling live messages.

## Backup and restore readiness

- [ ] Enable the provider's scheduled automated backups for the production database, or schedule encrypted logical backups if provider backups do not meet the agreed recovery needs.
- [ ] Store backup copies separately from the database account and restrict access because farmer and collection records are sensitive operational data.
- [ ] Set a retention period and document who receives backup-failure alerts.
- [ ] Restore a recent backup into a separate non-production database before go-live; verify farmer, worker, route, collection, and SMS-log records.
- [ ] Repeat a restore exercise after major schema changes and periodically thereafter. A successful backup job alone does not prove recoverability.

## SMS status history

The backend now has an optional status-history path. It is off unless `SMS_DELIVERY_LOG_ENABLED=true`. It records collection ID, provider name, provider status, provider response code when present, and attempt time. It deliberately does not store the message body or farmer phone number. The office-only endpoint returns the latest 50 attempts. Apply `sms-delivery-log-migration.sql` before enabling the flag or using that endpoint.

`accepted` means the provider accepted or queued the request; it is not a handset delivery receipt. The current integration does not process provider delivery callbacks. Keep this distinction in the office workflow.

## Go-live sequence

1. Confirm the production database and backend are isolated from test services.
2. Take and verify a production pre-cutover backup.
3. Apply the reviewed migrations and configure the admin account and SMS provider.
4. Smoke-check worker/admin login, farmer lookup, online collection, offline retry/deduplication, SMS attempt logging, and restore access using approved test accounts/phone numbers.
5. Publish the approved API and app build, then verify the installed APK reaches the production HTTPS API.
6. Start live operations only after the designated owner approves the cutover. Keep a rollback contact and restore point available.
