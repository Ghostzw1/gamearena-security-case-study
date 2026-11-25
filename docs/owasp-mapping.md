# OWASP mapping

## OWASP Top 10 (2021)

| Risk | How GameArena addresses it |
| --- | --- |
| **A01 Broken Access Control** | RLS on every table, column-level grants, ownership from `auth.uid()`, approval-gated data, admin requires `aal2`, private storage with per-message access. 416 tests try to break it. |
| **A02 Cryptographic Failures** | HTTPS + HSTS; IPs as HMAC-SHA256; cron secret stored only as SHA-256; VAPID ES256 signing with built-in crypto; signed, expiring file links. |
| **A03 Injection** | Parameterised queries through PostgREST/supabase-js (no string-built SQL); SQL functions with `search_path = ''`; zod + CHECK constraints; hidden-character filters; CSP against script injection. |
| **A04 Insecure Design** | Threat model per feature; "database is the last line of defence"; payment design trusts only verified provider callbacks; results cross-checked by role. |
| **A05 Security Misconfiguration** | Explicit revokes of Supabase's default `anon` EXECUTE; security headers; `poweredByHeader: false`; private bucket with MIME and size limits; least-privilege CI token. |
| **A06 Vulnerable and Outdated Components** | Minimal dependencies (each one justified); built-in `node:crypto` instead of extra packages; one test dependency pinned by lockfile. |
| **A07 Identification and Authentication Failures** | Supabase Auth; 8+ character passwords with letters and digits; JWT verified with `getClaims()`; TOTP two-step login for admins; ASCII usernames against look-alikes. |
| **A08 Software and Data Integrity Failures** | Results integrity (DB-assigned roles, cross-checks); money fields admin-only; Trojan Source scanning of source code; CI runs the attack tests on every push. |
| **A09 Security Logging and Monitoring Failures** | Reports keep reporter, resolver and timestamps; soft-delete keeps messages for disputes; errors logged without personal data. *(Gap: no central alerting yet.)* |
| **A10 Server-Side Request Forgery** | Push endpoints allowlisted to real push services in the DB and the server; the only other outbound call is a fixed exchange-rate URL. |

## OWASP API Security Top 10 (2023)

| Risk | How GameArena addresses it |
| --- | --- |
| **API1 Broken Object Level Authorization** | Every row is checked by RLS against `auth.uid()`, squad membership, approval status or admin `aal2`. |
| **API2 Broken Authentication** | JWT verified per request; admin MFA; no service-role key used by the app. |
| **API3 Broken Object Property Level Authorization** | Column-level grants (e.g. squad join codes and push keys unreadable; `clan_tag`, `reporter_role`, `status` not writable). |
| **API4 Unrestricted Resource Consumption** | DB rate limits for sign-ups, chat, uploads; caps on rooms, clans, reports, ideas, devices; body and file size limits. |
| **API5 Broken Function Level Authorization** | Every privileged function checks the caller itself (`require_admin`, `is_host`), and `anon` EXECUTE is revoked. |
| **API6 Unrestricted Access to Sensitive Business Flows** | Registration approval, squad capacity, top-10 fair-play rule, one country chat per player, payment flow design. |
| **API7 Server Side Request Forgery** | Push endpoint allowlist (see A10). |
| **API8 Security Misconfiguration** | See A05. |
| **API9 Improper Inventory Management** | Every database change is a versioned migration in this repo; every control is listed in [controls.md](controls.md). |
| **API10 Unsafe Consumption of APIs** | Exchange-rate responses validated (known currencies, positive numbers) with a safe fallback; push service responses only used for 404/410 clean-up. |
