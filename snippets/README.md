# Code excerpts

Small, self-contained pieces of GameArena's security code (the full app source is private).

| File | What it shows |
| --- | --- |
| [magic-bytes.ts](magic-bytes.ts) | Detecting what an upload really is from its first bytes (JPEG, PNG, GIF, WebP, MP4/MOV, WebM) and matching it to the extension |
| [ssrf-allowlist.ts](ssrf-allowlist.ts) | Only calling real Web Push services, never an address a user supplied |
| [vapid-es256-signing.ts](vapid-es256-signing.ts) | Signing Web Push requests (VAPID JWT, ES256) with Node's built-in crypto; sending empty, data-free pushes |
| [cron-secret-constant-time.ts](cron-secret-constant-time.ts) | Protecting a scheduled job: constant-time secret check, database verifies a SHA-256 hash, no service-role key |
| [hashed-client-ip.ts](hashed-client-ip.ts) | Rate limiting by IP without storing IPs (HMAC-SHA256 with a server secret) |
| [open-redirect-guard.ts](open-redirect-guard.ts) | Allowing only same-site paths after sign-in |
| [trojan-source-guards.ts](trojan-source-guards.ts) | Rejecting zero-width and text-direction characters |
| [security-headers.ts](security-headers.ts) | Content-Security-Policy and the other HTTP security headers |

The database side (RLS policies, triggers, security functions) is in [`../migrations`](../migrations).
