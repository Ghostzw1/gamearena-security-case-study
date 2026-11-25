# Controls catalogue

Every security control in GameArena: **threat → control → where it lives → test that proves it.**
"Test" names refer to suites in [`tests/`](../tests).

## Identity and access control

| Threat | Control | Where | Test |
| --- | --- | --- | --- |
| Reading data through the public API | RLS enabled on **every** table, explicit policies only; no table ships without them | DB | all |
| Writing columns you shouldn't (mass assignment) | All privileges revoked, then column-level `GRANT INSERT/UPDATE (...)` | DB | all |
| Acting as another player (IDOR) | Ownership columns default to `auth.uid()` and are not grantable; RLS re-checks | DB | chat, tournaments |
| Privileged functions hijacked | `SECURITY DEFINER` + `search_path = ''`; helpers in an unexposed `private` schema; `EXECUTE` revoked from `public` | DB | admin |
| Supabase's default `EXECUTE` for `anon` on new functions | Explicit `revoke ... from anon` on every signed-in-only function | DB | admin, tournaments |
| Stolen admin password | `is_admin()` requires an `app_admins` row **and** JWT `aal2` (TOTP two-step login) | DB + app | mfa |
| Discovering who is an admin | Admin panel renders a normal 404 for everyone else; `admin_status()` says `none` | app + DB | mfa |
| Promoting yourself to admin | `app_admins` has no API access at all (SQL editor only) | DB | mfa |
| Hosts escalating | Hosts add streamers only; only admins add hosts; hosts can't demote hosts | DB | tournaments |
| Session forgery | `getClaims()` verifies the JWT signature on every request; Server Actions re-check the user | app | - |
| Open redirect after login | `?next=` must be a same-site path (`/x`, not `//evil.com` or `\`) | app | - |

## Privacy

| Threat | Control | Where | Test |
| --- | --- | --- | --- |
| Harvesting phone numbers | WhatsApp numbers in their own table; owner only, plus confirmed squadmates | DB | chat, tournaments |
| Exposing CODM UIDs | Private by default; public only if the player opts in; squad + event staff can see | DB | tournaments |
| Account enumeration via the waitlist | Duplicate numbers get the same success screen | app | - |
| De-anonymising visitors | IPs stored only as HMAC-SHA256 with a server secret | app | - |
| Personal data in logs | Errors log only Postgres error codes | app | - |
| Data to third parties | Help bot runs offline; Web Push messages are empty; FX feed request carries nothing | app | push |
| Private files | Private bucket; signed links (1 h); access only if you can read the message; deleting the message hides the file | DB + storage | media |

## Input validation and integrity

| Threat | Control | Where | Test |
| --- | --- | --- | --- |
| Malicious or junk input | zod schemas on every Server Action **and** mirrored `CHECK` constraints | app + DB | all |
| Trojan Source / hidden text tricks | Control, zero-width and bidi characters rejected in all text; source code scanned | app + DB | chat, events |
| Look-alike usernames | ASCII `A–Z a–z 0–9 _`, case-insensitive unique index | DB | chat |
| Faked tournament results | DB assigns `reporter_role`; own squad only; live events only; sane ranges; host/streamer cross-check | DB | tournaments |
| Tampering with money | Trigger: fees, prizes, sponsor, refund threshold admin-only; CHECK: only GameArena's own events take fees | DB | tournaments, events |
| Joining squads illegally | Squads only via functions; join codes hidden by column privilege; capacity + top-10 fair-play rule | DB | tournaments, events |
| Skipping approval | Player list, room, event chat, results and reports require `status = 'approved'` | DB | events |
| Phishing ad / stream links | `https://` + real hostname / allowed platforms only; ad links immutable after creation; `rel="nofollow ugc noopener"` | DB + app | regions, events |

## Abuse and availability

| Threat | Control | Where | Test |
| --- | --- | --- | --- |
| Sign-up floods | Trigger: ≥10 per hashed IP or ≥100 total in 10 min rejected (`PT429`) | DB | - |
| Bots | Honeypot field; Supabase Auth rate limits | app | - |
| Chat floods | 5 messages / 10 s, 20 / min per player | DB | chat |
| Scams in chat | Links and phone numbers blocked by a trigger | DB | chat |
| Upload floods | 10 files / 10 min per player; size limits | DB + storage | media |
| Spam objects | Caps: 3 rooms, 1 clan, 10 reports per event, 3 ideas per day, 5 push devices | DB | tournaments, events, push |
| Slow dependencies | DB inserts time out after 8 s; FX fetch 5 s with a safe fallback | app | - |

## File uploads

| Threat | Control | Where | Test |
| --- | --- | --- | --- |
| Disguised files (script renamed `.jpg`) | Server reads the first 32 bytes (magic bytes) and must match the extension, else deletes it | app | - |
| Uploading into other users' space | Storage RLS: own folder `<user id>/...` only | storage | media |
| Posting someone else's file | Trigger: file must be in the sender's folder and exist | DB | media |
| Kind confusion | Video can't be posted as a picture; picture size ≤ 3 MB | DB | media |
| Executable content | Bucket MIME allowlist (images/videos only), `nosniff`, random names | storage | media |

## Secrets and server-side requests

| Threat | Control | Where | Test |
| --- | --- | --- | --- |
| Secrets in the browser | Only the public Supabase URL/anon key use `NEXT_PUBLIC_`; `server-only` imports fail the build if misused | app | - |
| Secrets in git | `.env.local` gitignored; secret values never printed; repository scanned before each push | process | - |
| Over-privileged jobs | Daily job uses the anon key + a secret checked by the DB against a SHA-256 hash (no service-role key) | DB + app | push |
| Timing attacks on secrets | Hash both sides then `timingSafeEqual` | app | - |
| SSRF | Push endpoints must be on Google/Mozilla/Microsoft/Apple push hosts (DB CHECK + server) | DB + app | push |
| Vulnerable dependencies | No new packages without a reason; Web Push signed with built-in `node:crypto` instead of a library | process | - |

## Browser and transport

| Threat | Control |
| --- | --- |
| XSS / data exfiltration | CSP: `default-src 'self'`, `connect-src` own Supabase only, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'` |
| Clickjacking | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| Downgrade attacks | HSTS 2 years with subdomains |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| URL leaks | `Referrer-Policy: strict-origin-when-cross-origin` |
| Unneeded device APIs | `Permissions-Policy` disables camera, mic, location, payment, USB |
| Cross-window attacks | `Cross-Origin-Opener-Policy: same-origin` |
| Fingerprinting | `X-Powered-By` removed |
| CSRF on Server Actions | Next.js Origin check; 64 KB body limit |

## Payments (designed, not yet live)

| Threat | Control |
| --- | --- |
| Faking "paid" from the browser | An entry counts as paid only after the server gets the provider's callback, **verifies its hash** with the integration key, **and** polls the provider to confirm status and amount |
| Handling card numbers | The app never sees or stores card numbers (PCI DSS scope reduction); payouts go to a bank account set in the provider's dashboard |
| Price tampering | The server recalculates every amount; the phone only displays quotes |
| Operating illegally | Real money disabled until a gaming licence is granted (test mode only) |
