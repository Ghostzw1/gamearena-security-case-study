# Threat model

Method: list what is worth protecting, who might attack it and from where, then walk every feature
through **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege). Updated with every feature; snapshot 2026-11-25.

## 1. System overview

```
Player's phone ──HTTPS──► Vercel (Next.js: pages, Server Actions, cron job)
      │                         │
      │  WSS (live chat),        │  user's own session (anon key + JWT)
      │  signed file links       ▼
      └────────────────────► Supabase (Postgres + Auth + Realtime + Storage)
                                 │
              Push services ◄────┘ (Vercel sends empty Web Push messages)
```

**Key assumption:** the Supabase URL and anon key are public (they ship to every browser). Anyone can
call the database API directly, skipping the website. **Row Level Security is the real boundary.**

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Players' WhatsApp numbers, emails, CODM UIDs | Personal data; scam and harassment risk |
| Account integrity (who is who) | Impersonation, scams, false reports |
| Admin powers | Bans, settings, sponsor money, approving clans |
| Tournament integrity (results, squads, prizes) | Real money prizes; cheating destroys trust |
| Private conversations and files (clans, events, countries) | Privacy; abuse if leaked |
| Secrets (IP hash secret, VAPID key, cron secret) | Would let an attacker forge or de-anonymise |
| Availability of chat and sign-ups | Spam floods, cost |

## 3. Attackers

| Actor | Capability |
| --- | --- |
| Curious visitor | Browser + public anon key; can call the API directly |
| Malicious player | Valid account (signed-in JWT); scripts against the API |
| Cheater | Wants to inflate results, join stronger squads, skip approval |
| Scammer / spammer | Wants to post links, phone numbers, floods of messages |
| Rogue host or streamer | Has some staff rights; wants more (money, other events) |
| Password thief | Has an admin's password (phishing, reuse) |
| External network attacker | Tries SSRF, clickjacking, script injection, downgrade |
| Insider tooling | Generated code or tools introducing hidden characters or secrets |

## 4. Trust boundaries

1. **Phone → server**: nothing from the browser is trusted (forms, hidden fields, file types, prices).
2. **Anyone → database API**: the anon key is public; RLS, grants, constraints and triggers must hold on their own.
3. **Server → third parties**: push services and the exchange-rate API receive no personal data.
4. **Admin vs everyone**: admin rights need a database row **and** a second authentication factor.

## 5. STRIDE per feature (abridged)

| Feature | Threat (STRIDE) | Mitigation |
| --- | --- | --- |
| Waitlist form | **D** spam flood; **I** reading sign-ups | Trigger rate limit by hashed IP; RLS insert-only for `anon`; honeypot; no "already registered" message (enumeration) |
| Accounts | **S** look-alike usernames | ASCII-only usernames, case-insensitive unique |
| Profiles | **T** writing someone else's profile | `id` defaults to `auth.uid()`, not grantable; RLS `id = auth.uid()` |
| WhatsApp numbers | **I** harvesting numbers | Separate table; owner-only, plus confirmed squadmates via RLS |
| Chat | **T** posting as others; **D** floods; scams | `user_id` forced; 5 msgs/10 s trigger; link + phone filter in the database |
| Clans / country / event chats | **I** reading private rooms | `can_read_channel()` in RLS: members, own country, approved players only |
| Tournaments | **E** players creating paid events | RLS: players create scrims only; admins create tournaments |
| Squads | **T** joining full squads, skipping codes | Squads only via functions; codes not readable from the table |
| Results | **T/R** faking results, denying reports | `reporter_role` set by the database; cross-check host vs streamer vs player; reports keep reporter id |
| Money fields | **T** host raising prizes / adding fees | Admin-only trigger; CHECK: only GameArena's own tournaments take fees |
| Registration approval | **E** pending players seeing rooms or lists | RLS on entries, rooms and event chats requires `status = 'approved'` |
| File uploads | **T** disguised files; **I** reading others' files | Own-folder uploads, MIME allowlist, magic bytes, signed links via readable message |
| Push notifications | **SSRF** via endpoint URL; **I** payload leak | Endpoint allowlist (DB + server); empty pushes |
| Scheduled job | **S** anyone triggering it; key theft | Bearer secret (constant-time), DB verifies SHA-256 hash; no service-role key |
| Admin panel | **E** stolen password; **I** discovering admins | `aal2` required; players get a plain 404 |
| Sponsor ads | Phishing links, script injection | `https://` only, real hostname, link immutable after creation, plain-text cards |
| Whole site | XSS, clickjacking, downgrade | CSP, `frame-ancestors 'none'`, HSTS, nosniff, Referrer/Permissions policies |

## 6. Residual risks (accepted for now, with a plan)

See [incidents-and-lessons.md](incidents-and-lessons.md#known-limitations-and-roadmap).
