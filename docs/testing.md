# Testing approach

## Why test the database directly?

The Supabase anon key is public, so an attacker doesn't need the website: they can call the database API
with their own scripts. The meaningful question is therefore **"what does the database allow?"**, not
"what does the UI show?". So the attack tests talk to Postgres the same way an attacker would: as the
`anon` role (visitor) or the `authenticated` role with a chosen user id.

## How the harness emulates Supabase

Each suite starts a fresh in-memory Postgres with [PGlite](https://pglite.dev) and recreates what
Supabase provides:

| Supabase piece | Stand-in |
| --- | --- |
| Roles `anon`, `authenticated`, `service_role` | `create role ...` with Supabase's default grants |
| `auth.uid()` | Reads `request.jwt.claim.sub` (set per test user) |
| `auth.jwt()` | Reads `request.jwt.claims` (used for the two-step login level `aal`) |
| `auth.users`, `auth.mfa_factors` | Minimal tables |
| `storage.buckets`, `storage.objects`, `storage.foldername()` | Minimal tables + function with RLS enabled |
| Realtime publication | `create publication supabase_realtime` |

Then it loads **every production migration in order** and runs the attacks. Switching identity is one
helper:

```js
await as(PLAYER_B, () => q("select * from public.profile_contacts where id = $1", [PLAYER_A]));
```

## Test style

Three assertions keep tests short and precise. Every "should fail" test names the **exact** Postgres
error code, so a test can't pass for the wrong reason:

```js
await err("players can't approve themselves", "42501", () =>
  as(P, () => q("select public.approve_all_entries($1)", [S2])));            // 42501 = insufficient privilege

await err("rooms can't have prizes", "23514", () =>
  as(A, () => q("insert into public.tournaments (name, prize_1_usd_cents) values ('Free money', 1000)")));
                                                                              // 23514 = CHECK violation
await eq("host wins, flagged for a check: 25 points", () =>
  as("anon", async () => (await q("select status, points, kills from public.result_board($1) where squad_id = $2", [S2, wolves])).rows),
  [{ status: "check", points: 25, kills: 10 }]);
```

Custom codes used by the security functions: `PT409` (conflict, e.g. squad full, country locked),
`PT422` (invalid, e.g. disguised upload), `PT429` (rate limited), `PT404` (unknown thing).

## Suites

| Suite | Tests | What it attacks |
| --- | --- | --- |
| `chat` | 82 | Profiles, private contacts, usernames, clans (approval, tags, join requests), chat filter and rate limit, blocks, reports, bans, account deletion |
| `admin` | 25 | Every admin function as visitor, player and admin; report resolution; bans |
| `regions` | 27 | Waitlist fields, sponsor ads (link validation, immutability), admin statistics |
| `tournaments` | 131 | Event creation, host rights, money guards, squads and codes, UIDs, rooms, results bot cross-checks, leaderboards, country chats |
| `push` | 29 | Push endpoint SSRF allowlist, device privacy, secret-checked daily job |
| `events` | 82 | Settings row, sponsored events, approvals, event chats, streamer slots, reports, live prize pool, top-10 rule, permanent country chat, clan switching, ideas board |
| `media` | 24 | Private bucket, own-folder uploads, posting others' files, disguised kinds, size caps, per-chat file access, deleted messages, upload rate limit |
| `mfa` | 16 | Admin powers with password only vs with the second step; status hints; self-promotion |

## Continuous integration

`.github/workflows/security-tests.yml` runs `npm test` on every push and pull request with a read-only
token. A change that weakens a policy breaks the build.

## Limits (honest)

- PGlite is real Postgres, but the Supabase services around it are stand-ins: Realtime delivery,
  the storage server and Supabase Auth itself are not exercised here.
- The application layer (Server Actions, magic-byte check, headers) was verified manually and by type
  checks, linting and builds in the private repo, not by these tests.
- Tests prove the rules do what they say; they can't prove the rules cover every business case.
  That's what the [threat model](threat-model.md) is for.
