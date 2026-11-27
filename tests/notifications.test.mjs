// Phone notifications (match reminders, room alerts): attack tests (2026-11-26).
import { PGlite } from "@electric-sql/pglite";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Migrations folder: passed by tests/run-all.mjs, or ../migrations when run alone.
const dir = process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "migrations");
const db = new PGlite({ extensions: { pg_trgm } });
await db.exec(`
  create role anon nologin; create role authenticated nologin; create role service_role nologin bypassrls;
  grant usage on schema public to anon, authenticated, service_role;
  alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
  alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
  alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
  create schema auth; create table auth.users (id uuid primary key, email text);
  create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
  grant usage on schema auth to anon, authenticated; grant execute on function auth.uid() to anon, authenticated;
  create publication supabase_realtime;
  create schema storage;
  create function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb) $$;
  grant execute on function auth.jwt() to anon, authenticated;
  create table auth.mfa_factors (id uuid primary key default gen_random_uuid(), user_id uuid not null, factor_type text not null default 'totp', status text not null default 'unverified');
  create table storage.buckets (id text primary key, name text not null, public boolean default false, file_size_limit bigint, allowed_mime_types text[]);
  create table storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text references storage.buckets (id), name text not null, owner uuid default auth.uid(), metadata jsonb, created_at timestamptz default now(), unique (bucket_id, name));
  create function storage.foldername(name text) returns text[] language sql immutable as $$ select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'), 1) - 1] $$;
  alter table storage.objects enable row level security;
  grant usage on schema storage to anon, authenticated;
  grant select, insert, update, delete on storage.objects to anon, authenticated;
  grant select on storage.buckets to anon, authenticated;
`);
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) await db.exec(fs.readFileSync(path.join(dir, f), "utf8"));

const id = (n) => `00000000-0000-0000-0000-0000000000${n}`;
const ADMIN = id("ad"), HOST = id("a1"), STREAM = id("a2"), OUTSIDER = id("77");
const A = id("0a"), B = id("0b"), C = id("0c"), D = id("0d"), E = id("0e"), F = id("0f"), NOPROFILE = id("99");
const names = { [ADMIN]: "Dynasty", [HOST]: "Queen", [STREAM]: "Streamer1", [OUTSIDER]: "Outsider", [A]: "Alpha", [B]: "Bravo", [C]: "Charlie", [D]: "Delta", [E]: "Echo", [F]: "Foxtrot" };
for (const u of [...Object.keys(names), NOPROFILE]) await db.query("insert into auth.users (id) values ($1)", [u]);
await db.query("insert into public.app_admins (user_id) values ($1)", [ADMIN]);

let pass = 0, fail = 0;
async function as(user, fn) {
  if (user === "anon") await db.exec("set role anon; select set_config('request.jwt.claim.sub', '', false)");
  else { await db.exec("set role authenticated"); await db.query("select set_config('request.jwt.claim.sub', $1, false)", [user]); await db.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify({ sub: user, aal: globalThis.AAL ?? "aal2" })]); }
  try { return await fn(); } finally { await db.exec("reset role"); }
}
const q = (s, p) => db.query(s, p);
const one = async (s, p) => (await q(s, p)).rows[0];
async function ok(n, fn) { try { const r = await fn(); pass++; console.log(`PASS  ${n}`); return r; } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }
async function err(n, code, fn) { try { await fn(); fail++; console.log(`FAIL  ${n}: expected ${code}, got success`); } catch (e) { if (e.code === code) { pass++; console.log(`PASS  ${n} (${e.code} ${e.message})`); } else { fail++; console.log(`FAIL  ${n}: expected ${code}, got ${e.code} ${e.message}`); } } }
async function eq(n, fn, exp) { try { const g = await fn(); if (JSON.stringify(g) === JSON.stringify(exp)) { pass++; console.log(`PASS  ${n}`); } else { fail++; console.log(`FAIL  ${n}: got ${JSON.stringify(g)}, expected ${JSON.stringify(exp)}`); } } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }

for (const [u, name] of Object.entries(names)) {
  await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [name]));
}

// --- Setup: cron secret, phones, a tournament in 3 hours and one in 30 minutes.
import crypto from "node:crypto";
const SECRET = "test-cron-secret-0123456789abcdef-xyz";
await db.query("insert into private.app_settings (key, value) values ('cron_secret_sha256', $1)", [crypto.createHash("sha256").update(SECRET).digest("hex")]);
const p256 = "B" + "x".repeat(86), authKey = "a".repeat(22);
const fcm = (k) => `https://fcm.googleapis.com/fcm/send/device-${k}:APA91b_token-${k}`;
const phone = (u, k) => as(u, () => q("select public.save_push_subscription($1, $2, $3)", [fcm(k), p256, authKey]));
for (const [u, k] of [[A, "a"], [C, "c"], [D, "d"], [E, "e"], [F, "f"]]) await phone(u, k);

const LATER = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, season, starts_at, status) values ('community', 'Night Ops', 2, now() + interval '3 hours', 'open') returning id"))).id;
const SOON = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, starts_at, status) values ('community', 'Rush Hour', now() + interval '30 minutes', 'open') returning id"))).id;
const FAR = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, starts_at, status) values ('community', 'Next Week', now() + interval '7 days', 'open') returning id"))).id;
for (const u of [A, B, C]) await as(u, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [LATER]));
await as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [SOON]));
await as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [FAR]));

// --- Settings.
await ok("C switches match reminders off", () => as(C, () => q("insert into public.notification_prefs (match_reminders) values (false)")));
await ok("E switches room alerts on", () => as(E, () => q("insert into public.notification_prefs (room_alerts) values (true)")));
await ok("F switches room alerts on", () => as(F, () => q("insert into public.notification_prefs (room_alerts) values (true)")));
await eq("players only see their own settings", () => as(E, async () => (await q("select user_id from public.notification_prefs")).rows.length), 1);
await err("players can't write someone else's settings", "42501", () => as(B, () => q("insert into public.notification_prefs (user_id, room_alerts) values ($1, true)", [A])));
await eq("players can't change someone else's settings", () => as(B, async () => (await q("update public.notification_prefs set room_alerts = false where user_id = $1", [E])).affectedRows), 0);
await err("visitors can't read settings", "42501", () => as("anon", () => q("select * from public.notification_prefs")));

// --- Match reminders.
await err("no secret, no reminders", "42501", () => as("anon", () => q("select public.queue_due_reminders('wrong-secret-wrong-secret-wrong-secret')")));
await eq("the job queues what's due", () => as("anon", async () => (await one("select public.queue_due_reminders($1) ok", [SECRET])).ok), true);
const mine = async (u) => (await q("select kind, tournament_id from public.notifications where user_id = $1 order by kind", [u])).rows.map((r) => `${r.kind}:${r.tournament_id === LATER ? "later" : r.tournament_id === SOON ? "soon" : "far"}`);
await eq("A: 5-hour reminder for Night Ops, 1-hour one for Rush Hour, nothing for next week", () => mine(A), ["match_1h:soon", "match_5h:later"]);
await eq("B (no phone linked): nothing queued", () => mine(B), []);
await eq("C (reminders off): nothing queued", () => mine(C), []);
await eq("the text says when (5-hour reminder)", async () => (await one("select title, body from public.notifications where user_id = $1 and kind = 'match_5h'", [A])), { title: "Night Ops S2", body: (await one("select 'Starts at ' || to_char(starts_at at time zone 'Africa/Harare', 'HH24:MI') || ' (CAT/SAST), in about 3 hours. Get ready.' b from public.tournaments where id = $1", [LATER])).b });
await eq("a second knock within 5 minutes does nothing", () => as("anon", async () => (await one("select public.queue_due_reminders($1) ok", [SECRET])).ok), false);
await q("update private.app_settings set value = (now() - interval '6 minutes')::text where key = 'notify_last_run'");
await ok("a later run is allowed", () => as("anon", () => q("select public.queue_due_reminders($1)", [SECRET])));
await eq("…and never sends the same reminder twice", async () => (await one("select count(*)::int c from public.notifications where user_id = $1", [A])).c, 2);

// --- Pushes.
await err("no secret, no phone list", "42501", () => as("anon", () => q("select * from public.take_due_pushes('wrong-secret-wrong-secret-wrong-secret')")));
await eq("the server gets A's phone once", () => as("anon", async () => (await q("select * from public.take_due_pushes($1)", [SECRET])).rows.map((r) => r.push_endpoint)), [fcm("a")]);
await eq("…and not again", () => as("anon", async () => (await q("select * from public.take_due_pushes($1)", [SECRET])).rows.length), 0);

// --- The phone reads its messages.
await err("visitors get nothing", "42501", () => as("anon", () => q("select * from public.take_my_notifications()")));
await eq("B has no messages", () => as(B, async () => (await q("select * from public.take_my_notifications()")).rows.length), 0);
await eq("A reads both messages", () => as(A, async () => (await q("select kind from public.take_my_notifications() order by kind")).rows.map((r) => r.kind)), ["match_1h", "match_5h"]);
await eq("…once", () => as(A, async () => (await q("select * from public.take_my_notifications()")).rows.length), 0);
await eq("players only see their own messages", () => as(B, async () => (await q("select * from public.notifications")).rows.length), 0);
await err("players can't write messages", "42501", () => as(B, () => q("insert into public.notifications (user_id, kind, tournament_id, title, body, url) values ($1, 'room', $2, 'Free money', 'Tap here', '/codm/tournaments')", [A, LATER])));
await err("players can't mark messages read by hand", "42501", () => as(A, () => q("update public.notifications set shown_at = null")));

// --- Room alerts.
const ROOM = (await as(D, () => one("insert into public.tournaments (kind, name, mode, format, starts_at, status) values ('scrim', 'Shipment 24/7', 'mp', 'squad', now() + interval '20 minutes', 'open') returning id"))).id;
await err("only the room's creator can send its alert", "42501", () => as(E, () => q("select public.queue_room_alert($1)", [ROOM])));
await err("tournaments aren't rooms", "42501", () => as(ADMIN, () => q("select public.queue_room_alert($1)", [LATER])));
await eq("D alerts the 2 players who want room alerts", () => as(D, async () => (await one("select public.queue_room_alert($1) n", [ROOM])).n), 2);
await eq("E's alert says what and where", async () => (await one("select title, url from public.notifications where user_id = $1 and kind = 'room'", [E])), { title: "New room: Shipment 24/7", url: (await one("select '/codm/tournaments/' || slug u from public.tournaments where id = $1", [ROOM])).u });
await eq("A (alerts off) gets none", async () => (await one("select count(*)::int c from public.notifications where user_id = $1 and kind = 'room'", [A])).c, 0);
await eq("sending it twice doesn't double the alert", () => as(D, async () => (await one("select public.queue_room_alert($1) n", [ROOM])).n), 0);
await eq("the room code isn't in the alert", async () => (await one("select count(*)::int c from public.notifications where kind = 'room' and (body ilike '%password%' and body not ilike '%room code%')")).c, 0);
await ok("a 3rd alert in an hour is still allowed", () => as(D, () => q("select public.queue_room_alert($1)", [ROOM])));
await err("4th alert in an hour is refused", "PT429", () => as(D, () => q("select public.queue_room_alert($1)", [ROOM])));
await q("delete from private.rate_counters where bucket = 'room_alert'");
await q("update public.tournaments set created_at = now() - interval '20 minutes' where id = $1", [ROOM]);
await err("an old room can't send alerts", "PT409", () => as(D, () => q("select public.queue_room_alert($1)", [ROOM])));
await eq("E's phone is on the next push list", () => as("anon", async () => (await q("select * from public.take_due_pushes($1) order by 1", [SECRET])).rows.map((r) => r.push_endpoint)), [fcm("e"), fcm("f")]);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
