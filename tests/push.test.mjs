// Push reminders: attack tests.
import { PGlite } from "@electric-sql/pglite";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Migrations folder: passed by tests/run-all.mjs, or ../migrations when run alone.
const dir = process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "migrations");
const db = new PGlite();
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
const A = id("0a"), B = id("0b"), C = id("0c");
for (const [u, name] of [[A, "Alpha"], [B, "Bravo"], [C, "Charlie"]]) {
  await db.query("insert into auth.users (id) values ($1)", [u]);
}
let pass = 0, fail = 0;
async function as(user, fn) {
  if (user === "anon") await db.exec("set role anon; select set_config('request.jwt.claim.sub', '', false)");
  else { await db.exec("set role authenticated"); await db.query("select set_config('request.jwt.claim.sub', $1, false)", [user]); await db.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify({ sub: user, aal: globalThis.AAL ?? "aal2" })]); }
  try { return await fn(); } finally { await db.exec("reset role"); }
}
const q = (s, p) => db.query(s, p);
async function ok(n, fn) { try { const r = await fn(); pass++; console.log(`PASS  ${n}`); return r; } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }
async function err(n, code, fn) { try { await fn(); fail++; console.log(`FAIL  ${n}: expected ${code}, got success`); } catch (e) { if (e.code === code) { pass++; console.log(`PASS  ${n} (${e.code} ${e.message})`); } else { fail++; console.log(`FAIL  ${n}: expected ${code}, got ${e.code} ${e.message}`); } } }
async function eq(n, fn, exp) { try { const g = await fn(); if (JSON.stringify(g) === JSON.stringify(exp)) { pass++; console.log(`PASS  ${n}`); } else { fail++; console.log(`FAIL  ${n}: got ${JSON.stringify(g)}, expected ${JSON.stringify(exp)}`); } } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }

for (const [u, name] of [[A, "Alpha"], [B, "Bravo"], [C, "Charlie"]]) await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [name]));

const SECRET = crypto.randomBytes(32).toString("hex");
await db.query("insert into private.app_settings (key, value) values ('cron_secret_sha256', $1)", [crypto.createHash("sha256").update(SECRET).digest("hex")]);

const p256 = "B" + "x".repeat(86);
const authKey = "a".repeat(22);
const fcm = (n) => `https://fcm.googleapis.com/fcm/send/device-${n}:APA91b_token-${n}`;
const save = (u, endpoint) => as(u, () => q("select public.save_push_subscription($1, $2, $3)", [endpoint, p256, authKey]));
const S2 = (await q("select id from public.tournaments where slug = 'warzone-unleashed-s2'")).rows[0].id;

// Saving devices
await ok("A saves a Chrome (FCM) device", () => save(A, fcm(1)));
await ok("B saves a Firefox device", () => save(B, "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABtoken"));
await ok("C saves an Apple device", () => save(C, "https://web.push.apple.com/QGzZ1xnJ7Y8token"));
await err("SSRF: internal address rejected", "23514", () => save(A, "https://169.254.169.254/latest/meta-data"));
await err("SSRF: look-alike host rejected", "23514", () => save(A, "https://fcm.googleapis.com.evil.example/send/x"));
await err("plain http rejected", "23514", () => save(A, "http://fcm.googleapis.com/fcm/send/x"));
await err("bad keys rejected", "23514", () => as(A, () => q("select public.save_push_subscription($1, 'short', 'x')", [fcm(9)])));
await err("visitors can't save devices", "42501", () => as("anon", () => q("select public.save_push_subscription($1, $2, $3)", [fcm(8), p256, authKey])));
await err("players can't insert rows directly", "42501", () => as(A, () => q("insert into public.push_subscriptions (endpoint, p256dh, auth) values ($1, $2, $3)", [fcm(7), p256, authKey])));
for (const n of [2, 3, 4, 5]) await save(A, fcm(n));
await err("6th device rejected", "PT429", () => save(A, fcm(6)));
await ok("saving the same device again is fine", () => save(A, fcm(1)));

// Privacy
await eq("A sees only their own devices", () => as(A, async () => (await q("select endpoint from public.push_subscriptions")).rows.length), 5);
await err("players can't read the push keys", "42501", () => as(A, () => q("select p256dh from public.push_subscriptions")));
await err("visitors can't list devices", "42501", () => as("anon", () => q("select endpoint from public.push_subscriptions")));
await eq("B can't delete A's device", () => as(B, async () => (await q("delete from public.push_subscriptions where endpoint = $1", [fcm(1)])).affectedRows), 0);
await err("nobody can read the cron secret hash", "42501", () => as(A, () => q("select * from private.app_settings")));

// Shared phone: device moves to the new account
await ok("B signs in on A's phone and turns reminders on", () => save(B, fcm(5)));
await eq("the device now belongs to B", () => as(B, async () => (await q("select endpoint from public.push_subscriptions where endpoint = $1", [fcm(5)])).rows.length), 1);

// Daily job
await err("job without secret refused", "42501", () => as("anon", () => q("select * from public.due_push_reminders(null)")));
await err("job with wrong secret refused", "42501", () => as("anon", () => q("select * from public.due_push_reminders($1)", ["f".repeat(64)])));
await err("players can't call the job either without the secret", "42501", () => as(A, () => q("select * from public.due_push_reminders($1)", ["x".repeat(40)])));
await as(C, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2]));
const due = await ok("job with the right secret gets today's devices", () => as("anon", async () => (await q("select push_endpoint from public.due_push_reminders($1) order by 1", [SECRET])).rows.map((r) => r.push_endpoint)));
await eq("registered player C isn't reminded; A (4) and B (2) are", async () => due?.length, 6);
await eq("nobody is reminded twice in a day", () => as("anon", async () => (await q("select * from public.due_push_reminders($1)", [SECRET])).rows.length), 0);
await ok("job forgets a dead device", () => as("anon", () => q("select public.forget_push_subscription($1, $2)", [SECRET, fcm(2)])));
await err("forget without secret refused", "42501", () => as("anon", () => q("select public.forget_push_subscription($1, $2)", ["nope", fcm(3)])));
await eq("dead device is gone", () => as(A, async () => (await q("select 1 from public.push_subscriptions where endpoint = $1", [fcm(2)])).rows.length), 0);
await ok("no open tournament → nobody reminded", async () => {
  await db.query("update public.tournaments set status = 'live' where id = $1", [S2]);
  await db.query("update public.push_subscriptions set last_sent_at = null");
  const r = await as("anon", () => q("select * from public.due_push_reminders($1)", [SECRET]));
  if (r.rows.length) throw new Error(`${r.rows.length} reminded`);
});
await ok("deleting an account removes its devices", async () => {
  await db.query("delete from auth.users where id = $1", [A]);
  const r = await db.query("select 1 from public.push_subscriptions where user_id = $1", [A]);
  if (r.rows.length) throw new Error("devices left behind");
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
