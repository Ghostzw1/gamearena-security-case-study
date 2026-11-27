// Admin two-step login: attack tests.
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

const ADMIN = "00000000-0000-0000-0000-0000000000ad", P = "00000000-0000-0000-0000-00000000000a";
for (const u of [ADMIN, P]) await db.query("insert into auth.users (id) values ($1)", [u]);
await db.query("insert into public.app_admins (user_id) values ($1)", [ADMIN]);

let pass = 0, fail = 0;
async function as(user, fn) {
  if (user === "anon") await db.exec("set role anon; select set_config('request.jwt.claim.sub', '', false)");
  else { await db.exec("set role authenticated"); await db.query("select set_config('request.jwt.claim.sub', $1, false)", [user]); await db.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify({ sub: user, aal: globalThis.AAL ?? "aal2" })]); }
  try { return await fn(); } finally { await db.exec("reset role"); }
}
const q = (s, p) => db.query(s, p);
const one = async (s, p) => (await q(s, p)).rows[0];
async function err(n, code, fn) { try { await fn(); fail++; console.log(`FAIL  ${n}: expected ${code}, got success`); } catch (e) { if (e.code === code) { pass++; console.log(`PASS  ${n} (${e.code} ${e.message})`); } else { fail++; console.log(`FAIL  ${n}: expected ${code}, got ${e.code} ${e.message}`); } } }
async function eq(n, fn, exp) { try { const g = await fn(); if (JSON.stringify(g) === JSON.stringify(exp)) { pass++; console.log(`PASS  ${n}`); } else { fail++; console.log(`FAIL  ${n}: got ${JSON.stringify(g)}, expected ${JSON.stringify(exp)}`); } } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }
const step = (level, user, fn) => { globalThis.AAL = level; return as(user, fn).finally(() => { globalThis.AAL = undefined; }); };

await step("aal2", ADMIN, () => q("insert into public.profiles (username, avatar_id) values ('Dynasty', 'op-recon-m')"));
await step("aal1", P, () => q("insert into public.profiles (username, avatar_id) values ('Player', 'op-recon-m')"));

// Password only (aal1)
await eq("admin without a 2FA app: status needs_setup", () => step("aal1", ADMIN, async () => (await one("select public.admin_status() s")).s), "needs_setup");
await eq("password only: not an admin", () => step("aal1", ADMIN, async () => (await one("select public.am_i_admin() a")).a), false);
await err("password only: admin functions refused", "42501", () => step("aal1", ADMIN, () => q("select * from public.admin_stats()")));
await err("password only: can't change settings", "42501", async () => { const r = await step("aal1", ADMIN, () => q("update public.app_config set top10_rule = false")); if (r.affectedRows === 0) { const e = new Error("no rows"); e.code = "42501"; throw e; } });
await err("password only: can't create prize tournaments", "42501", () => step("aal1", ADMIN, () => q("insert into public.tournaments (kind, name) values ('tournament', 'Sneaky Cup')")));
await eq("password only: can't read other countries' chats", () => step("aal1", ADMIN, async () => (await one("select private.can_read_channel(id) r from public.chat_channels where slug = 'codm-za'")).r), false);

// App set up, code not entered yet
await db.query("insert into auth.mfa_factors (user_id, factor_type, status) values ($1, 'totp', 'verified')", [ADMIN]);
await eq("after setting up the app: status needs_code", () => step("aal1", ADMIN, async () => (await one("select public.admin_status() s")).s), "needs_code");
await eq("still no admin powers before the code", () => step("aal1", ADMIN, async () => (await one("select public.am_i_admin() a")).a), false);

// Code entered (aal2)
await eq("with the code: status ok", () => step("aal2", ADMIN, async () => (await one("select public.admin_status() s")).s), "ok");
await eq("with the code: admin", () => step("aal2", ADMIN, async () => (await one("select public.am_i_admin() a")).a), true);
await eq("with the code: admin functions work", () => step("aal2", ADMIN, async () => (await q("select * from public.admin_stats()")).rows.length), 1);

// Normal players
await eq("players: status none (no hint they could be admin)", () => step("aal2", P, async () => (await one("select public.admin_status() s")).s), "none");
await eq("a player with aal2 is still not an admin", () => step("aal2", P, async () => (await one("select public.am_i_admin() a")).a), false);
await err("visitors can't ask for admin status", "42501", () => as("anon", () => q("select public.admin_status()")));
await err("players can't make themselves admin", "42501", () => step("aal2", P, () => q("insert into public.app_admins (user_id) values ($1)", [P])));
await err("players can't read the 2FA factors", "42501", () => step("aal2", P, () => q("select * from auth.mfa_factors")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
