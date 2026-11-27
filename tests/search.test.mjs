// Social v4 Stage 1: one search for players and clans (2026-11-27).
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
const ADMIN = id("ad"), A = id("0a"), B = id("0b"), C = id("0c"), D = id("0d");
const names = { [ADMIN]: "Dynasty", [A]: "Alpha", [B]: "Bravo", [C]: "Charlie", [D]: "DynamoKing" };
for (const u of Object.keys(names)) await db.query("insert into auth.users (id) values ($1)", [u]);
await db.query("insert into public.app_admins (user_id) values ($1)", [ADMIN]);

let pass = 0, fail = 0;
async function as(user, fn) {
  if (user === "anon") await db.exec("set role anon; select set_config('request.jwt.claim.sub', '', false)");
  else { await db.exec("set role authenticated"); await db.query("select set_config('request.jwt.claim.sub', $1, false)", [user]); await db.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify({ sub: user, aal: "aal2" })]); }
  try { return await fn(); } finally { await db.exec("reset role"); }
}
const q = (s, p) => db.query(s, p);
async function ok(n, fn) { try { const r = await fn(); pass++; console.log(`PASS  ${n}`); return r; } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }
async function err(n, code, fn) { try { await fn(); fail++; console.log(`FAIL  ${n}: expected ${code}, got success`); } catch (e) { if (e.code === code) { pass++; console.log(`PASS  ${n} (${e.code} ${e.message})`); } else { fail++; console.log(`FAIL  ${n}: expected ${code}, got ${e.code} ${e.message}`); } } }
async function eq(n, fn, exp) { try { const g = await fn(); if (JSON.stringify(g) === JSON.stringify(exp)) { pass++; console.log(`PASS  ${n}`); } else { fail++; console.log(`FAIL  ${n}: got ${JSON.stringify(g)}, expected ${JSON.stringify(exp)}`); } } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }

for (const [u, name] of Object.entries(names)) {
  await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [name]));
}
const search = (who, text) => as(who, async () => (await q("select kind, title from public.search_all($1)", [text])).rows);

await err("visitors can't search", "42501", () => as("anon", () => q("select * from public.search_all('alpha')")));
await eq("a typo still finds the player ('dynasti' → Dynasty)", async () => (await search(A, "dynasti")).filter((r) => r.kind === "player").map((r) => r.title).includes("Dynasty"), true);
await eq("a prefix ranks the closest name first", async () => (await search(A, "dyn")).filter((r) => r.kind === "player")[0].title, "Dynasty");
await eq("you don't find yourself", async () => (await search(A, "alpha")).length, 0);
await eq("one letter returns nothing", async () => (await search(A, "d")).length, 0);
await eq("SQL in the box is just text", async () => (await search(A, "' or 1=1 --")).length, 0);
await ok("Bravo blocks Charlie", () => as(B, () => q("insert into public.user_blocks (blocked_id) values ($1)", [C])));
await eq("…Charlie can't find Bravo", async () => (await search(C, "bravo")).length, 0);
await eq("…and Bravo can't find Charlie", async () => (await search(B, "charlie")).length, 0);
await eq("others still find both", async () => (await search(A, "bravo")).map((r) => r.title), ["Bravo"]);

const clan = await as(B, async () => (await q("insert into public.chat_channels (name, tag) values ('Night Wolves', 'NWLF') returning id")).rows[0].id);
await eq("clans waiting for approval don't show", async () => (await search(A, "night wolves")).filter((r) => r.kind === "clan").length, 0);
await as(ADMIN, () => q("select public.review_clan($1, true)", [clan]));
await eq("an approved clan shows, with its member count", async () => (await as(A, async () => (await q("select title, subtitle from public.search_all('night wolvs')")).rows)).filter((r) => r.title === "Night Wolves"), [{ title: "Night Wolves", subtitle: "1 members" }]);
await eq("…and by its tag", async () => (await search(A, "nwlf")).filter((r) => r.kind === "clan").map((r) => r.title), ["Night Wolves"]);

await ok("60 searches in a minute are fine", async () => { for (let i = 0; i < 60; i++) await search(D, "alpha"); });
await err("…the 61st search in a minute is refused", "PT429", () => search(D, "alpha"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
