// Stage 1 trust fixes: sponsor truth, no fake prizes, status moves, capacity (2026-11-26).
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

// --- Warzone Unleashed: sponsor not confirmed (owner, 2026-11-26).
await eq("Warzone S2: sponsorship pending, no sponsor name", async () => await one("select sponsor_name, sponsor_status from public.tournaments where slug = 'warzone-unleashed-s2'"), { sponsor_name: null, sponsor_status: "pending" });
await eq("Warzone S1 too", async () => (await one("select sponsor_status from public.tournaments where slug = 'warzone-unleashed-s1'")).sponsor_status, "pending");
await eq("event cards carry the sponsor status", () => as("anon", async () => (await one("select sponsor_status from public.event_cards() where slug = 'warzone-unleashed-s2'")).sponsor_status), "pending");

// --- No fake prizes, fees or sponsors on rooms players create.
const room = (u, extra = "", vals = []) => as(u, () => one(`insert into public.tournaments (kind, name${extra ? ", " + extra.split("=")[0] : ""}) values ('scrim', 'Night Room'${extra ? ", $1" : ""}) returning id`, vals));
await err("a room with a $500 prize is refused", "42501", () => room(A, "prize_1_usd_cents=", [50000]));
await err("a room with an entry fee is refused", "42501", () => room(A, "entry_fee_usd_cents=", [200]));
await err("a room claiming a sponsor is refused", "42501", () => room(A, "sponsor_name=", ["Econet"]));
await err("a room marked 'sponsorship pending' is refused", "42501", () => room(A, "sponsor_status=", ["pending"]));
const R1 = (await ok("a plain free room is fine", () => room(A)))?.id;
await err("the room's host can't add a sponsor later", "42501", () => as(A, () => q("update public.tournaments set sponsor_name = 'Econet', sponsor_status = 'confirmed' where id = $1", [R1])));
await err("a confirmed sponsor needs a name", "23514", () => as(ADMIN, () => q("update public.tournaments set sponsor_status = 'confirmed', sponsor_name = null where id = $1", [R1])));
await ok("admins can confirm a real sponsor", () => as(ADMIN, () => q("update public.tournaments set sponsor_name = 'Econet', sponsor_status = 'confirmed' where id = $1", [R1])));

// --- Status moves.
await ok("host opens… (open → live)", () => as(A, () => q("update public.tournaments set status = 'live' where id = $1", [R1])));
await ok("…and finishes (live → completed)", () => as(A, () => q("update public.tournaments set status = 'completed' where id = $1", [R1])));
await err("a finished room can't be reopened by its host", "PT409", () => as(A, () => q("update public.tournaments set status = 'open' where id = $1", [R1])));
await ok("admins can correct it", () => as(ADMIN, () => q("update public.tournaments set status = 'open' where id = $1", [R1])));
const R2 = (await room(B))?.id;
await ok("open → upcoming (pause registration) is allowed", () => as(B, () => q("update public.tournaments set status = 'upcoming' where id = $1", [R2])));
await err("upcoming → completed (skipping the match) is refused", "PT409", () => as(B, () => q("update public.tournaments set status = 'completed' where id = $1", [R2])));
await err("other players can't change it at all", "42501", () => as(C, async () => { const r = await q("update public.tournaments set status = 'open' where id = $1", [R2]); if (r.affectedRows === 0) throw Object.assign(new Error("no rows"), { code: "42501" }); }));

// --- Capacity: only pending + approved entries count.
const CUP = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, max_players, status) values ('community', 'Tiny Cup', 2, 'open') returning id"))).id;
await as(ADMIN, () => q("update public.tournaments set requires_approval = true where id = $1", [CUP]));
await ok("A registers (1 of 2)", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await err("A can't register twice", "23505", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await ok("B registers (2 of 2)", () => as(B, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await err("C is refused: full", "PT409", () => as(C, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await ok("admin rejects B", () => as(ADMIN, () => q("select public.set_entry_status($1, $2, 'rejected')", [CUP, B])));
await ok("C gets B's place: rejected entries don't count", () => as(C, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await err("D is refused: full again", "PT409", () => as(D, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
