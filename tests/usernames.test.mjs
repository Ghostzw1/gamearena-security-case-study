// Usernames with symbols: attack tests (2026-11-26).
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

// --- Usernames with symbols (2026-11-26).
const ch = (code) => String.fromCodePoint(code);
const make = (u, name) => as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [name]));
const rename = (u, name) => as(u, () => q("update public.profiles set username = $1 where id = $2", [name, u]));

await ok("plain name still works", () => make(A, "Ghost"));
await ok("CODM symbols are fine", () => make(B, "꧁Viper亗꧂"));
await ok("fancy letters are fine", () => make(C, "𝕯𝖆𝖗𝖐★"));
await eq("the key ignores symbols and fancy letters", async () => (await one("select private.username_key($1) k", ["꧁𝕲𝖍𝖔𝖘𝖙꧂"])).k, "ghost");
await err("Cyrillic look-alike can't pose as Ghost", "23505", () => make(D, "Gh" + ch(0x43e) + "st"));
await err("small caps can't pose as Ghost", "23505", () => make(D, "ɢʜᴏsᴛ"));
await err("Ø can't pose as Ghost", "23505", () => make(D, "GhØst"));
await err("CODM-font letters can't pose as Ghost", "23505", () => make(D, "Ghㄖ丂ㄒ"));
await err("'★Ghost★' can't pose as Ghost", "23505", () => make(D, "★Ghost★"));
await err("fancy-letter 𝕲𝖍𝖔𝖘𝖙 can't pose as Ghost", "23505", () => make(D, "𝕲𝖍𝖔𝖘𝖙"));
await err("upper/lower case can't pose as Ghost", "23505", () => make(D, "GHOST"));
await err("spaces refused", "23514", () => make(D, "Big Boss"));
await err("zero-width space refused", "23514", () => make(D, "Ali" + ch(0x200b) + "ce"));
await err("text-direction trick refused", "23514", () => make(D, "Ali" + ch(0x202e) + "ce"));
await err("blank Hangul filler refused", "23514", () => make(D, "Ali" + ch(0x3164)));
await err("glitch text (combining marks) refused", "23514", () => make(D, "Zal" + ch(0x0301) + "go"));
await err("HTML characters refused", "23514", () => make(D, "<b>Boss"));
await err("fake clan tag refused", "23514", () => make(D, "[ADM]Boss"));
await err("@ refused (kept for mentions)", "23514", () => make(D, "@Boss"));
await err("symbols only refused (needs 2 letters or numbers)", "23514", () => make(D, "亗亗亗"));
await err("too long refused", "23514", () => make(D, "Abcdefghijklmnopqrstu"));
await ok("D picks a free name", () => make(D, "Delta_7"));

// Sign-up form check (works before signing in).
await eq("taken name: not available, even dressed up", () => as("anon", async () => (await one("select public.is_username_available($1) ok", ["꧁ghost꧂"])).ok), false);
await eq("free fancy name: available", () => as("anon", async () => (await one("select public.is_username_available($1) ok", ["𝕹𝖎𝖓𝖏𝖆"])).ok), true);
await eq("invalid name: not available", () => as("anon", async () => (await one("select public.is_username_available($1) ok", ["a b"])).ok), false);

// Players can't write the key themselves.
await err("the key column can't be set by hand", "428C9", () => as(D, () => q("update public.profiles set username_key = 'ghost' where id = $1", [D])));

// Renames: the key follows, and the old name is free again.
await ok("C renames to a fancy name", () => rename(C, "꧁𝕹𝖎𝖌𝖍𝖙꧂"));
await eq("C's key follows the new name", async () => (await one("select username_key from public.profiles where id = $1", [C])).username_key, "night");
await eq("C's old name is free again", () => as("anon", async () => (await one("select public.is_username_available('Dark') ok")).ok), true);

// Admin finds players by typing the plain letters.
await eq("admin finds ꧁Viper亗꧂ by typing 'viper'", () => as(ADMIN, async () => (await q("select username from public.admin_find_player('viper')")).rows.map((r) => r.username)), ["꧁Viper亗꧂"]);
await eq("non-admins find nobody", () => as(A, async () => (await q("select * from public.admin_find_player('viper')")).rows.length), 0);
await err("visitors can't search players", "42501", () => as("anon", () => q("select * from public.admin_find_player('viper')")));

// Profile changes are rate limited (avatars save on every tap).
let limited = null;
for (let i = 0; i < 25 && !limited; i++) {
  try { await as(A, () => q("update public.profiles set avatar_id = $1 where id = $2", [i % 2 ? "op-recon-m" : "op-recon-f", A])); } catch (e) { limited = { at: i + 1, code: e.code }; }
}
await eq("21st profile change in a minute is refused", () => limited, { at: 21, code: "PT429" });
await eq("someone else isn't slowed down", () => as(B, async () => (await q("update public.profiles set avatar_id = 'op-recon-f' where id = $1", [B])).affectedRows), 1);
await eq("players can't read the rate counters", () => as(A, () => q("select * from private.rate_counters").then(() => "read", (e) => e.code)), "42501");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
