// Stage 3 player identity: profiles, privacy, history, achievements, search (2026-11-27).
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
const setp = (u, col, val) => as(u, () => q(`update public.profiles set ${col} = $1 where id = $2`, [val, u]));
await ok("Alpha opens their profile to everyone", () => setp(A, "profile_visibility", "everyone"));
await ok("Bravo makes theirs private", () => setp(B, "profile_visibility", "private"));
await ok("Alpha writes a bio", () => setp(A, "bio", "IGL. Shipment enjoyer. Zim represent."));
await err("bios over 160 characters are refused", "23514", () => setp(A, "bio", "x".repeat(161)));
await err("hidden characters in a bio are refused", "23514", () => setp(A, "bio", "Hi" + String.fromCodePoint(0x202e) + "there"));
await err("unknown visibility refused", "23514", () => setp(C, "profile_visibility", "secret"));
await eq("players can't edit someone else's bio", () => as(B, async () => (await q("update public.profiles set bio = 'hacked' where id = $1", [A])).affectedRows), 0);

// --- A solo tournament with confirmed results (the admin created it, so hosts it).
const T = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, format, max_players, status) values ('community', 'Proving Grounds', 'solo', 20, 'open') returning id"))).id;
for (const u of [A, B, C, D]) await as(u, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T]));
for (const u of [A, B, C, D]) await as(ADMIN, () => q("select public.set_entry_status($1, $2, 'approved')", [T, u]));
await as(ADMIN, () => q("update public.tournaments set status = 'live' where id = $1", [T]));
const host = (m, u, place, kills) => as(ADMIN, () => q("insert into public.match_results (tournament_id, match_no, player_id, placement, kills) values ($1, $2, $3, $4, $5)", [T, m, u, place, kills]));
await host(1, A, 1, 5); await host(1, B, 2, 3); await host(1, C, 3, 0);
await host(2, A, 2, 2); await host(2, B, 1, 1); await host(2, C, 4, 1);
// D only claims a result: never counts.
await as(D, () => q("insert into public.match_results (tournament_id, match_no, player_id, placement, kills) values ($1, 1, $2, 1, 20)", [T, D]));
await as(ADMIN, () => q("update public.tournaments set status = 'completed' where id = $1", [T]));
// Stage 5: results count once they're final (an admin locks them here).
await as(ADMIN, () => q("select public.lock_results($1)", [T]));

// --- Profile cards and privacy.
const card = (who, key) => as(who, async () => (await q("select limited, bio, username from public.player_card($1)", [key])).rows);
await eq("visitors see an 'everyone' profile", () => card("anon", "alpha"), [{ limited: false, bio: "IGL. Shipment enjoyer. Zim represent.", username: "Alpha" }]);
await eq("visitors don't see a players-only profile", () => card("anon", "charlie"), []);
await eq("players see Charlie (players-only)", async () => (await card(A, "charlie"))[0]?.limited, false);
await eq("a private profile shows name and avatar only", () => card(C, "bravo"), [{ limited: true, bio: null, username: "Bravo" }]);
await eq("Bravo sees their own private profile in full", async () => (await card(B, "bravo"))[0]?.limited, false);
await eq("admins see private profiles in full", async () => (await card(ADMIN, "bravo"))[0]?.limited, false);
await eq("fancy letters and symbols find the same player", async () => (await card(C, "꧁𝕬𝖑𝖕𝖍𝖆꧂"))[0]?.username, "Alpha");

// --- History from confirmed results only.
const hist = (who, u) => as(who, async () => (await q("select slug, rank, teams, points, kills, wins, matches from public.player_history($1)", [u])).rows.map((r) => [r.rank, r.teams, r.points, r.kills, r.wins, r.matches]));
await eq("Alpha: 1st of 3, 20 + 14 = 34 points, 7 kills, 1 win, 2 matches", () => hist("anon", A), [[1, 3, 34, 7, 1, 2]]);
await eq("Charlie: 3rd of 3 (10 + 9 = 19 points)", () => hist(A, C), [[3, 3, 19, 1, 0, 2]]);
await eq("Delta's own claim doesn't count: no rank, 0 matches", () => hist(D, D), [[null, null, 0, 0, 0, 0]]);
await eq("Bravo's history is hidden from others (private)", () => hist(C, B), []);
await eq("…and from visitors", () => hist("anon", C), []);

// --- Achievements need evidence.
const badges = (who, u) => as(who, async () => (await q("select code from public.player_achievements($1) order by code", [u])).rows.map((r) => r.code));
await eq("Alpha: first tournament, first win, podium, champion", () => badges("anon", A), ["champion", "first_tournament", "first_win", "podium"]);
await eq("Bravo (2nd): first tournament, first win, podium", () => badges(B, B), ["first_tournament", "first_win", "podium"]);
await eq("Delta (claim only): just first tournament", () => badges(D, D), ["first_tournament"]);
await eq("Echo (never played): nothing", () => badges(E, E), []);
const idea = (await as(E, () => one("insert into public.ideas (body) values ('Add a duo ladder please') returning id"))).id;
await eq("an open idea earns nothing yet", () => badges(E, E), []);
await as(ADMIN, () => q("update public.ideas set status = 'planned' where id = $1", [idea]));
await eq("a planned idea earns Community contributor", () => badges(E, E), ["contributor"]);

// --- Finding players.
await err("visitors can't search players", "42501", () => as("anon", () => q("select * from public.search_players('alp')")));
await eq("'alp' finds Alpha", () => as(C, async () => (await q("select username from public.search_players('alp')")).rows.map((r) => r.username)), ["Alpha"]);
await eq("one letter is too short to search", () => as(C, async () => (await q("select * from public.search_players('a')")).rows.length), 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
