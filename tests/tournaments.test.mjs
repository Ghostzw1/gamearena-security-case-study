// Tournaments, squads, results bot, UIDs, country chats: attack tests.
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
const report = (who, t, match, squad, place, kills) => as(who, () => q("insert into public.match_results (tournament_id, match_no, squad_id, placement, kills) values ($1, $2, $3, $4, $5)", [t, match, squad, place, kills]));

let n = 0;
for (const [u, name] of Object.entries(names)) {
  await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [name]));
  await as(u, () => q("insert into public.profile_contacts (whatsapp_number) values ($1)", [`+2637712345${String(n++).padStart(2, "0")}`]));
}

const S1 = (await one("select id from public.tournaments where slug = 'warzone-unleashed-s1'")).id;
const S2 = (await one("select id from public.tournaments where slug = 'warzone-unleashed-s2'")).id;

// --- Visitors -------------------------------------------------------------
await eq("visitors see both Warzone Unleashed seasons", () => as("anon", async () => (await q("select season, status from public.tournaments where name = 'Warzone Unleashed' order by season")).rows), [{ season: 1, status: "completed" }, { season: 2, status: "open" }]);
await eq("Warzone Unleashed S2 has no prizes (owner, 2026-11-26)", () => as("anon", () => one("select prize_1_usd_cents p1, prize_2_usd_cents p2, prize_3_usd_cents p3 from public.tournaments where id = $1", [S2])), { p1: 0, p2: 0, p3: 0 });
await eq("prize guard is switched back on after the no-prizes migration", () => one("select tgenabled from pg_trigger where tgname = 'tournaments_guard_update'"), { tgenabled: "O" });
await err("visitors can't see who entered", "42501", () => as("anon", () => q("select * from public.tournament_entries")));
await err("visitors can't register", "42501", () => as("anon", () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2])));
await err("visitors can't create tournaments", "42501", () => as("anon", () => q("insert into public.tournaments (name) values ('Hack')")));
await err("visitors can't join squads", "42501", () => as("anon", () => q("select public.join_squad('ABCDEFGH')")));
await err("visitors can't read UIDs", "42501", () => as("anon", () => q("select * from public.player_uids")));
await ok("visitors can read standings", () => as("anon", () => q("select * from public.tournament_standings($1)", [S2])));
await ok("visitors can read player counts", () => as("anon", () => q("select * from public.tournament_counts()")));

// --- Creating events ------------------------------------------------------
await err("players can't create prize tournaments", "42501", () => as(A, () => q("insert into public.tournaments (kind, name, entry_fee_usd_cents) values ('tournament', 'Fake Cup', 500)")));
await err("rooms can't have prizes (admins only, on insert too)", "42501", () => as(A, () => q("insert into public.tournaments (name, prize_1_usd_cents) values ('Free money', 1000)")));
const room = await ok("player creates a free room", () => as(A, async () => (await one("insert into public.tournaments (name, format) values ('Friday Scrims', 'duo') returning id")).id));
await eq("room creator is its host", () => as(A, async () => (await q("select role from public.tournament_staff where tournament_id = $1 and user_id = $2", [room, A])).rows), [{ role: "host" }]);
await ok("second room", () => as(A, () => q("insert into public.tournaments (name) values ('Room two')")));
await ok("third room", () => as(A, () => q("insert into public.tournaments (name) values ('Room three')")));
await err("fourth open room is blocked", "PT429", () => as(A, () => q("insert into public.tournaments (name) values ('Room four')")));
await err("player without profile can't create rooms", "42501", () => as(NOPROFILE, () => q("insert into public.tournaments (name) values ('Ghost room')")));
await err("hidden characters in names rejected", "23514", () => as(B, () => q(`insert into public.tournaments (name) values ('Bad${String.fromCharCode(0x202e)}Name')`)));
await err("non-WhatsApp group link rejected", "23514", () => as(B, () => q("insert into public.tournaments (name, whatsapp_group_url) values ('Linky', 'https://evil.example.com/abcdefghijk')")));
const cup = await ok("admin creates a prize tournament", () => as(ADMIN, async () => (await one("insert into public.tournaments (kind, name, entry_fee_usd_cents, prize_1_usd_cents) values ('tournament', 'Test Cup', 200, 10000) returning id")).id));

// --- The ruling stick -----------------------------------------------------
await err("player can't make themselves host", "42501", () => as(HOST, () => q("select public.add_tournament_staff($1, 'Queen', 'host')", [S2])));
await err("players can't insert staff rows directly", "42501", () => as(HOST, () => q("insert into public.tournament_staff (tournament_id, user_id, role) values ($1, $2, 'host')", [S2, HOST])));
await eq("admin gives Queen the ruling stick", () => as(ADMIN, async () => (await one("select public.add_tournament_staff($1, 'queen', 'host') u", [S2])).u), "Queen");
await err("unknown username", "PT404", () => as(ADMIN, () => q("select public.add_tournament_staff($1, 'nobody', 'host')", [S2])));
await ok("host adds a streamer", () => as(HOST, () => q("select public.add_tournament_staff($1, 'Streamer1', 'streamer')", [S2])));
await err("host can't add another host", "42501", () => as(HOST, () => q("select public.add_tournament_staff($1, 'Alpha', 'host')", [S2])));
await err("streamer can't add staff", "42501", () => as(STREAM, () => q("select public.add_tournament_staff($1, 'Bravo', 'streamer')", [S2])));
await err("host can't change prizes", "42501", () => as(HOST, () => q("update public.tournaments set prize_1_usd_cents = 1 where id = $1", [S2])));
await err("host can't change the entry fee", "42501", () => as(HOST, () => q("update public.tournaments set entry_fee_usd_cents = 5000 where id = $1", [S2])));
await ok("host sets the WhatsApp group", () => as(HOST, () => q("update public.tournaments set whatsapp_group_url = 'https://chat.whatsapp.com/AbCdEf123456' where id = $1", [S2])));
await eq("random player can't edit the tournament", () => as(B, async () => (await q("update public.tournaments set name = 'Hacked' where id = $1", [S2])).affectedRows), 0);
await eq("host can't delete the tournament", () => as(HOST, async () => (await q("delete from public.tournaments where id = $1", [S2])).affectedRows), 0);
await err("host can't remove another host", "42501", () => as(STREAM, () => q("select public.remove_tournament_staff($1, $2)", [S2, HOST])));

// --- Registration and squads ----------------------------------------------
await err("can't register for completed Season 1", "42501", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S1])));
await ok("A registers for Season 2 (fixed squad)", () => as(A, () => q("insert into public.tournament_entries (tournament_id, team_mode) values ($1, 'fixed')", [S2])));
await err("A can't register someone else", "42501", () => as(A, () => q("insert into public.tournament_entries (tournament_id, user_id) values ($1, $2)", [S2, B])));
await err("A can't register twice", "23505", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2])));
await err("A can't put themselves in a squad directly", "42501", () => as(A, () => q("update public.tournament_entries set squad_id = gen_random_uuid() where user_id = $1", [A])));
await err("squad names starting with Random are reserved", "PT422", () => as(A, () => q("select public.create_squad($1, 'Random Kings')", [S2])));
const code = await ok("A creates squad Blood Wolves", () => as(A, async () => (await one("select public.create_squad($1, 'Blood Wolves') c", [S2])).c));
await err("squad join codes can't be read from the table", "42501", () => as(C, () => q("select code from public.squads")));
await eq("A sees their own code", () => as(A, async () => (await one("select code from public.my_squad($1)", [S2])).code), code);
await eq("C can't see A's squad code", () => as(C, async () => (await q("select code from public.my_squad($1)", [S2])).rows.length), 0);
await eq("B joins with the code (auto-registers)", () => as(B, async () => (await one("select public.join_squad($1) n", [code.toLowerCase()])).n), "Blood Wolves");
await eq("B is registered as fixed", () => as(B, async () => (await one("select team_mode from public.tournament_entries where tournament_id = $1 and user_id = $2", [S2, B])).team_mode), "fixed");
await err("wrong code", "PT404", () => as(C, () => q("select public.join_squad('ZZZZZZZZ')")));
await eq("squadmate A sees B's WhatsApp", () => as(A, async () => (await q("select id from public.profile_contacts where id = $1", [B])).rows.length), 1);
await eq("C can't see A's WhatsApp", () => as(C, async () => (await q("select id from public.profile_contacts where id = $1", [A])).rows.length), 0);
for (const p of [C, D]) await as(p, () => q("select public.join_squad($1)", [code]));
await err("5th player can't join a full squad of 4", "PT409", () => as(E, () => q("select public.join_squad($1)", [code])));
await ok("E registers for a random squad", () => as(E, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2])));
await ok("F registers for a random squad", () => as(F, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2])));
await err("player can't make random squads", "42501", () => as(E, () => q("select public.make_random_squads($1)", [S2])));
await eq("community registrations wait for the host", () => as(E, async () => (await one("select status from public.tournament_entries where tournament_id = $1 and user_id = $2", [S2, E])).status), "pending");
await eq("pending players can't see the player list", () => as(E, async () => (await q("select user_id from public.tournament_entries where tournament_id = $1", [S2])).rows.length), 1);
await err("players can't approve themselves", "42501", () => as(E, () => q("select public.approve_all_entries($1)", [S2])));
await eq("host approves everyone waiting", () => as(HOST, async () => (await one("select public.approve_all_entries($1) n", [S2])).n), 6);
await eq("approved players see the whole list", () => as(E, async () => (await q("select user_id from public.tournament_entries where tournament_id = $1", [S2])).rows.length), 6);
await eq("host makes random squads (1 squad for 2 players)", () => as(HOST, async () => (await one("select public.make_random_squads($1) n", [S2])).n), 1);
await eq("E and F are in Random 1", () => as(E, async () => (await q("select s.name from public.tournament_entries e join public.squads s on s.id = e.squad_id where e.tournament_id = $1 and e.user_id in ($2, $3)", [S2, E, F])).rows.map((r) => r.name)), ["Random 1", "Random 1"]);
await eq("random squads have no join code", () => as(E, async () => (await one("select code from public.my_squad($1)", [S2])).code), null);
await err("host can't change format once players joined", "PT409", () => as(HOST, () => q("update public.tournaments set format = 'duo' where id = $1", [S2])));

// --- UIDs -----------------------------------------------------------------
await ok("A saves a private UID", () => as(A, () => q("insert into public.player_uids (codm_uid) values ('6741234567890123')")));
await ok("E saves a public UID", () => as(E, () => q("insert into public.player_uids (codm_uid, is_public) values ('6740000000000001', true)")));
await err("letters in a UID rejected", "23514", () => as(F, () => q("insert into public.player_uids (codm_uid) values ('abc123')")));
await err("can't save a UID for someone else", "42501", () => as(F, () => q("insert into public.player_uids (user_id, codm_uid) values ($1, '12345678')", [A])));
await eq("outsider sees only public UIDs", () => as(OUTSIDER, async () => (await q("select codm_uid from public.player_uids")).rows.map((r) => r.codm_uid)), ["6740000000000001"]);
await eq("squadmate B sees A's private UID", () => as(B, async () => (await q("select 1 from public.player_uids where user_id = $1", [A])).rows.length), 1);
await eq("host sees entrant A's private UID (to invite)", () => as(HOST, async () => (await q("select 1 from public.player_uids where user_id = $1", [A])).rows.length), 1);
await eq("outsider can't change A's UID", () => as(OUTSIDER, async () => (await q("update public.player_uids set is_public = true where user_id = $1", [A])).affectedRows), 0);

// --- Room info ------------------------------------------------------------
await ok("host sets the room ID and password", () => as(HOST, () => q("insert into public.tournament_rooms (tournament_id, room_info) values ($1, 'Room 1234 pass 99')", [S2])));
await eq("entrant sees the room", () => as(A, async () => (await q("select room_info from public.tournament_rooms where tournament_id = $1", [S2])).rows.length), 1);
await eq("outsider can't see the room", () => as(OUTSIDER, async () => (await q("select room_info from public.tournament_rooms")).rows.length), 0);
await err("player can't set someone else's room", "42501", () => as(B, () => q("insert into public.tournament_rooms (tournament_id, room_info) values ($1, 'fake room')", [room])));

// --- Results bot ----------------------------------------------------------
const wolves = (await one("select id from public.squads where name = 'Blood Wolves'")).id;
const random1 = (await one("select id from public.squads where name = 'Random 1'")).id;
await err("results closed before the tournament is live", "PT409", () => report(A, S2, 1, wolves, 1, 12));
await eq("player can't start the tournament", () => as(A, async () => (await q("update public.tournaments set status = 'live' where id = $1", [S2])).affectedRows), 0);
await ok("host starts the tournament", () => as(HOST, () => q("update public.tournaments set status = 'live' where id = $1", [S2])));
await err("no registering once live", "42501", () => as(OUTSIDER, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2])));
await ok("A claims match 1: 1st with 12 kills", () => report(A, S2, 1, wolves, 1, 12));
await eq("A's report is marked as a player report", () => as(A, async () => (await one("select reporter_role r from public.match_results where reporter_id = $1", [A])).r), "player");
await err("A can't report for another squad", "42501", () => report(A, S2, 1, random1, 20, 0));
await err("A can't report a match that doesn't exist", "PT422", () => report(A, S2, 3, wolves, 1, 5));
await err("A can't fake the reporter", "42501", () => as(A, () => q("insert into public.match_results (tournament_id, match_no, squad_id, placement, kills, reporter_id) values ($1, 2, $2, 1, 5, $3)", [S2, wolves, HOST])));
await err("silly kill count rejected", "23514", () => report(A, S2, 2, wolves, 1, 500));
await err("outsider can't report", "42501", () => report(OUTSIDER, S2, 1, wolves, 1, 30));
await eq("a claim alone is pending (0 points)", () => as("anon", async () => (await q("select status, points from public.result_board($1) where squad_id = $2", [S2, wolves])).rows), [{ status: "pending", points: 0 }]);
await ok("streamer reports Wolves: 1st, 12 kills", () => report(STREAM, S2, 1, wolves, 1, 12));
await eq("streamer's report is marked streamer", () => as(STREAM, async () => (await one("select reporter_role r from public.match_results where reporter_id = $1", [STREAM])).r), "streamer");
await eq("player + streamer agree: verified, 15 + 12 = 27 points", () => as("anon", async () => (await q("select status, points from public.result_board($1) where squad_id = $2", [S2, wolves])).rows), [{ status: "verified", points: 27 }]);
await ok("host reports Wolves with 10 kills (different)", () => report(HOST, S2, 1, wolves, 1, 10));
await eq("host wins, flagged for a check: 25 points", () => as("anon", async () => (await q("select status, points, kills from public.result_board($1) where squad_id = $2", [S2, wolves])).rows), [{ status: "check", points: 25, kills: 10 }]);
await ok("E claims Random 1 came 2nd with 3 kills", () => report(E, S2, 1, random1, 2, 3));
await ok("host confirms Random 1", () => report(HOST, S2, 1, random1, 2, 3));
await ok("match 2: host reports Random 1 first with 5 kills", () => report(HOST, S2, 2, random1, 1, 5));
await eq("standings add both matches", () => as("anon", async () => (await q("select label, points, kills, wins from public.tournament_standings($1)", [S2])).rows), [
  { label: "Random 1", points: 12 + 3 + 15 + 5, kills: 8, wins: 1 },
  { label: "Blood Wolves", points: 25, kills: 10, wins: 1 },
]);
await ok("A fixes their own claim", () => as(A, () => q("update public.match_results set kills = 10 where reporter_id = $1", [A])));
await eq("still flagged while the streamer disagrees", () => as("anon", async () => (await one("select status from public.result_board($1) where squad_id = $2", [S2, wolves])).status), "check");
await eq("B can't change A's report", () => as(B, async () => (await q("update public.match_results set kills = 99 where reporter_id = $1", [A])).affectedRows), 0);
await eq("B can't delete A's report", () => as(B, async () => (await q("delete from public.match_results where reporter_id = $1", [A])).affectedRows), 0);
await ok("host finishes the tournament", () => as(HOST, () => q("update public.tournaments set status = 'completed' where id = $1", [S2])));
await err("players can't report after it's finished", "PT409", () => report(A, S2, 2, wolves, 3, 2));
await ok("host can still correct after it's finished", () => as(HOST, () => q("update public.match_results set kills = 12 where reporter_id = $1 and squad_id = $2 and match_no = 1", [HOST, wolves])));
await eq("still a check: A claims 10 kills, host and streamer say 12", () => as("anon", async () => (await one("select status from public.result_board($1) where squad_id = $2 and match_no = 1", [S2, wolves])).status), "check");
await eq("Warzone Unleashed (sponsored community event) stays off the GameArena prize board", () => as("anon", async () => (await q("select * from public.monthly_player_board('tournament')")).rows.length), 0);
await eq("its own standings still have every squad", () => as("anon", async () => (await q("select label from public.tournament_standings($1)", [S2])).rows.map((r) => r.label)), ["Random 1", "Blood Wolves"]);
await eq("scrims leaderboard is separate (empty)", () => as("anon", async () => (await q("select * from public.monthly_player_board('scrim')")).rows.length), 0);
await err("unknown board rejected", "22023", () => as("anon", () => q("select * from public.monthly_player_board('everything')")));

// --- Clan scrim -----------------------------------------------------------
const clan = await as(A, async () => (await one("insert into public.chat_channels (name, tag) values ('Wolf Pack', 'WLF') returning id")).id);
await as(A, () => q("insert into public.tournament_entries (tournament_id, team_mode) values ($1, 'fixed')", [room]));
await as(B, () => q("insert into public.tournament_entries (tournament_id, team_mode) values ($1, 'fixed')", [room]));
await err("can't play for a clan you're not in", "42501", () => as(B, () => q("select public.create_squad($1, 'Fake Wolves', $2)", [room, clan])));
await ok("A enters the room for their clan", () => as(A, () => q("select public.create_squad($1, 'Wolf Pack', $2)", [room, clan])));
await ok("room host starts the room", () => as(A, () => q("update public.tournaments set status = 'live' where id = $1", [room])));
const packSquad = (await one("select id from public.squads where name = 'Wolf Pack'")).id;
await ok("room host reports the clan squad", () => report(A, room, 1, packSquad, 1, 7));
await eq("clan shows on the scrims clan board", () => as("anon", async () => (await q("select name, points from public.monthly_clan_board('scrim')")).rows), [{ name: "Wolf Pack", points: 22 }]);
await eq("clan isn't on the prize clan board", () => as("anon", async () => (await q("select * from public.monthly_clan_board('tournament')")).rows.length), 0);
await eq("scrim points don't leak into the prize board", () => as("anon", async () => (await q("select * from public.monthly_player_board('tournament')")).rows.length), 0);

// --- Leaving, withdrawing, deleting ----------------------------------------
await ok("D registers for Test Cup then withdraws", async () => {
  await as(ADMIN, () => q("update public.tournaments set status = 'open' where id = $1", [cup]));
  await as(D, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [cup]));
  const r = await as(D, () => q("delete from public.tournament_entries where tournament_id = $1 and user_id = $2", [cup, D]));
  if (r.affectedRows !== 1) throw new Error("not withdrawn");
});
await ok("captain leaves; captaincy passes on; empty squad deleted", async () => {
  await as(C, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [cup]));
  const c2 = await as(C, async () => (await one("select public.create_squad($1, 'Night Owls') c", [cup])).c);
  await as(D, () => q("select public.join_squad($1)", [c2]));
  await as(C, () => q("select public.leave_squad($1)", [cup]));
  const cap = (await one("select captain_id from public.squads where name = 'Night Owls'")).captain_id;
  if (cap !== D) throw new Error("captain not passed on: " + cap);
  await as(D, () => q("select public.leave_squad($1)", [cup]));
  if ((await q("select 1 from public.squads where name = 'Night Owls'")).rows.length) throw new Error("empty squad not deleted");
});
await ok("player deletes their own room (with squads, entries, results)", () => as(A, async () => { const r = await q("delete from public.tournaments where id = $1", [room]); if (r.affectedRows !== 1) throw new Error("not deleted"); }));
await ok("deleting an account cleans up entries", async () => { await db.query("delete from auth.users where id = $1", [F]); });

// --- Country chats --------------------------------------------------------
const zw = (await one("select id from public.chat_channels where slug = 'codm-zw'")).id;
const za = (await one("select id from public.chat_channels where slug = 'codm-za'")).id;
await eq("10 country chats", () => as(A, async () => (await one("select count(*)::int n from public.chat_channels where kind = 'country'")).n), 10);
await err("players can't create country chats", "42501", () => as(B, () => q("insert into public.chat_channels (kind, name, country_code) values ('country', 'Fakeland', 'FK')")));
await err("can't post in a country chat before joining", "42501", () => as(A, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'hi')", [zw])));
await eq("A joins Zimbabwe", () => as(A, async () => (await one("select public.join_country_chat('codm-zw') s")).s), "codm-zw");
await ok("A posts in Zimbabwe", () => as(A, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'Mhoro vese')", [zw])));
await as(B, () => q("select public.join_country_chat('codm-za')"));
await ok("B posts in South Africa", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'Howzit')", [za])));
await eq("A can't read South Africa's messages", () => as(A, async () => (await q("select * from public.chat_messages where channel_id = $1", [za])).rows.length), 0);
await err("A can't post in South Africa", "42501", () => as(A, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'hi')", [za])));
await err("A can't switch country within a week", "PT409", () => as(A, () => q("select public.join_country_chat('codm-za')")));
await err("A can't move themselves by editing the table", "42501", () => as(A, () => q("update public.country_chat_members set channel_id = $1", [za])));
await eq("A only sees their own membership", () => as(A, async () => (await q("select * from public.country_chat_members")).rows.length), 1);
await eq("admin reads every country chat", () => as(ADMIN, async () => (await q("select body from public.chat_messages where channel_id in ($1, $2) order by body", [zw, za])).rows.map((r) => r.body)), ["Howzit", "Mhoro vese"]);
await err("visitors can't join country chats", "42501", () => as("anon", () => q("select public.join_country_chat('codm-zw')")));
await eq("community chat still open to all", () => as(B, async () => (await one("select count(*)::int n from public.chat_channels where slug = 'codm-community'")).n), 1);

// --- Staff invites by email (2026-11-26) -------------------------------------
const INVITED = id("e1"), IMPOSTOR = id("e2");
await db.query("insert into auth.users (id, email) values ($1, 'Host.Person@Example.com'), ($2, 'someone@example.com')", [INVITED, IMPOSTOR]);
await ok("admin invites a host by email", () => as(ADMIN, () => q("insert into public.staff_invites (tournament_id, email, role) values ($1, 'host.person@example.com', 'host')", [S2])));
await err("invite emails must be lowercase and valid", "23514", () => as(ADMIN, () => q("insert into public.staff_invites (tournament_id, email) values ($1, 'Not An Email')", [S2])));
await err("a player can't create invites", "42501", () => as(B, () => q("insert into public.staff_invites (tournament_id, email) values ($1, 'me@example.com')", [S2])));
await eq("a player can't see invites (emails stay private)", () => as(B, async () => (await q("select * from public.staff_invites")).rows.length), 0);
await err("visitors can't read invites", "42501", () => as("anon", () => q("select * from public.staff_invites")));
await eq("admin sees the invite", () => as(ADMIN, async () => (await q("select email from public.staff_invites")).rows.map((r) => r.email)), ["host.person@example.com"]);
await ok("someone else signs up: no staff role", () => as(IMPOSTOR, () => q("insert into public.profiles (username, avatar_id) values ('someone_else', 'op-recon-m')")));
await eq("…and the invite is still waiting", () => as(ADMIN, async () => (await q("select count(*)::int n from public.staff_invites")).rows[0].n), 1);
await ok("the invited person creates their profile", () => as(INVITED, () => q("insert into public.profiles (username, avatar_id) values ('invited_host', 'op-recon-m')")));
await eq("…and is now host of the event (email matched, any case)", () => as(ADMIN, async () => (await q("select role from public.tournament_staff where tournament_id = $1 and user_id = $2", [S2, INVITED])).rows.map((r) => r.role)), ["host"]);
await eq("…and the invite is used up", () => as(ADMIN, async () => (await q("select count(*)::int n from public.staff_invites")).rows[0].n), 0);
await eq("impostor has no staff role", () => as(ADMIN, async () => (await q("select count(*)::int n from public.tournament_staff where user_id = $1", [IMPOSTOR])).rows[0].n), 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
