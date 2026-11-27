// Sponsored events, approvals, streamer slots, reports, event chats, top-10
// rule, country permanence, clan switching, ideas, settings: attack tests.
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
const ADMIN = id("ad"), HAVOC = id("a1"), STREAM = id("a2");
const P = Array.from({ length: 12 }, (_, i) => id(String(i + 10)));
const names = { [ADMIN]: "Dynasty", [HAVOC]: "MrsHavoc", [STREAM]: "LiveStreamer" };
P.forEach((u, i) => (names[u] = `Player${i + 1}`));
for (const u of Object.keys(names)) await db.query("insert into auth.users (id) values ($1)", [u]);
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
for (const [u, n] of Object.entries(names)) await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [n]));

const S2 = (await one("select id from public.tournaments where slug = 'warzone-unleashed-s2'")).id;

// --- Settings ("parameters") -------------------------------------------------
await eq("visitors read the settings", () => as("anon", async () => (await one("select prize_share_1, prize_share_2, prize_share_3 from public.app_config")).prize_share_1), 50);
await eq("players can't change settings", () => as(P[0], async () => (await q("update public.app_config set prize_share_1 = 99")).affectedRows), 0);
await err("prize shares can't add up to more than 100%", "23514", () => as(ADMIN, () => q("update public.app_config set prize_share_1 = 90")));
await ok("admin changes a setting", () => as(ADMIN, () => q("update public.app_config set default_min_players = 16")));
await err("nobody can add a second settings row", "42501", () => as(ADMIN, () => q("insert into public.app_config (id) values (true)")));

// --- Sponsored community event ---------------------------------------------
await eq("Warzone Unleashed is a free community event, sponsorship pending (owner, 2026-11-26)", () => as("anon", () => one("select kind, sponsor_name, sponsor_status, entry_fee_usd_cents from public.tournaments where id = $1", [S2])), { kind: "community", sponsor_name: null, sponsor_status: "pending", entry_fee_usd_cents: 0 });
await err("community events can't take entry fees", "23514", () => as(ADMIN, () => q("update public.tournaments set entry_fee_usd_cents = 200 where id = $1", [S2])));
await ok("admin gives MrsHavoc the event", () => as(ADMIN, () => q("select public.add_tournament_staff($1, 'MrsHavoc', 'host')", [S2])));
await err("host can't change who sponsors it", "42501", () => as(HAVOC, () => q("update public.tournaments set sponsor_name = 'Me' where id = $1", [S2])));
await ok("admin sets a new sponsor", () => as(ADMIN, () => q("update public.tournaments set sponsor_name = 'Econet Gaming' where id = $1", [S2])));
await ok("host writes the rules and the match days", () => as(HAVOC, () => q("update public.tournaments set rules = $2, match_times = array['2026-11-28 18:00+00', '2026-11-29 18:00+00']::timestamptz[], banner = 'pubgm' where id = $1", [S2, "1. No hacks.\n2. Screenshot every match.\n3. Be on time."])));
await err("unknown banner rejected", "23514", () => as(HAVOC, () => q("update public.tournaments set banner = 'evil' where id = $1", [S2])));
await err("hidden characters in rules rejected", "23514", () => as(HAVOC, () => q("update public.tournaments set rules = $2 where id = $1", [S2, `ok${String.fromCharCode(0x202e)}`])));
await err("players can't create community tournaments", "42501", () => as(P[0], () => q("insert into public.tournaments (kind, name) values ('community', 'My Cup')")));

// --- Approval ------------------------------------------------------------------
for (const p of P.slice(0, 4)) await as(p, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2]));
await eq("registrations wait for the host", () => as(P[0], async () => (await one("select status from public.tournament_entries where user_id = $1 and tournament_id = $2", [P[0], S2])).status), "pending");
await err("players can't approve themselves", "42501", () => as(P[0], () => q("select public.set_entry_status($1, $2, 'approved')", [S2, P[0]])));
await err("players can't change their own status directly", "42501", () => as(P[0], () => q("update public.tournament_entries set status = 'approved' where user_id = $1", [P[0]])));
await ok("host approves Player1", () => as(HAVOC, () => q("select public.set_entry_status($1, $2, 'approved')", [S2, P[0]])));
await ok("host rejects Player4", () => as(HAVOC, () => q("select public.set_entry_status($1, $2, 'rejected')", [S2, P[3]])));
await eq("visitor counts show approved and waiting", () => as("anon", async () => { const r = (await q("select players, pending from public.tournament_counts() where tournament_id = $1", [S2])).rows[0]; return [r.players, r.pending]; }), [1, 2]);
await eq("pending Player2 sees only their own entry", () => as(P[1], async () => (await q("select * from public.tournament_entries where tournament_id = $1", [S2])).rows.length), 1);
await eq("approved Player1 sees the list", () => as(P[0], async () => (await q("select * from public.tournament_entries where tournament_id = $1", [S2])).rows.length), 4);

// --- Event chat --------------------------------------------------------------
const chat = (await one("select id from public.chat_channels where kind = 'event' and tournament_id = $1", [S2])).id;
await ok("approved Player1 posts in the event chat", () => as(P[0], () => q("insert into public.chat_messages (channel_id, body) values ($1, 'Ready!')", [chat])));
await err("pending Player2 can't post in the event chat", "42501", () => as(P[1], () => q("insert into public.chat_messages (channel_id, body) values ($1, 'me too')", [chat])));
await eq("pending Player2 can't read it", () => as(P[1], async () => (await q("select * from public.chat_messages where channel_id = $1", [chat])).rows.length), 0);
await eq("host reads the event chat", () => as(HAVOC, async () => (await q("select * from public.chat_messages where channel_id = $1", [chat])).rows.length), 1);
await eq("new events get their own chat automatically", () => as(P[5], async () => { const t = (await one("insert into public.tournaments (name) values ('Night scrims') returning id")).id; return (await q("select kind from public.chat_channels where tournament_id = $1", [t])).rows.map((r) => r.kind); }), ["event"]);
await eq("rooms (scrims) let players straight in", () => as(P[6], async () => { const t = (await one("select id from public.tournaments where name = 'Night scrims'")).id; await q("insert into public.tournament_entries (tournament_id) values ($1)", [t]); return (await one("select status from public.tournament_entries where tournament_id = $1 and user_id = $2", [t, P[6]])).status; }), "approved");

// --- Streamer slots --------------------------------------------------------------
await err("only real streaming sites", "23514", () => as(STREAM, () => q("insert into public.stream_requests (tournament_id, platform, channel_url) values ($1, 'twitch', 'https://evil.example.com/me')", [S2])));
const req = await ok("streamer books a slot for match 1", () => as(STREAM, async () => (await one("insert into public.stream_requests (tournament_id, platform, channel_url, match_no, note) values ($1, 'tiktok', 'https://www.tiktok.com/@livestreamer', 1, 'I stream CODM daily') returning id", [S2])).id));
await err("can't book twice", "23505", () => as(STREAM, () => q("insert into public.stream_requests (tournament_id, platform, channel_url) values ($1, 'twitch', 'https://twitch.tv/me')", [S2])));
await err("can't book for someone else", "42501", () => as(STREAM, () => q("insert into public.stream_requests (tournament_id, user_id, platform, channel_url) values ($1, $2, 'twitch', 'https://twitch.tv/x')", [S2, P[0]])));
await eq("other players don't see a pending booking", () => as(P[0], async () => (await q("select * from public.stream_requests")).rows.length), 0);
await err("players can't approve streamers", "42501", () => as(P[0], () => q("select public.review_stream_request($1, true)", [req])));
await ok("host approves the streamer", () => as(HAVOC, () => q("select public.review_stream_request($1, true)", [req])));
await eq("approved streamer is now staff", () => as(HAVOC, async () => (await one("select role from public.tournament_staff where tournament_id = $1 and user_id = $2", [S2, STREAM])).role), "streamer");
await eq("everyone signed in sees the approved stream", () => as(P[1], async () => (await q("select channel_url from public.stream_requests")).rows.length), 1);

// --- Reports -------------------------------------------------------------------
await ok("streamer reports a hacker", () => as(STREAM, () => q("insert into public.event_reports (tournament_id, reason, match_no, suspect, details) values ($1, 'hacking', 1, 'xXAimbotXx', 'Wall hacks in final zone')", [S2])));
await ok("approved player reports teaming", () => as(P[0], () => q("insert into public.event_reports (tournament_id, reason) values ($1, 'teaming')", [S2])));
await err("pending player can't report", "42501", () => as(P[1], () => q("insert into public.event_reports (tournament_id, reason) values ($1, 'hacking')", [S2])));
await err("unknown reason rejected", "23514", () => as(P[0], () => q("insert into public.event_reports (tournament_id, reason) values ($1, 'boring')", [S2])));
await eq("reporter sees only their own report", () => as(P[0], async () => (await q("select * from public.event_reports")).rows.length), 1);
await eq("host sees all reports", () => as(HAVOC, async () => (await q("select * from public.event_reports where tournament_id = $1", [S2])).rows.length), 2);
await err("players can't resolve reports", "42501", () => as(P[0], async () => { const r = (await one("select id from public.event_reports where reporter_id = $1", [P[0]])).id; await q("select public.resolve_event_report($1, 'dismissed')", [r]); }));
await ok("host resolves a report", () => as(HAVOC, async () => { const r = (await one("select id from public.event_reports where reason = 'hacking'")).id; await q("select public.resolve_event_report($1, 'resolved')", [r]); }));
await err("report spam is capped at 10 per event", "PT429", () => as(P[0], async () => { for (let i = 0; i < 10; i++) await q("insert into public.event_reports (tournament_id, reason) values ($1, 'other')", [S2]); }));

// --- Official GameArena tournament: live pool + top-10 rule -----------------------
const cup = await as(ADMIN, async () => (await one("insert into public.tournaments (kind, name, format, entry_fee_usd_cents, min_players, requires_approval) values ('tournament', 'GameArena Cup', 'duo', 200, 20, false) returning id")).id);
for (const p of P.slice(4, 12)) await as(p, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [cup]));
await eq("unpaid entries don't count: 8 registrations, none paid yet → $0 (paid tournaments approve only after payment)", () => as("anon", () => one("select players, pool_usd_cents, prize_1, prize_2, prize_3, min_players from public.prize_pool($1)", [cup])), { players: 0, pool_usd_cents: 0, prize_1: 0, prize_2: 0, prize_3: 0, min_players: 20 });
await eq("no live pool for community events", () => as("anon", async () => (await q("select * from public.prize_pool($1)", [S2])).rows.length), 0);
// Make Player5 and Player6 this month's top 2 by winning a finished cup.
await as(ADMIN, () => q("update public.tournaments set status = 'live' where id = $1", [cup]));
const c1 = await as(P[4], async () => { await q("update public.tournaments set status = 'open' where id = $1", [cup]).catch(() => {}); return null; });
void c1;
await as(ADMIN, () => q("update public.tournaments set status = 'open' where id = $1", [cup]));
const codeA = await as(P[4], async () => (await one("select public.create_squad($1, 'Top Dogs') c", [cup])).c);
await as(P[6], () => q("select public.join_squad($1)", [codeA]));
const codeB = await as(P[5], async () => (await one("select public.create_squad($1, 'Second Best') c", [cup])).c);
await as(P[7], () => q("select public.join_squad($1)", [codeB]));
await as(ADMIN, () => q("update public.tournaments set status = 'live' where id = $1", [cup]));
const top = (await one("select id from public.squads where name = 'Top Dogs'")).id;
const second = (await one("select id from public.squads where name = 'Second Best'")).id;
await as(ADMIN, () => q("insert into public.match_results (tournament_id, match_no, squad_id, placement, kills) values ($1, 1, $2, 1, 10), ($1, 1, $3, 2, 5)", [cup, top, second]));
await eq("cup results go on the GameArena prize board", () => as("anon", async () => (await q("select username from public.monthly_player_board('tournament') order by points desc, username")).rows.map((r) => r.username).slice(0, 4)), ["Player5", "Player7", "Player6", "Player8"]);
const cup2 = await as(ADMIN, async () => (await one("insert into public.tournaments (kind, name, format, entry_fee_usd_cents, requires_approval) values ('tournament', 'GameArena Cup 2', 'duo', 200, false) returning id")).id);
await as(P[4], () => q("insert into public.tournament_entries (tournament_id) values ($1)", [cup2]));
const code2 = await as(P[4], async () => (await one("select public.create_squad($1, 'Super Team') c", [cup2])).c);
await err("top-10 players can't team up in GameArena tournaments", "PT409", () => as(P[5], () => q("select public.join_squad($1)", [code2])));
await ok("but they can team up in sponsored community events", async () => {
  await as(ADMIN, () => q("update public.tournaments set requires_approval = false where id = $1", [S2]));
  await as(P[4], () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2]));
  const c = await as(P[4], async () => (await one("select public.create_squad($1, 'Fun Squad') c", [S2])).c);
  await as(P[5], () => q("select public.join_squad($1)", [c]));
});
await ok("admin can switch the top-10 rule off", () => as(ADMIN, () => q("update public.app_config set top10_rule = false")));
await ok("then they can team up", () => as(P[5], () => q("select public.join_squad($1)", [code2])));
await as(ADMIN, () => q("update public.app_config set top10_rule = true"));
await ok("random squads keep top-10 players apart", async () => {
  const cup3 = await as(ADMIN, async () => (await one("insert into public.tournaments (kind, name, format, requires_approval) values ('tournament', 'GameArena Cup 3', 'squad', false) returning id")).id);
  for (const p of [P[4], P[5], P[6], P[7], P[8], P[9], P[10], P[11]]) await as(p, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [cup3]));
  await as(ADMIN, () => q("select public.make_random_squads($1)", [cup3]));
  const rows = (await q("select squad_id, count(*) filter (where user_id = any($2::uuid[]))::int tops from public.tournament_entries where tournament_id = $1 group by squad_id", [cup3, [P[4], P[5], P[6], P[7]]])).rows;
  if (rows.some((r) => r.tops > 1)) throw new Error("two top-10 players in one squad: " + JSON.stringify(rows));
});

// --- Country chat is permanent -------------------------------------------------
await ok("Player1 picks Zimbabwe", () => as(P[0], () => q("select public.join_country_chat('codm-zw')")));
await err("Player1 can never switch", "PT409", () => as(P[0], () => q("select public.join_country_chat('codm-za')")));
await err("players can't reset it", "42501", () => as(P[0], () => q("select public.admin_reset_country_chat($1)", [P[0]])));
await ok("admin resets a mistake", () => as(ADMIN, () => q("select public.admin_reset_country_chat($1)", [P[0]])));
await ok("then Player1 can pick again", () => as(P[0], () => q("select public.join_country_chat('codm-za')")));

// --- Clans: switching needs the new clan master --------------------------------
const wolves = await as(P[0], async () => (await one("insert into public.chat_channels (name, tag) values ('Wolves', 'WLF') returning id")).id);
const lions = await as(P[1], async () => (await one("insert into public.chat_channels (name, tag) values ('Lions', 'LNS') returning id")).id);
await as(ADMIN, () => q("select public.review_clan($1, true)", [wolves]));
await as(ADMIN, () => q("select public.review_clan($1, true)", [lions]));
await as(P[2], () => q("insert into public.clan_join_requests (channel_id) values ($1)", [wolves]));
await as(P[0], () => q("select public.accept_clan_request($1, $2)", [wolves, P[2]]));
await ok("Player3 asks to move to Lions", () => as(P[2], () => q("insert into public.clan_join_requests (channel_id) values ($1)", [lions])));
await err("Wolves' master can't accept for Lions", "42501", () => as(P[0], () => q("select public.accept_clan_request($1, $2)", [lions, P[2]])));
await ok("Lions' master accepts", () => as(P[1], () => q("select public.accept_clan_request($1, $2)", [lions, P[2]])));
await eq("Player3 is only in Lions now, with the LNS tag", () => as(P[2], async () => { const m = (await q("select channel_id from public.clan_members where user_id = $1", [P[2]])).rows; const t = (await one("select clan_tag from public.profiles where id = $1", [P[2]])).clan_tag; return [m.length, m[0].channel_id === lions, t]; }), [1, true, "LNS"]);
await err("players can't add themselves to a clan", "42501", () => as(P[3], () => q("insert into public.clan_members (channel_id) values ($1)", [wolves])));
await err("can't ask to join a clan waiting for approval", "42501", async () => { const pend = await as(P[8], async () => (await one("insert into public.chat_channels (name, tag) values ('Pending', 'PND') returning id")).id); await as(P[3], () => q("insert into public.clan_join_requests (channel_id) values ($1)", [pend])); });
await err("clan owners can't jump to another clan", "PT409", async () => { await as(P[0], () => q("insert into public.clan_join_requests (channel_id) values ($1)", [lions])); await as(P[1], () => q("select public.accept_clan_request($1, $2)", [lions, P[0]])); });

// --- Ideas board ---------------------------------------------------------------
// --- Public event cards --------------------------------------------------------
await eq("visitors see event cards with the host and sponsor", () => as("anon", async () => { const r = (await q("select name, kind, sponsor_name, host_username from public.event_cards() where id = $1", [S2])).rows[0]; return [r.name, r.kind, r.sponsor_name, r.host_username]; }), ["Warzone Unleashed", "community", "Econet Gaming", "MrsHavoc"]);
await err("cards don't open up private tables to visitors", "42501", () => as("anon", () => q("select * from public.profiles")));

const idea = await ok("player posts an idea", () => as(P[0], async () => (await one("insert into public.ideas (body) values ('Add a Free Fire section please') returning id")).id));
await err("too-short ideas rejected", "23514", () => as(P[0], () => q("insert into public.ideas (body) values ('hi')")));
await err("visitors can't post ideas", "42501", () => as("anon", () => q("insert into public.ideas (body) values ('Hello there')")));
await err("visitors can't read the board", "42501", () => as("anon", () => q("select * from public.idea_board()")));
await ok("idea 2", () => as(P[0], () => q("insert into public.ideas (body) values ('Weekly MVP award')")));
await ok("idea 3", () => as(P[0], () => q("insert into public.ideas (body) values ('Clan wars every Sunday')")));
await err("max 3 ideas a day", "PT429", () => as(P[0], () => q("insert into public.ideas (body) values ('One more idea')")));
for (const p of [P[1], P[2], P[3]]) await as(p, () => q("select public.vote_idea($1, 1)", [idea]));
await as(P[4], () => q("select public.vote_idea($1, -1)", [idea]));
await ok("a vote can be changed", () => as(P[3], () => q("select public.vote_idea($1, -1)", [idea])));
await ok("and taken back", () => as(P[4], () => q("select public.vote_idea($1, 0)", [idea])));
await eq("board counts 👍 2 / 👎 1 and shows my vote", () => as(P[1], async () => { const r = (await q("select up, down, my_vote, author from public.idea_board() where id = $1", [idea])).rows[0]; return [r.up, r.down, r.my_vote, r.author]; }), [2, 1, 1, "Player1"]);
await err("players can't vote twice by inserting", "42501", () => as(P[1], () => q("insert into public.idea_votes (idea_id, vote) values ($1, 1)", [idea])));
await eq("players can't mark ideas as planned", () => as(P[0], async () => (await q("update public.ideas set status = 'planned' where id = $1", [idea])).affectedRows), 0);
await ok("admin marks it planned", () => as(ADMIN, () => q("update public.ideas set status = 'planned' where id = $1", [idea])));
await eq("other players can't delete it", () => as(P[1], async () => (await q("delete from public.ideas where id = $1", [idea])).affectedRows), 0);

// Renames show everywhere straight away: boards read the current name (2026-11-26).
const topId = (await one("select user_id from public.monthly_player_board('tournament') where username = 'Player5'")).user_id;
await ok("Player5 renames to a name with symbols", () => as(topId, () => q("update public.profiles set username = '꧁𝕽𝖊𝖆𝖕𝖊𝖗꧂' where id = $1", [topId])));
await eq("the prize board shows the new name", () => as("anon", async () => (await one("select username from public.monthly_player_board('tournament') where user_id = $1", [topId])).username), "꧁𝕽𝖊𝖆𝖕𝖊𝖗꧂");
await eq("the old name is gone from the board", () => as("anon", async () => (await q("select 1 from public.monthly_player_board('tournament') where username = 'Player5'")).rows.length), 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
