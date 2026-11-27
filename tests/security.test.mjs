// Stage 5: administration and security (2026-11-27). Maps to the directive's TEST 8:
import { PGlite } from "@electric-sql/pglite";
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

// unauthorised admin access, other people's private data, tournament and
// result tampering, duplicate or malicious submissions; plus the Stage 5
// audit coverage, moderation queue, community bans and H6/H8 fixes.

const id = (n) => `00000000-0000-0000-0000-0000000000${n}`;
const ADMIN = id("ad"), HOST = id("a1");
const A = id("0a"), B = id("0b"), C = id("0c"), D = id("0d"), E = id("0e");
const names = { [ADMIN]: "Dynasty", [HOST]: "Queen", [A]: "Alpha", [B]: "Bravo", [C]: "Charlie", [D]: "Delta", [E]: "Echo" };
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

for (const [u, name] of Object.entries(names)) {
  await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [name]));
}
const audits = async (action) => (await one("select count(*)::int n from public.audit_log where action = $1", [action])).n;
const RLO = String.fromCharCode(0x202e);

// ===== TEST 8.1: unauthorised admin access =====
for (const [what, sql] of [
  ["the moderation queue", "select * from public.admin_content_reports()"],
  ["the audit trail", "select * from public.admin_audit_log(null, 10)"],
  ["banning", `select public.ban_player('${B}', 'no reason', 1)`],
  ["resolving reports", `select public.resolve_content_report('player', 'dismissed', null, null, '${B}', null)`],
  ["the chat report list", "select * from public.admin_open_reports()"],
]) {
  await err(`a player can't open ${what}`, "42501", () => as(A, () => q(sql)));
}
globalThis.AAL = "aal1";
await err("an admin without two-step login can't open the audit trail", "42501", () => as(ADMIN, () => q("select * from public.admin_audit_log(null, 10)")));
await err("…or ban anyone", "42501", () => as(ADMIN, () => q("select public.ban_player($1, 'testing', 1)", [B])));
globalThis.AAL = undefined;
await err("a player can't make themselves admin", "42501", () => as(A, () => q("insert into public.app_admins (user_id) values ($1)", [A])));
await eq("a player can't change app settings", () => as(A, async () => (await q("update public.app_config set default_min_players = 2")).affectedRows), 0);
await err("nobody writes the audit log directly", "42501", () => as(A, () => q("insert into public.audit_log (action) values ('fake.entry')")));
await err("…not even an admin can erase it", "42501", () => as(ADMIN, () => q("delete from public.audit_log")));
await eq("players can't read the audit log", () => as(A, async () => (await q("select * from public.audit_log")).rows.length), 0);

// ===== TEST 8.2: other people's private data =====
await ok("Alpha saves a WhatsApp number", () => as(A, () => q("insert into public.profile_contacts (whatsapp_number) values ('+263771234567')")));
await eq("Bravo can't read it", () => as(B, async () => (await q("select * from public.profile_contacts")).rows.length), 0);
await ok("Alpha and Charlie become friends and talk privately", async () => {
  await as(A, () => q("select public.send_friend_request($1)", [C]));
  await as(C, () => q("select public.respond_friend_request($1, true)", [A]));
  const slug = await as(A, async () => (await one("select public.open_dm($1) s", [C])).s);
  const ch = (await one("select id from public.chat_channels where slug = $1", [slug])).id;
  await as(A, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'secret plan')", [ch]));
});
await eq("Bravo can't read their messages", () => as(B, async () => (await q("select * from public.chat_messages where body = 'secret plan'")).rows.length), 0);
await eq("…or their notifications", () => as(B, async () => (await q("select * from public.notifications where user_id <> $1", [B])).rows.length), 0);
await eq("…or their friendship", () => as(B, async () => (await q("select * from public.friendships")).rows.length), 0);
await eq("…even the admin can't read private messages", () => as(ADMIN, async () => (await q("select * from public.chat_messages where body = 'secret plan'")).rows.length), 0);

// ===== TEST 8.3: unauthorised tournament changes =====
const T = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, format, max_players, status) values ('community', 'Lock Cup', 'solo', 50, 'open') returning id"))).id;
await as(ADMIN, () => q("select public.add_tournament_staff($1, 'Queen', 'host')", [T]));
await eq("a player can't rename someone's tournament", async () => { await as(A, () => q("update public.tournaments set name = 'Hacked Cup' where id = $1", [T])); return (await one("select name from public.tournaments where id = $1", [T])).name; }, "Lock Cup");
await eq("…or finish it", async () => { await as(A, () => q("update public.tournaments set status = 'completed' where id = $1", [T])); return (await one("select status from public.tournaments where id = $1", [T])).status; }, "open");
await eq("…or delete it", async () => { await as(A, () => q("delete from public.tournaments where id = $1", [T])); return (await one("select count(*)::int n from public.tournaments where id = $1", [T])).n; }, 1);
await err("…or make themselves host", "42501", () => as(A, () => q("select public.add_tournament_staff($1, 'Alpha', 'host')", [T])));
await err("…or put a prize on their own room", "42501", () => as(A, () => q("insert into public.tournaments (kind, name, prize_1_usd_cents) values ('scrim', 'Fake Prize Room', 100000)")));

// ===== TEST 8.4: unauthorised result changes =====
for (const p of [A, B]) await as(p, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T]));
for (const p of [A, B]) await as(HOST, () => q("select public.set_entry_status($1, $2, 'approved')", [T, p]));
await as(ADMIN, () => q("update public.tournaments set status = 'live' where id = $1", [T]));
await ok("the host enters Alpha's result: 2nd, 5 kills", () => as(HOST, () => q("insert into public.match_results (tournament_id, match_no, player_id, placement, kills) values ($1, 1, $2, 2, 5)", [T, A])));
await eq("Alpha can't change the host's numbers", async () => { await as(A, () => q("update public.match_results set placement = 1, kills = 30 where tournament_id = $1", [T])); return (await one("select placement, kills from public.match_results where tournament_id = $1 and reporter_role = 'host'", [T])); }, { placement: 2, kills: 5 });
await eq("…or delete them", async () => { await as(B, () => q("delete from public.match_results where tournament_id = $1", [T])); return (await one("select count(*)::int n from public.match_results where tournament_id = $1", [T])).n; }, 1);
await err("…or post as the host", "42501", () => as(A, () => q("insert into public.match_results (tournament_id, match_no, player_id, placement, kills, reporter_id) values ($1, 2, $2, 1, 9, $3)", [T, A, HOST])));

// ===== TEST 8.5: duplicate and malicious submissions =====
await ok("SQL in an idea is stored as plain text", () => as(D, () => q("insert into public.ideas (body) values ($1)", ["'); drop table public.profiles; --"])));
await eq("…and nothing was dropped", async () => (await one("select count(*)::int n from public.profiles")).n, 7);
await ok("a script tag in a comment is just text", async () => {
  const idea = (await one("select id from public.ideas limit 1")).id;
  await as(E, () => q("insert into public.idea_comments (idea_id, body) values ($1, '<script>alert(1)</script>')", [idea]));
});
await eq("…stored exactly as typed (React escapes it on screen)", async () => (await one("select body from public.idea_comments")).body, "<script>alert(1)</script>");
await err("hidden direction characters are refused", "23514", () => as(E, () => q("insert into public.ideas (body) values ($1)", ["harmless" + RLO + "txt.exe"])));
await eq("player search treats input as text", () => as(A, async () => (await q("select * from public.search_players($1)", ["' or 1=1 --"])).rows.length), 0);

// ===== Audit coverage =====
await ok("the admin bans Echo for 3 days", () => as(ADMIN, () => q("select public.ban_player($1, 'Spamming the chat', 3)", [E])));
await eq("…logged", () => audits("player.banned"), 1);
await ok("…and lifts it", () => as(ADMIN, () => q("select public.unban_player($1)", [E])));
await eq("…logged", () => audits("player.unbanned"), 1);
await ok("the admin changes an app setting", () => as(ADMIN, () => q("update public.app_config set default_min_players = 24")));
await eq("…logged with the old and new value", async () => (await one("select detail from public.audit_log where action = 'config.changed'")).detail, { default_min_players: [20, 24] });
await ok("the admin invites a host by email", () => as(ADMIN, () => q("insert into public.staff_invites (tournament_id, email, role) values ($1, 'new.host@example.com', 'host')", [T])));
await eq("…logged without the email address", async () => JSON.stringify((await one("select detail from public.audit_log where action = 'invite.created'")).detail).includes("@"), false);
await ok("the admin adds a sponsor slot", () => as(ADMIN, () => q("insert into public.sponsored_slots (placement, sponsor, headline, cta_url) values ('hub', 'Local Shop', 'Data bundles', 'https://example.co.zw/data')")));
await eq("…logged", () => audits("sponsor_slot.created"), 1);
const clan = await as(B, async () => (await one("insert into public.chat_channels (name, tag) values ('Storm Riders', 'STRM') returning id")).id);
await ok("the admin approves Bravo's clan", () => as(ADMIN, () => q("select public.review_clan($1, true)", [clan])));
await eq("…logged", () => audits("clan.approved"), 1);
const clan2 = await as(C, async () => (await one("insert into public.chat_channels (name, tag) values ('Fake Clan', 'FAKE') returning id")).id);
await ok("…and rejects Charlie's", () => as(ADMIN, () => q("select public.review_clan($1, false)", [clan2])));
await eq("…logged", () => audits("clan.removed"), 1);
await ok("Delta picks a country chat; the admin resets it", async () => {
  const zw = (await one("select slug from public.chat_channels where kind = 'country' and country_code = 'ZW'")).slug;
  await as(D, () => q("select public.join_country_chat($1)", [zw]));
  await as(ADMIN, () => q("select public.admin_reset_country_chat($1)", [D]));
});
await eq("…logged", () => audits("country.reset"), 1);
await eq("the admin reads the trail with names", () => as(ADMIN, async () => (await one("select actor_name, target_name from public.admin_audit_log('player.', 5) where action = 'player.banned'"))), { actor_name: "Dynasty", target_name: "Echo" });

// ===== Reports and moderation =====
const report = (who, kind, { ref = null, target = null, reason = "abuse", details = null } = {}) =>
  as(who, () => q("insert into public.content_reports (kind, ref, target, reason, details) values ($1, $2, $3, $4, $5)", [kind, ref, target, reason, details]));
await ok("Bravo reports Delta for cheating, with details", () => report(B, "player", { target: D, reason: "cheating", details: "Aimbot in match 2 of Lock Cup" }));
await ok("Charlie reports Delta too", () => report(C, "player", { target: D, reason: "abuse" }));
await err("…reporting the same player twice is refused", "23505", () => report(B, "player", { target: D, reason: "spam" }));
await err("you can't report yourself", "42501", () => report(B, "player", { target: B }));
await err("a player report needs a player, not a post number", "42501", () => as(B, () => q("insert into public.content_reports (kind, ref, reason) values ('player', 5, 'spam')")));
await err("no links in report details", "PT422", () => report(E, "player", { target: D, details: "proof at www.example.com" }));
await ok("Alpha reports Bravo's clan", () => report(A, "clan", { target: clan, reason: "impersonation" }));
const ideaId = (await one("select id from public.ideas where user_id = $1", [D])).id;
await ok("Alpha reports Delta's idea", () => report(A, "idea", { ref: ideaId, reason: "spam" }));
const SP = await as(D, async () => (await one("select public.create_squad_post('br', 'ZW', 'any', 2, '{}', null, 'Selling accounts cheap', 7) id")).id);
await ok("Alpha reports Delta's squad post as a scam", () => report(A, "squad_post", { ref: SP, reason: "scam" }));
await eq("reporters see only their own reports", () => as(C, async () => (await q("select kind from public.content_reports")).rows), [{ kind: "player" }]);
await eq("the queue groups reports by what was reported", () => as(ADMIN, async () => {
  const r = (await q("select * from public.admin_content_reports() where kind = 'player'")).rows[0];
  return [r.reports, r.preview, r.owner_name, r.details];
}), [2, "Delta", "Delta", ["Aimbot in match 2 of Lock Cup"]]);
await err("players can't resolve reports", "42501", () => as(B, () => q("select public.resolve_content_report('player', 'dismissed', null, null, $1, null)", [D])));
await err("you can't 'remove' a player (ban instead)", "22023", () => as(ADMIN, () => q("select public.resolve_content_report('player', 'removed', null, null, $1, null)", [D])));
await ok("the admin dismisses the clan report", () => as(ADMIN, () => q("select public.resolve_content_report('clan', 'dismissed', 'Real clan, name is fine', null, $1, null)", [clan])));
await eq("…the clan stays approved", async () => (await one("select approved from public.chat_channels where id = $1", [clan])).approved, true);
await err("…a second decision is refused", "PT404", () => as(ADMIN, () => q("select public.resolve_content_report('clan', 'dismissed', null, null, $1, null)", [clan])));
await ok("the admin removes Delta's idea", () => as(ADMIN, () => q("select public.resolve_content_report('idea', 'removed', 'Not an idea', $1, null, null)", [ideaId])));
await eq("…it's gone and the report is resolved", async () => [(await one("select count(*)::int n from public.ideas where id = $1", [ideaId])).n, (await one("select status, decision from public.content_reports where kind = 'idea'"))], [0, { status: "resolved", decision: "removed" }]);
await ok("the admin bans Delta for the scam post (7 days)", () => as(ADMIN, () => q("select public.resolve_content_report('squad_post', 'banned', 'Selling accounts', $1, null, 7)", [SP])));
await eq("…the post is closed and Delta is banned", async () => [(await one("select status from public.squad_posts where id = $1", [SP])).status, (await one("select count(*)::int n from public.chat_bans where user_id = $1 and banned_until > now()", [D])).n], ["closed", 1]);
await eq("…every decision is in the audit log", () => audits("content_report.resolved"), 3);

// ===== A ban is a community ban =====
await err("banned Delta can't send friend requests", "42501", () => as(D, () => q("select public.send_friend_request($1)", [A])));
const AP = await as(A, async () => (await one("select public.create_squad_post('mp', 'ZW', 'any', 1, '{}', null, null, 3) id")).id);
await err("…or ask to join squads", "42501", () => as(D, () => q("select public.request_to_join($1, null)", [AP])));
await err("…or post squads", "42501", () => as(D, () => q("select public.create_squad_post('br', 'ZW', 'any', 1, '{}', null, null, 3)")));
await err("…or post ideas", "42501", () => as(D, () => q("insert into public.ideas (body) values ('Let me back in please')")));
await err("…or chat", "42501", async () => { const ch = (await one("select id from public.chat_channels where slug = 'codm-community'")).id; await as(D, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'hello')", [ch])); });

// ===== H6: deleting an account keeps the results that person sent =====
const before = (await one("select count(*)::int n from public.match_results where tournament_id = $1", [T])).n;
await ok("the host deletes their account", () => q("delete from auth.users where id = $1", [HOST]));
await eq("…their result stays, marked as the host's", async () => [(await one("select count(*)::int n from public.match_results where tournament_id = $1", [T])).n, (await one("select reporter_id, reporter_role, placement from public.match_results where tournament_id = $1", [T]))], [before, { reporter_id: null, reporter_role: "host", placement: 2 }]);
await eq("…and that isn't logged as a result change", () => audits("result.changed"), 0);
await ok("Bravo deletes their account", () => q("delete from auth.users where id = $1", [B]));
await eq("…the cheating report Bravo sent is kept (reporter removed)", async () => (await one("select count(*)::int n from public.content_reports where kind = 'player' and target = $1 and reporter_id is null", [D])).n, 1);

// ===== H8: joining a squad still works with the lock =====
const T2 = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, format, max_players, status) values ('community', 'Duo Night', 'duo', 20, 'open') returning id"))).id;
await as(A, () => q("insert into public.tournament_entries (tournament_id, team_mode) values ($1, 'fixed')", [T2]));
await err("registering twice is refused", "23505", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T2])));
const code = await as(A, async () => (await one("select public.create_squad($1, 'Night Owls') c", [T2])).c);
await eq("Charlie joins Alpha's duo with the code", () => as(C, async () => (await one("select public.join_squad($1) n", [code])).n), "Night Owls");
await err("…a third player is refused (duo is full)", "PT409", () => as(E, () => q("select public.join_squad($1)", [code])));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
