// Social v4 Stage 5: journey B (register, check in, room, result + screenshot, verified, final, achievement), payouts, penalties, review flags, team chats (2026-11-27).
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
const ADMIN = id("ad"), HOST = id("a1"), H2 = id("a2");
const A = id("0a"), B = id("0b"), C = id("0c"), D = id("0d"), E = id("0e"), F = id("0f");
const names = { [ADMIN]: "Dynasty", [HOST]: "Queen", [H2]: "Rook", [A]: "Alpha", [B]: "Bravo", [C]: "Charlie", [D]: "Delta", [E]: "Echo", [F]: "Foxtrot" };
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
const call = (who, sql, params) => as(who, () => q(sql, params));
const val = async (who, sql, params) => { const r = await call(who, sql, params); const row = r.rows[0]; return row ? Object.values(row)[0] : undefined; };
const status = (who, t, s) => call(who, "update public.tournaments set status = $1 where id = $2", [s, t]);
const result = (who, t, m, player, place, kills) => call(who, "insert into public.match_results (tournament_id, match_no, player_id, placement, kills) values ($1, $2, $3, $4, $5)", [t, m, player, place, kills]);
const room = (who, t = T) => as(who, async () => (await q("select room_info from public.tournament_rooms where tournament_id = $1", [t])).rows.map((r) => r.room_info));
const final = async (t) => (await one("select private.results_final($1) f", [t])).f;
const badges = (u) => as(u, async () => (await q("select code from public.player_achievements($1) order by code", [u])).rows.map((r) => r.code));
const backdate = async (t, hours) => { await q("alter table public.tournaments disable trigger user"); await q(`update public.tournaments set completed_at = now() - interval '${hours} hours' where id = $1`, [t]); await q("alter table public.tournaments enable trigger user"); };
const SHA = "a".repeat(64);
const shot = (u, n) => `${u}/00000000-0000-4000-8000-${String(n).padStart(12, "0")}.jpg`;
const upload = (u, path) => call(u, "insert into storage.objects (bucket_id, name) values ('match-evidence', $1)", [path]);
const evidence = (u, t, m, subject, isSquad, path, sha = SHA) => val(u, "select public.add_match_evidence($1, $2, $3, $4, $5, $6, 123456, 'image/jpeg') id", [t, m, subject, isSquad, path, sha]);

// Everyone is an established account except Alpha (new this week).
await q("update public.profiles set created_at = now() - interval '90 days' where id <> $1", [A]);

// ===== Journey B: Queen hosts a solo room =====
const T = await ok("Queen (a player) creates a free solo room and hosts it", () => as(HOST, async () => (await one("insert into public.tournaments (name, format, max_players) values ('Saturday Solo', 'solo', 20) returning id")).id));
await ok("Alpha registers", () => call(A, "insert into public.tournament_entries (tournament_id) values ($1)", [T]));
await err("…a second registration is blocked", "23505", () => call(A, "insert into public.tournament_entries (tournament_id) values ($1)", [T]));
for (const u of [B, C, D]) await call(u, "insert into public.tournament_entries (tournament_id) values ($1)", [T]);
await ok("Queen sets the room details", () => call(HOST, "insert into public.tournament_rooms (tournament_id, room_info) values ($1, 'Room 123456 / pass 789')", [T]));
await eq("before anyone checks in, registered players see the room", () => room(B), ["Room 123456 / pass 789"]);
await eq("…a stranger doesn't", () => room(E), []);
await ok("open → checkin", () => status(HOST, T, "checkin"));
await ok("Alpha, Bravo and Charlie check in", async () => { for (const u of [A, B, C]) await call(u, "select public.check_in($1)", [T]); });
await eq("now only checked-in players see the room: Alpha yes, Delta (no check-in) no", async () => [await room(A), await room(D)], [["Room 123456 / pass 789"], []]);
await eq("…the host still sees it", () => room(HOST), ["Room 123456 / pass 789"]);
await ok("checkin → live", () => status(HOST, T, "live"));

// Result + screenshot
await ok("Alpha claims 1st with 5 kills", () => result(A, T, 1, A, 1, 5));
await ok("Alpha uploads a screenshot into their own folder", () => upload(A, shot(A, 1)));
await err("Bravo can't upload into Alpha's folder", "42501", () => upload(B, shot(A, 2)));
const EV = await ok("…and attaches it to the result (hash computed by our server)", () => evidence(A, T, 1, A, false, shot(A, 1)));
await err("a screenshot that was never uploaded is refused", "42501", () => evidence(A, T, 1, A, false, shot(A, 9)));
await err("Bravo can't attach evidence to Alpha's result", "42501", async () => { await upload(B, shot(B, 1)); return evidence(B, T, 1, A, false, shot(B, 1)); });
await err("a stranger can't attach evidence", "42501", async () => { await upload(E, shot(E, 1)); return evidence(E, T, 1, E, false, shot(E, 1)); });
await err("a hash must be 64 hex characters", "23514", async () => { await upload(A, shot(A, 3)); return evidence(A, T, 1, A, false, shot(A, 3), "nothex"); });
await ok("two more screenshots for the same result", async () => { await upload(A, shot(A, 4)); await evidence(A, T, 1, A, false, shot(A, 4)); await upload(A, shot(A, 5)); await evidence(A, T, 1, A, false, shot(A, 5)); });
await err("…a 4th is refused", "PT429", async () => { await upload(A, shot(A, 6)); return evidence(A, T, 1, A, false, shot(A, 6)); });
await eq("evidence is private: Bravo sees none, Alpha sees theirs, Queen sees all", async () => [
  (await as(B, () => q("select id from public.match_evidence where tournament_id = $1 and uploader_id = $2", [T, A]))).rows.length,
  (await as(A, () => q("select id from public.my_evidence($1)", [T]))).rows.length,
  (await as(HOST, () => q("select id from public.event_evidence($1)", [T]))).rows.length,
], [0, 3, 3]);
const file = (u) => as(u, async () => (await q("select name from storage.objects where bucket_id = 'match-evidence' and name = $1", [shot(A, 1)])).rows.length);
await eq("the image opens for Alpha and Queen, never for Bravo", async () => [await file(A), await file(HOST), await file(B)], [1, 1, 0]);
await err("Alpha can't delete a screenshot once it's attached", "42501", async () => { const r = await call(A, "delete from storage.objects where bucket_id = 'match-evidence' and name = $1", [shot(A, 1)]); if (r.affectedRows === 0) throw Object.assign(new Error("kept"), { code: "42501" }); });
await err("Alpha can't verify their own screenshot", "42501", () => call(A, "select public.review_evidence($1, true)", [EV]));
await err("Rook (hosts another event) can't verify it", "42501", () => call(H2, "select public.review_evidence($1, true)", [EV]));
await ok("Queen verifies it", () => call(HOST, "select public.review_evidence($1, true)", [EV]));
await eq("…logged", async () => (await one("select count(*)::int n from public.audit_log where action = 'evidence.reviewed' and tournament_id = $1", [T])).n, 1);
await eq("the public receipt shows the hash, status and the verifier's role (no image, no uploader)", () => as("anon", () => one("select sha256, status, verified_role, results_final from public.evidence_receipt($1)", [EV])), { sha256: SHA, status: "verified", verified_role: "host", results_final: false });
await err("visitors can't list evidence", "42501", () => call("anon", "select * from public.match_evidence"));

// Official numbers and standings
await ok("Queen enters the official numbers", async () => { await result(HOST, T, 1, A, 1, 5); await result(HOST, T, 1, B, 2, 3); await result(HOST, T, 1, C, 3, 1); });
await eq("standings update: Alpha leads", () => as("anon", async () => (await q("select label, points from public.tournament_standings($1)", [T])).rows), [{ label: "Alpha", points: 20 }, { label: "Bravo", points: 15 }, { label: "Charlie", points: 11 }]);
await ok("live → completed", () => status(HOST, T, "completed"));
await eq("results are provisional during the dispute window", () => as("anon", async () => (await one("select final, open_disputes from public.results_state($1)", [T]))), { final: false, open_disputes: 0 });
await eq("…so Alpha has no Champion badge yet", () => badges(A), ["first_tournament"]);
await err("a host can't set the lock time by hand", "42501", async () => { await call(HOST, "update public.tournaments set results_locked_at = now(), completed_at = now() - interval '9 days' where id = $1", [T]); if (!(await final(T))) throw Object.assign(new Error("ignored"), { code: "42501" }); });
const DSP = await ok("Bravo questions match 1", () => val(B, "select public.open_dispute($1, 1, $2, false, 'Alpha was second, check the video')", [T, A]));
await err("results can't be locked with an open dispute", "PT409", () => call(ADMIN, "select public.lock_results($1)", [T]));
await ok("Queen answers it", () => call(HOST, "select public.resolve_dispute($1, false, 'Screenshot checked: Alpha was first')", [DSP]));
await err("the host can't lock before the window ends", "PT409", () => call(HOST, "select public.lock_results($1)", [T]));
await err("players can't lock", "42501", () => call(A, "select public.lock_results($1)", [T]));
await ok("an admin locks the results", () => call(ADMIN, "select public.lock_results($1)", [T]));
await eq("…final, and logged", async () => [await final(T), (await one("select count(*)::int n from public.audit_log where action = 'results.locked' and tournament_id = $1", [T])).n], [true, 1]);

// Locked means locked
await err("the host can't change a final result", "PT409", () => call(HOST, "update public.match_results set placement = 9 where tournament_id = $1 and player_id = $2 and reporter_role = 'host'", [T, A]));
await err("…or delete it", "PT409", () => call(HOST, "delete from public.match_results where tournament_id = $1 and player_id = $2 and reporter_role = 'host'", [T, B]));
await err("no new claims", "PT409", () => result(D, T, 1, D, 1, 30));
await err("no new disputes", "PT409", () => call(C, "select public.open_dispute($1, 1, $2, false, 'One more look please')", [T, A]));
await err("no new evidence", "PT409", async () => { await upload(B, shot(B, 7)); return evidence(B, T, 1, B, false, shot(B, 7)); });
await eq("Alpha's verified achievements appear: Champion, Finalist, First Win", () => badges(A), ["champion", "first_tournament", "first_win", "podium"]);
await eq("…and the history says the results are final", () => as(A, async () => (await one("select final, rank from public.player_history($1)", [A]))), { final: true, rank: 1 });
await err("only admins correct final results", "42501", () => call(HOST, "select public.correct_final_result($1, 1, $2, false, 2, 3, 'Video shows second place')", [T, B]));
await err("…and only with a reason", "22023", () => call(ADMIN, "select public.correct_final_result($1, 1, $2, false, 2, 4, 'no')", [T, B]));
await ok("an admin corrects Bravo's kills, with a reason", () => call(ADMIN, "select public.correct_final_result($1, 1, $2, false, 2, 4, 'Kill feed shows 4 kills')", [T, B]));
await eq("…Bravo now has 16 points, and the reason is in the audit log", async () => [(await one("select points from public.tournament_standings($1) where label = 'Bravo'", [T])).points, (await one("select detail->>'reason' r from public.audit_log where action = 'result.corrected'")).r], [16, "Kill feed shows 4 kills"]);

// Results become final on their own after the window (if nothing is open)
const T2 = (await as(H2, () => one("insert into public.tournaments (name, format) values ('Rook Room', 'solo') returning id"))).id;
for (const u of [D, E]) await call(u, "insert into public.tournament_entries (tournament_id) values ($1)", [T2]);
await status(H2, T2, "live"); await result(H2, T2, 1, D, 1, 2); await status(H2, T2, "completed");
await eq("Rook's room isn't final straight after it ends", () => final(T2), false);
await backdate(T2, 25);
await eq("…it is 25 hours later", () => final(T2), true);
await eq("monthly boards count final events only: Alpha and Delta, not a live event", async () => {
  const T3 = (await as(H2, () => one("insert into public.tournaments (name, format) values ('Still Live', 'solo') returning id"))).id;
  await call(F, "insert into public.tournament_entries (tournament_id) values ($1)", [T3]); await status(H2, T3, "live"); await result(H2, T3, 1, F, 1, 50);
  return as("anon", async () => (await q("select username from public.monthly_player_board('scrim') order by username")).rows.map((r) => r.username));
}, ["Alpha", "Bravo", "Charlie", "Delta"]);

// ===== Payouts (recorded by hand) =====
const pay = (who, t, place, u, amount, last) => val(who, "select public.record_payout($1, $2, $3, $4, 'USD', 'ecocash', $5, null)", [t, place, u, amount, last]);
await err("players can't record payouts", "42501", () => pay(A, T, 1, A, 10000, "1234"));
await err("not for someone who didn't play", "PT404", () => pay(ADMIN, T, 1, E, 10000, "1234"));
const PO = await ok("an admin records Alpha's $100 (EcoCash ref ending 1234)", () => pay(ADMIN, T, 1, A, 10000, "MP12.34-1234"));
await eq("…the public Winners list shows it with a masked reference", () => as("anon", async () => (await q("select winner, place, amount_minor, reference_masked, status from public.winners()")).rows), [{ winner: "Alpha", place: 1, amount_minor: 10000, reference_masked: "•••• 1234", status: "sent" }]);
await eq("payout rows are private: Alpha sees theirs, Bravo none", async () => [(await call(A, "select id from public.payouts")).rows.length, (await call(B, "select id from public.payouts")).rows.length], [1, 0]);
await err("Bravo can't confirm Alpha's payout", "PT404", () => call(B, "select public.confirm_payout($1)", [PO]));
await ok("Alpha confirms receipt", () => call(A, "select public.confirm_payout($1)", [PO]));
await eq("…confirmed, and the recording was logged", async () => [(await one("select status from public.payouts where id = $1", [PO])).status, (await one("select count(*)::int n from public.audit_log where action = 'payout.recorded'")).n], ["confirmed", 1]);
await err("no payouts before results are final", "PT409", async () => { const T4 = (await as(HOST, () => one("insert into public.tournaments (name, format) values ('Unfinished', 'solo') returning id"))).id; await call(A, "insert into public.tournament_entries (tournament_id) values ($1)", [T4]); return pay(ADMIN, T4, 1, A, 500, "9999"); });

// ===== Penalties =====
const penalty = (who, u, kind, t, reason, days) => val(who, "select public.issue_penalty($1, $2, $3, $4, $5)", [u, kind, t, reason, days]);
await err("hosts can't issue penalties", "42501", () => penalty(HOST, C, "warning", null, "Late to the room", null));
await ok("an admin warns Charlie", () => penalty(ADMIN, C, "warning", null, "Late to the room twice", null));
await err("a temporary ban needs a length", "22023", () => penalty(ADMIN, D, "temp_ban", null, "Abuse in chat", null));
await ok("an admin bans Delta for 7 days", () => penalty(ADMIN, D, "temp_ban", null, "Abuse in chat", 7));
await eq("…which is a real ban", async () => (await one("select count(*)::int n from public.chat_bans where user_id = $1 and banned_until > now() + interval '6 days'", [D])).n, 1);
await eq("players see their own record only", async () => [(await call(C, "select kind from public.penalty_log")).rows.map((r) => r.kind), (await call(B, "select kind from public.penalty_log")).rows.length], [["warning"], 0]);
await ok("an admin takes Bravo's prize (forfeit)", () => penalty(ADMIN, B, "prize_forfeit", T, "Shared his account", null));
await err("…so no payout can be recorded for Bravo", "PT409", () => pay(ADMIN, T, 2, B, 5000, "5678"));
const T5 = (await as(HOST, () => one("insert into public.tournaments (name, format) values ('Cheat Check', 'solo') returning id"))).id;
for (const u of [A, F]) await call(u, "insert into public.tournament_entries (tournament_id) values ($1)", [T5]);
await call(HOST, "insert into public.tournament_rooms (tournament_id, room_info) values ($1, 'Room 555')", [T5]);
await status(HOST, T5, "live"); await result(HOST, T5, 1, F, 1, 40); await result(HOST, T5, 1, A, 2, 3);
await eq("Foxtrot sees the room before the penalty", () => room(F, T5), ["Room 555"]);
await ok("an admin disqualifies Foxtrot from a live event", () => penalty(ADMIN, F, "disqualification", T5, "Aimbot on stream", null));
await eq("…Foxtrot's results stop counting and the room disappears for them", async () => [(await as("anon", () => q("select label from public.tournament_standings($1)", [T5]))).rows.map((r) => r.label), await room(F, T5)], [["Alpha"], []]);
await eq("every penalty is logged", async () => (await one("select count(*)::int n from public.audit_log where action = 'penalty.issued'")).n, 4);

// ===== Review flags (an admin decides; nothing automatic) =====
await q("insert into public.profile_contacts (id, whatsapp_number) values ($1, '+263770000000'), ($2, '+263770000000') on conflict (id) do update set whatsapp_number = excluded.whatsapp_number", [D, E]);
for (const u of [A, B, C]) await call(u, "insert into public.content_reports (kind, target, reason) values ('player', $1, 'cheating')", [F]);
const flags = await ok("an admin reads the review flags", () => as(ADMIN, async () => (await q("select kind, username, detail from public.admin_review_flags() order by kind, username")).rows));
await eq("…new account on the podium: Alpha (Bravo and Charlie are older accounts)", () => (flags ?? []).filter((f) => f.kind === "new_account_podium").map((f) => f.username), ["Alpha"]);
await eq("…one WhatsApp number on Delta and Echo (the number isn't shown)", () => (flags ?? []).filter((f) => f.kind === "shared_whatsapp").map((f) => [f.username, f.detail.includes("+263")]), [["Delta", false], ["Echo", false]]);
await eq("…three players reported Foxtrot", () => (flags ?? []).filter((f) => f.kind === "repeated_reports").map((f) => f.username), ["Foxtrot"]);
await err("players can't read the flags", "42501", () => call(A, "select * from public.admin_review_flags()"));

// ===== Team chats =====
const DUO = (await as(HOST, () => one("insert into public.tournaments (name, format) values ('Duo Night', 'duo') returning id"))).id;
for (const u of [A, C, E]) await call(u, "insert into public.tournament_entries (tournament_id) values ($1)", [DUO]);
const code = await ok("Alpha makes team Wolves", () => val(A, "select public.create_squad($1, 'Wolves')", [DUO]));
await ok("Charlie joins with the code", () => val(C, "select public.join_squad($1)", [code]));
const teamChat = (u) => as(u, async () => (await q("select name, kind from public.my_groups() where name like 'Team %'")).rows);
await eq("both get the team chat automatically", async () => [await teamChat(A), await teamChat(C)], [[{ name: "Team Wolves", kind: "squad" }], [{ name: "Team Wolves", kind: "squad" }]]);
await eq("…a player on no team doesn't", () => teamChat(E), []);
await ok("Charlie leaves the team", () => call(C, "select public.leave_squad($1)", [DUO]));
await eq("…and the team chat", () => teamChat(C), []);
await ok("the room is deleted", () => call(HOST, "delete from public.tournaments where id = $1", [DUO]));
await eq("…and its team chat with it", async () => (await one("select count(*)::int n from public.chat_channels where name = 'Team Wolves'")).n, 0);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
