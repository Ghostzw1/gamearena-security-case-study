// Stage 2 competitive core: audit log, status machine, check-in, disputes (2026-11-27).
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
const status = (who, t, s) => as(who, () => q("update public.tournaments set status = $1 where id = $2", [s, t]));
const audit = async (t, action) => (await one("select count(*)::int n from public.audit_log where tournament_id = $1 and action = $2", [t, action])).n;

// --- Setup: an admin makes a draft solo tournament and adds a host.
const T = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, format, max_players, status) values ('community', 'Night Cup', 'solo', 50, 'draft') returning id"))).id;
await as(ADMIN, () => q("update public.tournaments set requires_approval = true where id = $1", [T]));
await ok("admin adds Queen as host", () => as(ADMIN, () => q("select public.add_tournament_staff($1, 'Queen', 'host')", [T])));

// --- Drafts are hidden.
await eq("visitors don't see a draft", () => as("anon", async () => (await q("select 1 from public.tournaments where id = $1", [T])).rows.length), 0);
await eq("players don't see a draft", () => as(A, async () => (await q("select 1 from public.tournaments where id = $1", [T])).rows.length), 0);
await eq("the host sees it", () => as(HOST, async () => (await q("select 1 from public.tournaments where id = $1", [T])).rows.length), 1);
await eq("drafts stay off the public event list", () => as("anon", async () => (await q("select 1 from public.event_cards() where id = $1", [T])).rows.length), 0);
await err("nobody registers for a draft", "42501", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T])));

// --- Status machine.
await ok("host publishes: draft → open", () => status(HOST, T, "open"));
for (const u of [A, B, C, D]) await as(u, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T]));
for (const u of [A, B, C]) await as(HOST, () => q("select public.set_entry_status($1, $2, 'approved')", [T, u]));
await ok("open → closed (registration closed)", () => status(HOST, T, "closed"));
await err("no new registrations while closed", "42501", () => as(E, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T])));
await err("closed → completed (skipping the match) is refused", "PT409", () => status(HOST, T, "completed"));

// --- Check-in.
await err("no check-in before check-in opens", "PT409", () => as(A, () => q("select public.check_in($1)", [T])));
await ok("closed → checkin", () => status(HOST, T, "checkin"));
const at = await ok("A checks in", () => as(A, async () => (await one("select public.check_in($1) at", [T])).at));
await eq("checking in twice keeps the first time", () => as(A, async () => String((await one("select public.check_in($1) at", [T])).at)), String(at));
await err("D (not approved) can't check in", "PT409", () => as(D, () => q("select public.check_in($1)", [T])));
await err("E (not registered) can't check in", "PT409", () => as(E, () => q("select public.check_in($1)", [T])));
await err("visitors can't check in", "42501", () => as("anon", () => q("select public.check_in($1)", [T])));
await err("A can't set the time by hand", "42501", () => as(A, () => q("update public.tournament_entries set checked_in_at = now() where tournament_id = $1 and user_id = $2", [T, B])));
await ok("host marks B present", () => as(HOST, () => q("select public.host_check_in($1, $2, true)", [T, B])));
await err("players can't mark others present", "42501", () => as(A, () => q("select public.host_check_in($1, $2, true)", [T, C])));
await eq("2 of 3 approved players checked in", async () => (await one("select count(*)::int n from public.tournament_entries where tournament_id = $1 and checked_in_at is not null", [T])).n, 2);
await ok("C withdraws during check-in", () => as(C, () => q("delete from public.tournament_entries where tournament_id = $1 and user_id = $2", [T, C])));
await ok("checkin → live", () => status(HOST, T, "live"));
await eq("no withdrawing once it's live", () => as(B, async () => (await q("delete from public.tournament_entries where tournament_id = $1 and user_id = $2", [T, B])).affectedRows), 0);

// --- Results and disputes.
await ok("host types A's match 1 result", () => as(HOST, () => q("insert into public.match_results (tournament_id, match_no, player_id, placement, kills) values ($1, 1, $2, 3, 4)", [T, A])));
await ok("A claims a result (player claims aren't decisions)", () => as(A, () => q("insert into public.match_results (tournament_id, match_no, player_id, placement, kills) values ($1, 1, $2, 2, 6)", [T, A])));
await err("disputes need a reason of 10+ characters", "23514", () => as(A, () => q("select public.open_dispute($1, 1, $2, false, 'wrong')", [T, A])));
await err("only registered players can dispute", "42501", () => as(E, () => q("select public.open_dispute($1, 1, $2, false, 'I was there, this is wrong')", [T, A])));
await err("the subject must be in this event", "22023", () => as(A, () => q("select public.open_dispute($1, 1, $2, false, 'This player is not even here')", [T, F])));
const DISP = await ok("A disputes match 1", () => as(A, async () => (await one("select public.open_dispute($1, 1, $2, false, 'I came 2nd with 6 kills, see my screenshot') id", [T, A])).id));
await err("one open dispute per result per player", "23505", () => as(A, () => q("select public.open_dispute($1, 1, $2, false, 'Same thing again please')", [T, A])));
await eq("other players can't read A's dispute", () => as(B, async () => (await q("select * from public.result_disputes")).rows.length), 0);
await eq("everyone sees that the result is disputed (no names)", () => as("anon", async () => (await one("select open_disputes n from public.open_dispute_counts($1) where match_no = 1", [T])).n), 1);
await err("players can't decide disputes", "42501", () => as(B, () => q("select public.resolve_dispute($1, true, 'ok')", [DISP])));
await err("players can't edit disputes directly", "42501", () => as(A, () => q("update public.result_disputes set status = 'upheld' where id = $1", [DISP])));
await ok("host upholds it with an answer", () => as(HOST, () => q("select public.resolve_dispute($1, true, 'Checked the screenshot: corrected to 2nd, 6 kills')", [DISP])));
await err("a decided dispute can't be decided again", "PT409", () => as(HOST, () => q("select public.resolve_dispute($1, false, 'changed my mind')", [DISP])));
await eq("A reads the answer", () => as(A, async () => (await one("select status, resolution from public.result_disputes where id = $1", [DISP]))), { status: "upheld", resolution: "Checked the screenshot: corrected to 2nd, 6 kills" });
await ok("host corrects the result", () => as(HOST, () => q("update public.match_results set placement = 2, kills = 6 where tournament_id = $1 and reporter_role = 'host' and player_id = $2", [T, A])));
await ok("live → completed", () => status(HOST, T, "completed"));
await err("a finished tournament can't be reopened by the host", "PT409", () => status(HOST, T, "live"));
await ok("an admin can reopen it", () => as(ADMIN, () => status(ADMIN, T, "live")));

// --- Cancelling.
const T2 = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, status) values ('community', 'Rain Check Cup', 'open') returning id"))).id;
await ok("admin cancels an open tournament", () => status(ADMIN, T2, "cancelled"));
await err("no registrations for a cancelled tournament", "42501", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T2])));

// --- Audit log.
await eq("every status move is logged", () => audit(T, "tournament.changed"), 6);
await eq("approvals are logged", () => audit(T, "entry.approved"), 3);
await eq("the withdrawal is logged", () => audit(T, "entry.withdrawn"), 1);
await eq("check-ins are logged", () => audit(T, "entry.checked_in"), 2);
await eq("the host's results are logged, the player's claim isn't", async () => [await audit(T, "result.saved"), await audit(T, "result.changed")], [1, 1]);
await eq("the dispute is logged", async () => [await audit(T, "dispute.opened"), await audit(T, "dispute.upheld")], [1, 1]);
await eq("staff changes are logged (creator + Queen)", () => audit(T, "staff.added"), 2);
await eq("the actor is recorded", async () => (await one("select actor from public.audit_log where tournament_id = $1 and action = 'dispute.upheld'", [T])).actor, HOST);
await eq("players can't read the audit log", () => as(A, async () => (await q("select * from public.audit_log")).rows.length), 0);
await eq("the host reads their tournament's log", () => as(HOST, async () => (await q("select * from public.audit_log where tournament_id = $1", [T])).rows.length > 0), true);
await eq("the host can't read other tournaments' logs", () => as(HOST, async () => (await q("select * from public.audit_log where tournament_id = $1", [T2])).rows.length), 0);
const T3 = (await as(A, () => one("insert into public.tournaments (kind, name) values ('scrim', 'Short Room') returning id"))).id;
await ok("a player deletes their own room", () => as(A, () => q("delete from public.tournaments where id = $1", [T3])));
await eq("…and the log keeps the record", () => audit(T3, "tournament.deleted"), 1);
await err("nobody writes the audit log directly", "42501", () => as(ADMIN, () => q("insert into public.audit_log (action) values ('fake.entry')")));
await err("nobody edits the audit log", "42501", () => as(ADMIN, () => q("delete from public.audit_log")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
