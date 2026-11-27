// Stage 4a: friends, private messages, notifications (2026-11-27).
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
const notes = async (u, kind) => (await one("select count(*)::int n from public.notifications where user_id = $1 and kind = $2", [u, kind])).n;
const friend = (who, target) => as(who, async () => (await one("select public.send_friend_request($1) r", [target])).r);

// --- Friends.
await eq("Alpha asks Bravo", () => friend(A, B), "requested");
await eq("asking again doesn't duplicate", () => friend(A, B), "requested");
await eq("Bravo sees an incoming request", () => as(B, async () => (await q("select username, incoming from public.my_friends()")).rows), [{ username: "Alpha", incoming: true }]);
await eq("Bravo gets a notification", () => notes(B, "friend_request"), 1);
await ok("Bravo accepts", () => as(B, () => q("select public.respond_friend_request($1, true)", [A])));
await eq("Alpha is told", () => notes(A, "friend_accepted"), 1);
await eq("they're friends both ways", () => as(A, async () => (await one("select status from public.my_friends() where other_id = $1", [B])).status), "accepted");
await ok("Charlie asks Bravo", () => friend(C, B));
await ok("Bravo declines", () => as(B, () => q("select public.respond_friend_request($1, false)", [C])));
await eq("the declined request is gone", () => as(C, async () => (await q("select * from public.my_friends()")).rows.length), 0);
await err("Charlie can't 'accept' their own request", "PT404", () => as(D, () => q("select public.respond_friend_request($1, true)", [E])));
await err("nobody befriends themselves", "PT404", () => friend(A, A));
await err("visitors can't send requests", "42501", () => as("anon", () => q("select public.send_friend_request($1)", [B])));
await err("players can't write friendships directly", "42501", () => as(C, () => q("insert into public.friendships (low, high, requested_by, status, accepted_at) values ($1, $2, $1, 'accepted', now())", [C < D ? C : D, C < D ? D : C])));
await eq("others can't see Alpha and Bravo's friendship", () => as(C, async () => (await q("select * from public.friendships")).rows.length), 0);
await ok("Delta blocks Alpha", () => as(D, () => q("insert into public.user_blocks (blocked_id) values ($1)", [A])));
await err("a blocked player can't send a request", "PT409", () => friend(A, D));
await eq("Echo and Foxtrot's mutual requests become a friendship", async () => [await friend(E, F), await friend(F, E)], ["requested", "friends"]);

// --- Private messages.
await err("no private chat without being friends", "PT409", () => as(A, () => q("select public.open_dm($1)", [C])));
const slug = await ok("Alpha opens a chat with Bravo", () => as(A, async () => (await one("select public.open_dm($1) s", [B])).s));
await eq("Bravo gets the same conversation", () => as(B, async () => (await one("select public.open_dm($1) s", [A])).s), slug);
const ch = (await one("select id from public.chat_channels where slug = $1", [slug])).id;
const say = (who, text) => as(who, () => q("insert into public.chat_messages (channel_id, body) values ($1, $2)", [ch, text]));
await ok("Alpha says hi", () => say(A, "yo bravo, duo tonight?"));
await ok("and again", () => say(A, "room at 8"));
await eq("Bravo reads both", () => as(B, async () => (await q("select body from public.chat_messages where channel_id = $1 order by id", [ch])).rows.length), 2);
await eq("Charlie can't read them", () => as(C, async () => (await q("select body from public.chat_messages where channel_id = $1", [ch])).rows.length), 0);
await eq("admins can't read private messages", () => as(ADMIN, async () => (await q("select body from public.chat_messages where channel_id = $1", [ch])).rows.length), 0);
await eq("the conversation isn't listed for others", () => as(C, async () => (await q("select 1 from public.chat_channels where kind = 'dm'")).rows.length), 0);
await err("Charlie can't post into it", "42501", () => say(C, "let me in"));
await eq("Bravo: one notification for the conversation, not one per message", () => notes(B, "message"), 1);
await eq("Bravo has 2 unread", () => as(B, async () => (await one("select unread from public.my_conversations()")).unread), 2);
await ok("Bravo reads the conversation", () => as(B, () => q("select public.mark_dm_read($1)", [slug])));
await eq("…unread is 0 and the notification is cleared", async () => [await as(B, async () => (await one("select unread from public.my_conversations()")).unread), await notes(B, "message")], [0, 0]);
await ok("a later message notifies again", () => say(A, "you there?"));
await eq("…one new notification", () => notes(B, "message"), 1);
await err("Charlie can't mark someone else's chat read", "PT404", () => as(C, () => q("select public.mark_dm_read($1)", [slug])));
const msg = (await one("select id from public.chat_messages where channel_id = $1 order by id limit 1", [ch])).id;
await ok("Bravo reports a message", () => as(B, () => q("insert into public.chat_reports (message_id, reason) values ($1, 'spam')", [msg])));
await eq("admins see only the reported message", () => as(ADMIN, async () => (await q("select body from public.admin_open_reports() where message_id = $1", [msg])).rows.map((r) => r.body)), ["yo bravo, duo tonight?"]);
await ok("Alpha unfriends Bravo", () => as(A, () => q("select public.remove_friend($1)", [B])));
await err("no more messages after unfriending", "42501", () => say(A, "wait"));
await eq("…but the history stays readable", () => as(B, async () => (await q("select 1 from public.chat_messages where channel_id = $1", [ch])).rows.length), 3);
await eq("the conversation shows it can't be replied to", () => as(B, async () => (await one("select can_reply from public.my_conversations()")).can_reply), false);

// --- Tournament notifications.
const T = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, status) values ('community', 'Ping Cup', 'open') returning id"))).id;
for (const u of [C, E]) await as(u, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [T]));
await as(ADMIN, () => q("select public.set_entry_status($1, $2, 'approved')", [T, C]));
await as(ADMIN, () => q("select public.set_entry_status($1, $2, 'rejected')", [T, E]));
await eq("approval and rejection are notified", async () => [await notes(C, "entry_approved"), await notes(E, "entry_rejected")], [1, 1]);
await as(ADMIN, () => q("update public.tournaments set status = 'checkin' where id = $1", [T]));
await eq("check-in opening notifies approved players only", async () => [await notes(C, "checkin_open"), await notes(E, "checkin_open")], [1, 0]);
await as(ADMIN, () => q("update public.tournaments set status = 'cancelled' where id = $1", [T]));
await eq("cancelling notifies registered players", () => notes(C, "event_cancelled"), 1);

// --- The list.
await eq("Charlie's unread count", () => as(C, async () => (await one("select notifications from public.my_unread_counts()")).notifications), 3);
await ok("Charlie marks everything read", () => as(C, () => q("select public.mark_notifications_read()")));
await eq("…unread is 0", () => as(C, async () => (await one("select notifications from public.my_unread_counts()")).notifications), 0);
await eq("players only see their own notifications", () => as(C, async () => (await q("select distinct user_id from public.notifications")).rows.map((r) => r.user_id)), [C]);
await ok("Foxtrot turns social phone alerts off", () => as(F, () => q("insert into public.notification_prefs (social_alerts) values (false)")));
await ok("Charlie asks Foxtrot", () => friend(C, F));
await eq("…the request shows in the list but won't be pushed", async () => (await one("select pushed_at is not null p from public.notifications where user_id = $1 and kind = 'friend_request' and ref = $2", [F, "u:" + C])).p, true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
