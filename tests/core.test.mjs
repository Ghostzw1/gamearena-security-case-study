// Social v4 Stage 2: privacy, message requests, groups, notification categories, IDOR (2026-11-27).
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
const ADMIN = id("ad");
const A = id("0a"), B = id("0b"), C = id("0c"), D = id("0d"), E = id("0e"), F = id("0f");
const names = { [ADMIN]: "Dynasty", [A]: "Alpha", [B]: "Bravo", [C]: "Charlie", [D]: "Delta", [E]: "Echo", [F]: "Foxtrot" };
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
// Profiles made more than a day ago (so the new-account limit doesn't apply), except Foxtrot.
await q("update public.profiles set created_at = now() - interval '3 days' where id <> $1", [F]);

const dm = (who, other) => as(who, async () => (await one("select public.open_dm($1) s", [other])).s);
const chanId = async (slug) => (await one("select id from public.chat_channels where slug = $1", [slug])).id;
const say = (who, ch, text) => as(who, () => q("insert into public.chat_messages (channel_id, body) values ($1, $2)", [ch, text]));
const convo = (who, other) => as(who, async () => (await q("select status, incoming_request, can_reply from public.my_conversations() where other_id = $1", [other])).rows[0] ?? null);
const friends = async (a, b) => { await as(a, () => q("select public.send_friend_request($1)", [b])); await as(b, () => q("select public.respond_friend_request($1, true)", [a])); };

// ===== Privacy settings =====
await err("unknown 'who can message me' values are refused", "23514", () => as(A, () => q("update public.profiles set message_privacy = 'strangers' where id = $1", [A])));
await err("unknown ranks are refused", "23514", () => as(A, () => q("update public.profiles set codm_rank = 'godlike' where id = $1", [A])));
await ok("Alpha sets a self-reported rank and hides online status", () => as(A, () => q("update public.profiles set codm_rank = 'legendary', show_online = false where id = $1", [A])));
await err("nobody changes someone else's settings", "42501", async () => {
  const r = await as(B, () => q("update public.profiles set message_privacy = 'nobody' where id = $1", [A]));
  if (r.affectedRows === 0) throw Object.assign(new Error("no rows"), { code: "42501" });
});
await ok("Bravo shows his profile to friends only", () => as(B, () => q("update public.profiles set profile_visibility = 'friends' where id = $1", [B])));
await eq("…Charlie (not a friend) sees the limited card", () => as(C, async () => (await one("select limited from public.player_card('bravo')")).limited), true);
await friends(B, C);
await eq("…once they're friends, Charlie sees the full profile", () => as(C, async () => (await one("select limited from public.player_card('bravo')")).limited), false);

// ===== Message requests =====
const sR = await ok("Delta (a stranger) messages Alpha: it becomes a request", () => dm(D, A));
const r1 = await chanId(sR);
await eq("…Alpha sees it as an incoming request", () => convo(A, D), { status: "request", incoming_request: true, can_reply: true });
await ok("Delta sends 3 messages while it waits", async () => { for (const t of ["hi", "want to squad?", "I play sniper"]) await say(D, r1, t); });
await err("…a 4th is refused until Alpha answers", "42501", () => say(D, r1, "hello??"));
await eq("…Alpha was told it's a message request", async () => (await one("select title from public.notifications where user_id = $1 and kind = 'message'", [A])).title, "Message request");
await err("Charlie can't answer Alpha's request", "PT404", () => as(C, () => q("select public.answer_message_request($1, true)", [sR])));
await err("…or read the messages", "PT404", async () => { const n = (await as(C, () => q("select * from public.chat_messages where channel_id = $1", [r1]))).rows.length; if (n === 0) throw Object.assign(new Error("hidden"), { code: "PT404" }); });
await ok("Alpha replies, which accepts it", () => say(A, r1, "sure, tonight"));
await eq("…it's a normal chat now", () => convo(D, A), { status: "open", incoming_request: false, can_reply: true });
await ok("…and Delta can carry on", () => say(D, r1, "great"));

const sE = await dm(E, A);
const r2 = await chanId(sE);
await say(E, r2, "buy cheap CP");
await ok("Alpha ignores Echo's request", () => as(A, () => q("select public.answer_message_request($1, false)", [sE])));
await eq("…it leaves Alpha's list", () => convo(A, E), null);
await err("…and Echo can't send more", "42501", () => say(E, r2, "hello?"));

await ok("Charlie only takes messages from friends and clan mates", () => as(C, () => q("update public.profiles set message_privacy = 'friends' where id = $1", [C])));
await err("…so Delta (a stranger) can't start a chat", "PT409", () => dm(D, C));
const clan = await as(B, async () => (await one("select id from public.chat_channels where kind = 'clan' and owner_id = $1", [B])) ?? (await one("insert into public.chat_channels (name, tag) values ('Storm Riders', 'STRM') returning id")));
await as(ADMIN, () => q("select public.review_clan($1, true)", [clan.id]));
await as(D, () => q("insert into public.clan_join_requests (channel_id) values ($1)", [clan.id]));
await as(B, () => q("select public.accept_clan_request($1, $2)", [clan.id, D]));
await as(C, () => q("insert into public.clan_join_requests (channel_id) values ($1)", [clan.id]));
await as(B, () => q("select public.accept_clan_request($1, $2)", [clan.id, C]));
await ok("…but once they share a clan, Delta can", () => dm(D, C));
await ok("Echo takes messages from friends only ('nobody' new)", () => as(E, () => q("update public.profiles set message_privacy = 'nobody' where id = $1", [E])));
await err("…so Bravo can't start one", "PT409", () => dm(B, E));
await ok("Delta blocks Bravo", () => as(D, () => q("insert into public.user_blocks (blocked_id) values ($1)", [B])));
await err("…Bravo can't message Delta", "PT409", () => dm(B, D));
await err("you can't message yourself", "PT409", () => dm(A, A));
await ok("Foxtrot (a new account) sends 3 requests", async () => { for (const t of [A, B, ADMIN]) await dm(F, t); });
await err("…a 4th on the first day is refused", "PT429", async () => { await as(C, () => q("update public.profiles set message_privacy = 'everyone' where id = $1", [C])); await dm(F, C); });

// ===== Groups =====
await friends(A, B);
await friends(A, C);
await err("groups need at least one other member", "PT422", () => as(A, () => q("select public.create_group('Night Squad', $1)", [[]])));
await err("only friends can be added", "PT409", () => as(A, () => q("select public.create_group('Night Squad', $1)", [[B, E]])));
const gSlug = await ok("Alpha makes a group with Bravo and Charlie", () => as(A, async () => (await one("select public.create_group('Night Squad', $1) s", [[B, C]])).s));
const g = await chanId(gSlug);
await eq("members see the group", () => as(B, async () => (await q("select name, members from public.my_groups()")).rows), [{ name: "Night Squad", members: 3 }]);
await eq("…outsiders don't (not even its row)", () => as(D, async () => (await q("select * from public.chat_channels where id = $1", [g])).rows.length), 0);
await err("outsiders can't post in it", "42501", () => say(D, g, "let me in"));
await eq("outsiders can't list its members", () => as(D, async () => (await q("select * from public.group_members where channel_id = $1", [g])).rows.length), 0);
await ok("Bravo writes in the group", () => say(B, g, "tonight 8pm?"));
await eq("…Alpha and Charlie get one notification each", async () => (await q("select user_id, title from public.notifications where kind = 'message' and ref = $1 order by user_id", ["g:" + g])).rows.map((r) => r.title), ["New messages in Night Squad", "New messages in Night Squad"]);
await ok("…a second message doesn't add another", () => say(B, g, "bring snipers"));
await eq("…still one each", async () => (await one("select count(*)::int n from public.notifications where ref = $1", ["g:" + g])).n, 2);
await eq("Alpha has 2 unread messages in the group", () => as(A, async () => (await one("select unread from public.my_groups()")).unread), 2);
await eq("…counted in the Chats badge too", () => as(A, async () => (await one("select messages from public.my_unread_counts()")).messages >= 2), true);
await ok("Alpha opens the group", () => as(A, () => q("select public.mark_chat_read($1)", [gSlug])));
await eq("…unread is 0 and the notification is gone", async () => [await as(A, async () => (await one("select unread from public.my_groups()")).unread), (await one("select count(*)::int n from public.notifications where user_id = $1 and ref = $2", [A, "g:" + g])).n], [0, 0]);
await err("nobody marks someone else's chat as read", "PT404", () => as(D, () => q("select public.mark_chat_read($1)", [gSlug])));
await eq("the admin can't read group messages either", () => as(ADMIN, async () => (await q("select * from public.chat_messages where channel_id = $1", [g])).rows.length), 0);
await err("Bravo (not the owner) can't add people", "42501", () => as(B, () => q("select public.add_group_members($1, $2)", [g, [D]])));
await err("…or remove them", "42501", () => as(B, () => q("select public.remove_group_member($1, $2)", [g, C])));
await ok("Alpha (owner) leaves: Bravo takes over", () => as(A, () => q("select public.leave_group($1)", [g])));
await eq("…Bravo is the owner now", async () => (await one("select role from public.group_members where channel_id = $1 and user_id = $2", [g, B])).role, "owner");
await ok("Bravo removes Charlie, then leaves", async () => { await as(B, () => q("select public.remove_group_member($1, $2)", [g, C])); await as(B, () => q("select public.leave_group($1)", [g])); });
await eq("…the empty group is deleted", async () => (await one("select count(*)::int n from public.chat_channels where id = $1", [g])).n, 0);
await ok("Alpha makes 4 more groups today", async () => { for (let i = 0; i < 4; i++) await as(A, () => q("select public.create_group($1, $2)", [`Squad ${i + 1}`, [B]])); });
await err("…a 6th in one day is refused", "PT429", () => as(A, () => q("select public.create_group('One Too Many', $1)", [[B]])));

// ===== Unfriending =====
const sAB = await dm(A, B);
const cAB = await chanId(sAB);
await eq("a chat between friends is a 'friends' chat", async () => (await one("select dm_status from public.chat_channels where id = $1", [cAB])).dm_status, "friends");
await ok("Bravo unfriends Alpha", () => as(B, () => q("select public.remove_friend($1)", [A])));
await err("…Alpha can't write in the old chat", "42501", () => say(A, cAB, "still there?"));
await ok("…but writing to Bravo again turns it into a request", () => dm(A, B));
await eq("…which Bravo sees as incoming", () => convo(B, A), { status: "request", incoming_request: true, can_reply: true });

// ===== Notification categories =====
await ok("Charlie turns off message pushes", () => as(C, () => q("insert into public.notification_prefs (message_alerts) values (false)")));
const sAC = await dm(A, C);
const cAC = await chanId(sAC);
await ok("Alpha messages Charlie", () => say(A, cAC, "hey"));
await eq("…Charlie sees it in the app but no push goes out", async () => (await one("select pushed_at is not null p from public.notifications where user_id = $1 and ref = $2", [C, "c:" + cAC])).p, true);
await eq("new notification links use the new paths", async () => (await one("select url from public.notifications where user_id = $1 and ref = $2", [C, "c:" + cAC])).url.startsWith("/chats/"), true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
