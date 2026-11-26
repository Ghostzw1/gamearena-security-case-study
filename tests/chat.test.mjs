// Runs ALL migrations in PGlite (real Postgres) with Supabase-like roles and
// auth.uid(), then attacks the profiles/chat security rules as different users.
import { PGlite } from "@electric-sql/pglite";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Migrations folder: passed by tests/run-all.mjs, or ../migrations when run alone.
const dir = process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "migrations");
const db = new PGlite();

await db.exec(`
  create role anon nologin;
  create role authenticated nologin;
  create role service_role nologin bypassrls;
  grant usage on schema public to anon, authenticated, service_role;
  alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
  alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
  alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
  create schema auth;
  create table auth.users (id uuid primary key, email text);
  create function auth.uid() returns uuid language sql stable as
    $$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
  grant usage on schema auth to anon, authenticated;
  grant execute on function auth.uid() to anon, authenticated;
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
for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
  await db.exec(fs.readFileSync(path.join(dir, f), "utf8"));
}

const A = "00000000-0000-0000-0000-00000000000a";
const B = "00000000-0000-0000-0000-00000000000b";
const C = "00000000-0000-0000-0000-00000000000c";
const ADMIN = "00000000-0000-0000-0000-0000000000ad";
for (const id of [A, B, C, ADMIN]) await db.query("insert into auth.users (id) values ($1)", [id]);
await db.query("insert into public.app_admins (user_id) values ($1)", [ADMIN]);

let pass = 0;
let fail = 0;
async function as(user, fn) {
  if (user === "anon") await db.exec("set role anon; select set_config('request.jwt.claim.sub', '', false)");
  else {
    await db.exec("set role authenticated");
    await db.query("select set_config('request.jwt.claim.sub', $1, false)", [user]);
    await db.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify({ sub: user, aal: globalThis.AAL ?? "aal2" })]);
  }
  try {
    return await fn();
  } finally {
    await db.exec("reset role");
  }
}
const q = (sql, params) => db.query(sql, params);
async function ok(name, fn) {
  try {
    const r = await fn();
    pass++;
    console.log(`PASS  ${name}`);
    return r;
  } catch (e) {
    fail++;
    console.log(`FAIL  ${name}: ${e.code} ${e.message}`);
  }
}
async function err(name, code, fn) {
  try {
    await fn();
    fail++;
    console.log(`FAIL  ${name}: expected ${code}, got success`);
  } catch (e) {
    if (e.code === code) {
      pass++;
      console.log(`PASS  ${name} (${e.code} ${e.message})`);
    } else {
      fail++;
      console.log(`FAIL  ${name}: expected ${code}, got ${e.code} ${e.message}`);
    }
  }
}
async function expectEq(name, fn, expected) {
  try {
    const got = await fn();
    if (JSON.stringify(got) === JSON.stringify(expected)) {
      pass++;
      console.log(`PASS  ${name}`);
    } else {
      fail++;
      console.log(`FAIL  ${name}: got ${JSON.stringify(got)}, expected ${JSON.stringify(expected)}`);
    }
  } catch (e) {
    fail++;
    console.log(`FAIL  ${name}: ${e.code} ${e.message}`);
  }
}
const profile = (name) => q("insert into public.profiles (username, avatar_id) values ($1, 'skull-pink')", [name]);

// ---------- usernames + profiles ----------
await expectEq("anon: username check works before sign-in", () => as("anon", async () => (await q("select public.is_username_available('Ghost') ok")).rows[0].ok), true);
await err("anon cannot read profiles", "42501", () => as("anon", () => q("select * from public.profiles")));
await ok("A creates own profile", () => as(A, () => profile("Ghost")));
await expectEq("username now taken (any case)", () => as("anon", async () => (await q("select public.is_username_available('GHOST') ok")).rows[0].ok), false);
await err("B cannot take 'ghost' (case-insensitive unique)", "23505", () => as(B, () => profile("ghost")));
await err("B cannot create a profile with A's id", "42501", () => as(B, () => q("insert into public.profiles (id, username, avatar_id) values ($1, 'Fake', 'a')", [A])));
await err("bad username rejected", "23514", () => as(B, () => profile("bad name!")));
await err("look-alike of a taken name rejected", "23505", () => as(B, () => profile("Ghоst"))); // Cyrillic o
await ok("B creates own profile", () => as(B, () => profile("Viper")));
await ok("C creates own profile", () => as(C, () => profile("Cobra")));
await ok("ADMIN creates profile", () => as(ADMIN, () => profile("Admin")));
await expectEq("B updating A's profile changes nothing", () => as(B, async () => (await q("update public.profiles set avatar_id = 'hacked' where id = $1", [A])).affectedRows), 0);
await ok("A updates own avatar", () => as(A, () => q("update public.profiles set avatar_id = 'wolf-cyan' where id = $1", [A])));
await err("A cannot change own created_at", "42501", () => as(A, () => q("update public.profiles set created_at = now() where id = $1", [A])));

// ---------- private contacts ----------
await ok("A saves WhatsApp number", () => as(A, () => q("insert into public.profile_contacts (whatsapp_number) values ('+263771234567')")));
await expectEq("B cannot see A's WhatsApp number", () => as(B, async () => (await q("select * from public.profile_contacts")).rows.length), 0);
await expectEq("A sees own WhatsApp number", () => as(A, async () => (await q("select whatsapp_number from public.profile_contacts")).rows[0].whatsapp_number), "+263771234567");
await err("bad WhatsApp format rejected", "23514", () => as(B, () => q("insert into public.profile_contacts (whatsapp_number) values ('0771234567')")));

// ---------- community chat ----------
const community = (await q("select id from public.chat_channels where slug = 'codm-community'")).rows[0].id;
await err("anon cannot read messages", "42501", () => as("anon", () => q("select * from public.chat_messages")));
await ok("A posts in community", () => as(A, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'Who is up for squads tonight?')", [community])));
await expectEq("B reads A's community message", () => as(B, async () => (await q("select body from public.chat_messages where channel_id = $1", [community])).rows.length), 1);
await err("B cannot post as A", "42501", () => as(B, () => q("insert into public.chat_messages (channel_id, user_id, body) values ($1, $2, 'fake')", [community, A])));
await err("link blocked", "PT422", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'free CP at cheap-cp.xyz')", [community])));
await err("https link blocked", "PT422", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'see https://t.co/abc')", [community])));
await err("phone number blocked", "PT422", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'call me 077 123 4567')", [community])));
await ok("normal numbers allowed (scores)", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'I got 23 kills, 2nd place')", [community])));
await err("control characters blocked", "23514", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, $2)", [community, "hi" + String.fromCharCode(0x202e) + "evil"])));
await err("over 500 characters blocked", "23514", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, $2)", [community, "x".repeat(501)])));
for (let i = 0; i < 3; i++) await as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, $2)", [community, `msg ${i}`]));
await ok("4th quick message ok", () => as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'msg 3')", [community])));
await ok("5th quick message ok", () => as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'msg 4')", [community])));
await err("6th message in 10s rate limited", "PT429", () => as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'msg 5')", [community])));

// ---------- clans ----------
const clanA = await ok("A creates a clan", () => as(A, async () => (await q("insert into public.chat_channels (name, tag, description) values ('Blaze Wolves', 'BW', 'Night squad') returning id")).rows[0].id));
await expectEq("A is clan owner automatically", () => as(A, async () => (await q("select role from public.clan_members where channel_id = $1 and user_id = $2", [clanA, A])).rows[0].role), "owner");
await err("A cannot own a second clan (one clan per player)", "23505", () => as(A, () => q("insert into public.chat_channels (name, tag) values ('Second Clan', 'SC')")));
await err("new clans need a tag", "23514", () => as(C, () => q("insert into public.chat_channels (name) values ('No Tag Clan')")));
await err("A cannot make a community channel", "42501", () => as(A, () => q("insert into public.chat_channels (name, kind) values ('Fake Official', 'community')")));
await err("B cannot take the same clan name (any case)", "23505", () => as(B, () => q("insert into public.chat_channels (name, tag) values ('blaze wolves', 'BWX')")));
await err("A can't chat before an admin approves the clan", "42501", () => as(A, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'too early')", [clanA])));
await expectEq("other players can't see a clan waiting for approval", () => as(B, async () => (await q("select * from public.chat_channels where id = $1", [clanA])).rows.length), 0);
await err("players can't approve clans", "42501", () => as(A, () => q("select public.review_clan($1, true)", [clanA])));
await ok("admin approves the clan", () => as(ADMIN, () => q("select public.review_clan($1, true)", [clanA])));
await expectEq("A's username now shows the clan tag", () => as(A, async () => (await q("select clan_tag from public.profiles where id = $1", [A])).rows[0].clan_tag), "BW");
await ok("A posts in own clan", () => as(A, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'Clan meeting at 8')", [clanA])));
await expectEq("B (not a member) can't read clan chat", () => as(B, async () => (await q("select * from public.chat_messages where channel_id = $1", [clanA])).rows.length), 0);
await err("B (not a member) can't post in clan", "42501", () => as(B, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'let me in')", [clanA])));
await err("B cannot add C to a clan", "42501", () => as(B, () => q("insert into public.clan_members (channel_id, user_id) values ($1, $2)", [clanA, C])));
await err("B cannot join as owner", "42501", () => as(B, () => q("insert into public.clan_members (channel_id, role) values ($1, 'owner')", [clanA])));
await ok("B asks to join the clan", () => as(B, () => q("insert into public.clan_join_requests (channel_id, message) values ($1, 'I play sniper')", [clanA])));
await err("C (not clan master) can't accept B", "42501", () => as(C, () => q("select public.accept_clan_request($1, $2)", [clanA, B])));
await ok("clan master A accepts B", () => as(A, () => q("select public.accept_clan_request($1, $2)", [clanA, B])));
await expectEq("B now carries the clan tag", () => as(B, async () => (await q("select clan_tag from public.profiles where id = $1", [B])).rows[0].clan_tag), "BW");
await err("players can't set their own clan tag", "42501", () => as(C, () => q("update public.profiles set clan_tag = 'BW' where id = $1", [C])));
await expectEq("B now reads clan chat", () => as(B, async () => (await q("select * from public.chat_messages where channel_id = $1", [clanA])).rows.length), 1);
await err("B cannot join a community channel as member", "42501", () => as(B, () => q("insert into public.clan_members (channel_id) values ($1)", [community])));
await expectEq("A (owner) can't leave own clan", () => as(A, async () => (await q("delete from public.clan_members where channel_id = $1 and user_id = $2", [clanA, A])).affectedRows), 0);
await expectEq("B cannot delete A's clan", () => as(B, async () => (await q("delete from public.chat_channels where id = $1", [clanA])).affectedRows), 0);
await expectEq("B leaves the clan", () => as(B, async () => (await q("delete from public.clan_members where channel_id = $1 and user_id = $2", [clanA, B])).affectedRows), 1);

// ---------- delete, report, block, ban ----------
const msgA = (await q("select id from public.chat_messages where user_id = $1 and channel_id = $2", [A, community])).rows[0].id;
await err("B cannot edit A's message directly", "42501", () => as(B, () => q("update public.chat_messages set body = 'edited' where id = $1", [msgA])));
await err("B cannot delete A's message", "42501", () => as(B, () => q("select public.delete_chat_message($1)", [msgA])));
await ok("B reports A's message", () => as(B, () => q("insert into public.chat_reports (message_id, reason) values ($1, 'spam')", [msgA])));
await err("B can't report twice", "23505", () => as(B, () => q("insert into public.chat_reports (message_id, reason) values ($1, 'abuse')", [msgA])));
await expectEq("B cannot read reports", () => as(B, async () => (await q("select * from public.chat_reports")).rows.length), 0);
await expectEq("admin reads reports", () => as(ADMIN, async () => (await q("select * from public.chat_reports")).rows.length), 1);
const clanMsg = (await q("select id from public.chat_messages where channel_id = $1", [clanA])).rows[0].id;
await err("B can't report a clan message it can't see", "42501", () => as(B, () => q("insert into public.chat_reports (message_id, reason) values ($1, 'spam')", [clanMsg])));
await ok("C blocks B", () => as(C, () => q("insert into public.user_blocks (blocked_id) values ($1)", [B])));
await expectEq("C no longer sees B's messages", () => as(C, async () => (await q("select * from public.chat_messages where user_id = $1", [B])).rows.length), 0);
await expectEq("A still sees B's messages", () => as(A, async () => (await q("select * from public.chat_messages where user_id = $1", [B])).rows.length), 1);
await expectEq("B can't see C's block list", () => as(B, async () => (await q("select * from public.user_blocks")).rows.length), 0);
await err("B can't ban anyone", "42501", () => as(B, () => q("select public.ban_player($1, 'no reason', 1)", [C])));
await err("B can't read bans table", "42501", () => as(B, () => q("select * from public.chat_bans")));
await ok("admin bans C for 1 day", () => as(ADMIN, () => q("select public.ban_player($1, 'Spamming the community', 1)", [C])));
await db.exec("update public.chat_messages set created_at = now() - interval '2 minutes'"); // clear C's rate limit
await err("banned C can't post", "42501", () => as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'still here')", [community])));
await ok("A deletes own message", () => as(A, () => q("select public.delete_chat_message($1)", [msgA])));
await expectEq("deleted message hidden from everyone", () => as(B, async () => (await q("select * from public.chat_messages where id = $1", [msgA])).rows.length), 0);
const msgB = (await q("select id from public.chat_messages where user_id = $1 and deleted_at is null", [B])).rows[0].id;
await ok("admin deletes B's message", () => as(ADMIN, () => q("select public.delete_chat_message($1)", [msgB])));
await expectEq("admin can read A's clan chat", () => as(ADMIN, async () => (await q("select * from public.chat_messages where channel_id = $1", [clanA])).rows.length), 1);

// ---------- private schema + account deletion ----------
await err("anon can't use private helpers", "42501", () => as("anon", () => q("select private.is_admin()")));
await err("anon can't delete accounts", "42501", () => as("anon", () => q("select public.delete_my_account()")));
await ok("A deletes own account", () => as(A, () => q("select public.delete_my_account()")));
await expectEq("A's login, profile, contacts, clan and clan messages are gone", async () => {
  const n = async (sql, p) => (await q(sql, p)).rows[0].n;
  return [
    await n("select count(*)::int n from auth.users where id = $1", [A]),
    await n("select count(*)::int n from public.profiles where id = $1", [A]),
    await n("select count(*)::int n from public.profile_contacts where id = $1", [A]),
    await n("select count(*)::int n from public.chat_channels where owner_id = $1", [A]),
    await n("select count(*)::int n from public.chat_messages where user_id = $1", [A]),
  ];
}, [0, 0, 0, 0, 0]);
await expectEq("other players untouched", async () => (await q("select count(*)::int n from public.profiles")).rows[0].n, 3);
await expectEq("chat_messages is in the realtime publication", async () => (await q("select count(*)::int n from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'chat_messages'")).rows[0].n, 1);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
