// Social v4 Stage 3: clan roles, invites, recruiting, leadership; squads v4 and squad chats (2026-11-27).
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
const audits = async (action) => (await one("select count(*)::int n from public.audit_log where action = $1", [action])).n;
const role = async (clan, u) => (await one("select role from public.clan_members where channel_id = $1 and user_id = $2", [clan, u]))?.role ?? null;
const call = (who, sql, params) => as(who, () => q(sql, params));

// ===== Journey C: clan leader =====
const CL = await ok("Alpha creates a clan", () => as(A, async () => (await one("insert into public.chat_channels (name, tag, description) values ('Night Owls', 'NOWL', 'Late squads') returning id")).id));
await ok("an admin approves it", () => call(ADMIN, "select public.review_clan($1, true)", [CL]));
for (const p of [B, C, D]) {
  await call(p, "insert into public.clan_join_requests (channel_id) values ($1)", [CL]);
}
await ok("Alpha accepts Bravo", () => call(A, "select public.accept_clan_request($1, $2)", [CL, B]));
await ok("Alpha promotes Bravo to officer", () => call(A, "select public.set_clan_role($1, $2, 'officer')", [CL, B]));
await eq("…logged", () => audits("clan.role_changed"), 1);
await ok("Bravo (officer) accepts Charlie and Delta", async () => { await call(B, "select public.accept_clan_request($1, $2)", [CL, C]); await call(B, "select public.accept_clan_request($1, $2)", [CL, D]); });
await err("Bravo can't promote anyone (leader only)", "42501", () => call(B, "select public.set_clan_role($1, $2, 'officer')", [CL, C]));
await err("…or hand over the clan", "42501", () => call(B, "select public.transfer_clan_leadership($1, $2)", [CL, B]));
await err("…or change the clan's details", "42501", () => call(B, "select public.update_clan($1, 'mine now', false, null, null)", [CL]));
await err("…or remove the leader", "42501", () => call(B, "select public.remove_clan_member($1, $2)", [CL, A]));
await ok("Bravo removes Delta (a member)", () => call(B, "select public.remove_clan_member($1, $2)", [CL, D]));
await eq("…Delta is out and it's logged", async () => [await role(CL, D), await audits("clan.member_removed")], [null, 1]);
await err("Charlie (member) can't remove anyone", "42501", () => call(C, "select public.remove_clan_member($1, $2)", [CL, B]));
await ok("Bravo (officer) posts an announcement", () => call(B, "select public.set_clan_announcement($1, 'Scrims at 8')", [CL]));
await err("Charlie (member) can't", "42501", () => call(C, "select public.set_clan_announcement($1, 'my news')", [CL]));
await eq("join requests are visible to officers", () => as(B, async () => { await call(E, "insert into public.clan_join_requests (channel_id, message) values ($1, 'sniper here')", [CL]); return (await q("select user_id from public.clan_join_requests where channel_id = $1", [CL])).rows.length; }), 1);

// Invitations
await ok("Bravo invites Foxtrot", () => call(B, "select public.invite_to_clan($1, $2)", [CL, F]));
await eq("…Foxtrot is notified", async () => (await one("select count(*)::int n from public.notifications where user_id = $1 and kind = 'clan_invite'", [F])).n, 1);
await err("Charlie (member) can't invite", "42501", () => call(C, "select public.invite_to_clan($1, $2)", [CL, E]));
await eq("invites are private: Charlie sees none, Foxtrot sees his", async () => [await as(C, async () => (await q("select * from public.clan_invites")).rows.length), await as(F, async () => (await q("select * from public.clan_invites")).rows.length)], [0, 1]);
await err("you can't accept an invite you don't have", "PT404", () => call(E, "select public.answer_clan_invite($1, true)", [CL]));
await ok("Foxtrot accepts", () => call(F, "select public.answer_clan_invite($1, true)", [CL]));
await eq("…and is a member with the clan tag", async () => [await role(CL, F), (await one("select clan_tag from public.profiles where id = $1", [F])).clan_tag], ["member", "NOWL"]);

// Recruiting, banner, details
await err("only gallery banners", "23514", () => call(A, "select public.update_clan($1, 'Late squads', true, null, 'activision-ghost')", [CL]));
await ok("Alpha stops recruiting, with requirements and a banner", () => call(A, "select public.update_clan($1, 'Late squads', false, 'Legendary only, mic on', 'ember')", [CL]));
await eq("…saved and logged", async () => [(await one("select recruiting, requirements, banner from public.chat_channels where id = $1", [CL])), await audits("clan.updated")], [{ recruiting: false, requirements: "Legendary only, mic on", banner: "ember" }, 1]);
await err("…so nobody can ask to join", "42501", () => call(D, "insert into public.clan_join_requests (channel_id) values ($1)", [CL]));

// Leadership
await err("leadership only goes to a member", "PT404", () => call(A, "select public.transfer_clan_leadership($1, $2)", [CL, D]));
await ok("Alpha hands the clan to Bravo", () => call(A, "select public.transfer_clan_leadership($1, $2)", [CL, B]));
await eq("…Bravo leads, Alpha is an officer, and it's logged", async () => [await role(CL, B), await role(CL, A), (await one("select owner_id from public.chat_channels where id = $1", [CL])).owner_id === B, await audits("clan.leader_transferred")], ["owner", "officer", true, 1]);
await err("Alpha (officer now) can't promote", "42501", () => call(A, "select public.set_clan_role($1, $2, 'officer')", [CL, C]));
await ok("an officer can leave on their own", () => call(A, "delete from public.clan_members where channel_id = $1 and user_id = $2", [CL, A]));
await eq("…Alpha is out", () => role(CL, A), null);
await err("the leader can't just leave (hand over or delete first)", "42501", async () => { const r = await call(B, "delete from public.clan_members where channel_id = $1 and user_id = $2", [CL, B]); if (r.affectedRows === 0) throw Object.assign(new Error("kept"), { code: "42501" }); });

// ===== Squads =====
const post = (who, o = {}) => as(who, async () => (await one(
  "select public.create_squad_post($1, $2, $3, $4, $5, $6, $7, $8) id",
  [o.mode ?? "br", o.region ?? "ZW", o.rank ?? "any", o.needed ?? 1, o.when ?? "now", o.at ?? null, o.voice ?? "in_game", o.body ?? null],
)).id);
const P1 = await ok("Charlie posts 'now': 1 player, BR", () => post(C, { body: "Need a sniper" }));
await eq("…it ends 2 hours from now", async () => (await one("select abs(extract(epoch from (expires_at - now())) - 7200) < 60 ok from public.squad_posts where id = $1", [P1])).ok, true);
await err("…and Charlie can't open a second one", "PT409", () => post(C, { mode: "mp" }));
await err("notes are 140 characters max", "PT422", () => post(D, { body: "x".repeat(141) }));
await err("unknown modes are refused", "23514", () => post(D, { mode: "zombies" }));
await err("a time more than a week away is refused", "PT422", () => post(D, { when: "time", at: new Date(Date.now() + 8 * 864e5).toISOString() }));
const P2 = await ok("Delta posts for Saturday, ranked, WhatsApp call", () => post(D, { when: "saturday", mode: "ranked", voice: "whatsapp", needed: 2 }));
await eq("…it starts on a Saturday at 8 pm (Harare time)", async () => (await one("select extract(dow from starts_at at time zone 'Africa/Harare')::int d, extract(hour from starts_at at time zone 'Africa/Harare')::int h from public.squad_posts where id = $1", [P2])), { d: 6, h: 20 });
const P3 = await ok("Echo posts for tonight", () => post(E, { when: "tonight", mode: "custom", voice: "no_mic" }));
await eq("…it starts at 8 pm tonight, or now if that's passed", async () => (await one("select starts_at >= now() - interval '1 minute' and starts_at <= date_trunc('day', now() at time zone 'Africa/Harare') at time zone 'Africa/Harare' + interval '20 hours' + interval '1 minute' ok from public.squad_posts where id = $1", [P3])).ok, true);

await ok("Foxtrot asks to join Charlie's squad", () => call(F, "select public.request_to_join($1, 'sniper, mic on')", [P1]));
await ok("Charlie accepts", () => call(C, "select public.answer_join_request($1, $2, true)", [P1, F]));
const sq = await one("select chat_id from public.squad_posts where id = $1", [P1]);
await eq("…a squad chat exists with both of them", async () => (await q("select user_id from public.group_members where channel_id = $1 order by user_id", [sq.chat_id])).rows.map((r) => r.user_id), [C, F].sort());
await eq("…the post closed itself (1 of 1 filled)", async () => (await one("select status from public.squad_posts where id = $1", [P1])).status, "closed");
await eq("…Foxtrot's notification opens the squad chat", async () => (await one("select url from public.notifications where user_id = $1 and kind = 'squad_answered'", [F])).url.startsWith("/chats/"), true);
await eq("…and they're not made friends", async () => (await one("select count(*)::int n from public.friendships")).n, 0);
await eq("the board gives the chat to members only", async () => [
  (await as(F, async () => (await one("select chat_slug from public.squad_board() where id = $1", [P1])).chat_slug)) !== null,
  await as(D, async () => (await q("select * from public.squad_board() where id = $1", [P1])).rows.length),
], [true, 0]);
await ok("Foxtrot writes in the squad chat", () => call(F, "insert into public.chat_messages (channel_id, body) values ($1, 'ready at 8')", [sq.chat_id]));
await eq("…outsiders can't read it", async () => (await as(D, async () => (await q("select * from public.chat_messages where channel_id = $1", [sq.chat_id])).rows.length)), 0);
await eq("…not even an admin", async () => (await as(ADMIN, async () => (await q("select * from public.chat_messages where channel_id = $1", [sq.chat_id])).rows.length)), 0);
await err("…and outsiders can't post in it", "42501", () => call(D, "insert into public.chat_messages (channel_id, body) values ($1, 'hi')", [sq.chat_id]));
await eq("Charlie sees it in his groups list as a squad chat", () => as(C, async () => (await one("select kind from public.my_groups()")).kind), "squad");

await q("update public.squad_posts set expires_at = now() - interval '1 minute', created_at = now() - interval '3 hours' where id = $1", [P3]);
await ok("once Echo's post has ended, Echo can post again", () => post(E, { mode: "mp" }));
await eq("…the old one is closed", async () => (await one("select status from public.squad_posts where id = $1", [P3])).status, "closed");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
