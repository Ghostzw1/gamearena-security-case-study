// Stage 4b: squad finder, Ideas Board, clan announcements (2026-11-27).
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
const ADMIN = id("ad");
const A = id("0a"), B = id("0b"), C = id("0c"), D = id("0d"), E = id("0e"), F = id("0f"), NOPROFILE = id("99");
const names = { [ADMIN]: "Dynasty", [A]: "Alpha", [B]: "Bravo", [C]: "Charlie", [D]: "Delta", [E]: "Echo", [F]: "Foxtrot" };
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
const audits = async (action) => (await one("select count(*)::int n from public.audit_log where action = $1", [action])).n;
const RLO = String.fromCharCode(0x202e);
const post = (who, o = {}) => as(who, async () => (await one(
  "select public.create_squad_post($1, $2, $3, $4, $5, $6, $7, $8) id",
  [o.mode ?? "br", o.region ?? "ZW", o.rank ?? "legendary", o.needed ?? 2, o.roles ?? ["sniper", "support"], o.when ?? "Evenings after 7", o.body ?? "Need 2 for ranked BR", o.days ?? 7],
)).id);
const board = (who) => as(who, async () => (await q("select * from public.squad_board()")).rows);

// --- Squad finder: posting.
await err("players without a profile can't post", "42501", () => post(NOPROFILE));
await err("visitors can't post", "42501", () => as("anon", () => q("select public.create_squad_post('br', 'ZW', 'any', 2, '{}', null, null, 7)")));
const P1 = await ok("Alpha posts: 2 players for ranked BR", () => post(A));
await err("modes are BR or MP only", "23514", () => post(E, { mode: "zombies" }));
await err("a squad needs 1–4 players", "23514", () => post(E, { needed: 5 }));
await err("only known roles", "23514", () => post(E, { roles: ["hacker"] }));
await err("unknown regions are refused", "23514", () => post(E, { region: "US" }));
await err("hidden direction characters are refused", "23514", () => post(E, { body: "join" + RLO + "us" }));
const PF = await ok("Foxtrot asks for a 60-day post", () => post(F, { days: 60 }));
await eq("…it's capped at 14 days", async () => (await one("select expires_at <= created_at + interval '14 days' and expires_at > now() + interval '13 days' x from public.squad_posts where id = $1", [PF])).x, true);
const P2 = await ok("Alpha posts a second one (MP)", () => post(A, { mode: "mp", roles: ["objective"] }));
await err("…a third open post is refused (2 at a time)", "PT429", () => post(A));
await err("players can't write posts directly", "42501", () => as(A, () => q("insert into public.squad_posts (mode, region, needed) values ('br', 'ZW', 1)")));
await err("players can't edit posts directly", "42501", () => as(A, () => q("update public.squad_posts set needed = 4 where id = $1", [P1])));
await eq("Bravo sees Alpha's two posts and Foxtrot's", async () => (await board(B)).length, 3);
await err("visitors can't read the board", "42501", () => as("anon", () => q("select * from public.squad_board()")));
await eq("the board shows the author's name and key", async () => { const r = (await board(B)).find((p) => p.id === P1); return [r.author, r.author_key, r.mine, r.pending]; }, ["Alpha", "alpha", false, 0]);

// --- Asking to join.
await ok("Bravo asks to join Alpha's BR post", () => as(B, () => q("select public.request_to_join($1, 'Sniper, mic on')", [P1])));
await err("…asking twice is refused", "23505", () => as(B, () => q("select public.request_to_join($1, null)", [P1])));
await err("Alpha can't ask to join their own post", "PT409", () => as(A, () => q("select public.request_to_join($1, null)", [P1])));
await eq("Alpha is notified", () => notes(A, "squad_request"), 1);
await eq("Alpha's board shows 1 waiting request", async () => (await board(A)).find((p) => p.id === P1).pending, 1);
await eq("Bravo's board shows the request as pending", async () => (await board(B)).find((p) => p.id === P1).my_request, "pending");
await eq("Alpha sees who asked", () => as(A, async () => (await q("select username, message, status from public.squad_requests($1)", [P1])).rows), [{ username: "Bravo", message: "Sniper, mic on", status: "pending" }]);
await eq("Charlie can't see who asked", () => as(C, async () => (await q("select * from public.squad_requests($1)", [P1])).rows.length), 0);
await eq("…not even by reading the table", () => as(C, async () => (await q("select * from public.squad_post_requests")).rows.length), 0);
await err("Charlie can't answer for Alpha", "42501", () => as(C, () => q("select public.answer_join_request($1, $2, true)", [P1, B])));
await err("players can't accept themselves", "42501", () => as(B, () => q("update public.squad_post_requests set status = 'accepted'")));
await ok("Alpha accepts Bravo", () => as(A, () => q("select public.answer_join_request($1, $2, true)", [P1, B])));
await eq("…they're friends now", async () => (await one("select status from public.friendships where low = least($1::uuid, $2::uuid) and high = greatest($1::uuid, $2::uuid)", [A, B])).status, "accepted");
await eq("…Bravo is told", async () => (await one("select title from public.notifications where user_id = $1 and kind = 'squad_answered'", [B])).title, "You're in the squad");
await err("…answering twice is refused", "PT404", () => as(A, () => q("select public.answer_join_request($1, $2, false)", [P1, B])));
await ok("Charlie asks, then takes it back", async () => { await as(C, () => q("select public.request_to_join($1, null)", [P1])); await as(C, () => q("select public.cancel_join_request($1)", [P1])); });
await eq("…the request is gone", async () => (await one("select count(*)::int n from public.squad_post_requests where post_id = $1 and user_id = $2", [P1, C])).n, 0);
await ok("Charlie asks again; Alpha declines", async () => { await as(C, () => q("select public.request_to_join($1, null)", [P1])); await as(A, () => q("select public.answer_join_request($1, $2, false)", [P1, C])); });
await eq("…Charlie is told politely and isn't made a friend", async () => [(await one("select title from public.notifications where user_id = $1 and kind = 'squad_answered'", [C])).title, (await one("select count(*)::int n from public.friendships where $1::uuid in (low, high) and $2::uuid in (low, high)", [A, C])).n], ["Squad request declined", 0]);

// --- Blocks.
await ok("Delta blocks Alpha", () => as(D, () => q("insert into public.user_blocks (blocked_id) values ($1)", [A])));
await eq("…Delta no longer sees Alpha's posts", async () => (await board(D)).filter((p) => p.author === "Alpha").length, 0);
await eq("…and Alpha doesn't see Delta's", async () => { const DP = await post(D, { needed: 1 }); return (await board(A)).filter((p) => p.id === DP).length; }, 0);
await err("…Delta can't ask to join Alpha's post", "PT409", () => as(D, () => q("select public.request_to_join($1, null)", [P1])));

// --- Closing and expiry.
await err("Charlie can't close Alpha's post", "42501", () => as(C, () => q("select public.close_squad_post($1)", [P1])));
await ok("Alpha closes the BR post", () => as(A, () => q("select public.close_squad_post($1)", [P1])));
await err("…nobody can ask to join a closed post", "PT409", () => as(E, () => q("select public.request_to_join($1, null)", [P1])));
await eq("…it's gone from Echo's board but Alpha still sees it", async () => [(await board(E)).some((p) => p.id === P1), (await board(A)).find((p) => p.id === P1).status], [false, "closed"]);
await ok("an admin closes Alpha's MP post", () => as(ADMIN, () => q("select public.close_squad_post($1)", [P2])));
await eq("…and that's in the audit log", () => audits("squad_post.closed"), 1);
const P3 = await ok("Alpha posts a third today (both others closed)", () => post(A));
await ok("…and closes it", () => as(A, () => q("select public.close_squad_post($1)", [P3])));
await err("…a fourth post in one day is refused (3 a day)", "PT429", () => post(A));
await q("update public.squad_posts set created_at = now() - interval '10 days', expires_at = now() - interval '1 day' where id = $1", [PF]);
await eq("expired posts drop off the board", async () => (await board(B)).some((p) => p.id === PF), false);
await err("…and can't be joined", "PT409", () => as(B, () => q("select public.request_to_join($1, null)", [PF])));

// --- Reports.
const PE = await ok("Echo posts", () => post(E, { needed: 3, body: "Squad for Saturday" }));
await ok("Bravo reports Echo's post as spam", () => as(B, () => q("insert into public.content_reports (kind, ref, reason) values ('squad_post', $1, 'spam')", [PE])));
await err("…reporting twice is refused", "23505", () => as(B, () => q("insert into public.content_reports (kind, ref, reason) values ('squad_post', $1, 'abuse')", [PE])));
await err("unknown reasons are refused", "23514", () => as(C, () => q("insert into public.content_reports (kind, ref, reason) values ('squad_post', $1, 'ugly')", [PE])));
await err("can't report a post you can't see", "42501", () => as(C, () => q("insert into public.content_reports (kind, ref, reason) values ('squad_post', $1, 'spam')", [P1])));
await err("can't report in someone else's name", "42501", () => as(C, () => q("insert into public.content_reports (kind, ref, reason, reporter_id) values ('squad_post', $1, 'spam', $2)", [PE, B])));
await eq("reports are private: Charlie sees 0, Bravo 1, the admin 1", async () => [
  await as(C, async () => (await q("select * from public.content_reports")).rows.length),
  await as(B, async () => (await q("select * from public.content_reports")).rows.length),
  await as(ADMIN, async () => (await q("select * from public.content_reports")).rows.length),
], [0, 1, 1]);

// --- Ideas Board.
const I1 = await ok("Alpha posts an idea about tournaments", () => as(A, async () => (await one("insert into public.ideas (body, category) values ('Duo tournaments on Sundays', 'tournaments') returning id")).id));
await eq("…new ideas start as 'submitted'", async () => (await one("select status from public.ideas where id = $1", [I1])).status, "submitted");
await err("unknown categories are refused", "23514", () => as(B, () => q("insert into public.ideas (body, category) values ('Something else', 'memes')")));
await err("players can't post an idea already 'released'", "42501", () => as(B, () => q("insert into public.ideas (body, status) values ('Pretend it shipped', 'released')")));
await eq("players can't change an idea's status", async () => { await as(B, () => q("update public.ideas set status = 'released' where id = $1", [I1])); return (await one("select status from public.ideas where id = $1", [I1])).status; }, "submitted");
await ok("the admin moves it to review with a note", () => as(ADMIN, () => q("update public.ideas set status = 'review', status_note = 'Checking with hosts' where id = $1", [I1])));
await eq("…the change is in the audit log", () => audits("idea.status"), 1);
await err("old statuses are gone", "23514", () => as(ADMIN, () => q("update public.ideas set status = 'open' where id = $1", [I1])));
await err("notes can't hide direction characters", "23514", () => as(ADMIN, () => q("update public.ideas set status_note = $2 where id = $1", [I1, "ok" + RLO + "ko"])));
await eq("the board shows category, note and author key", () => as(B, async () => { const r = (await q("select * from public.idea_board() where id = $1", [I1])).rows[0]; return [r.category, r.status, r.status_note, r.author_key, r.comments]; }), ["tournaments", "review", "Checking with hosts", "alpha", 0]);

// --- Comments.
await ok("Bravo comments", () => as(B, () => q("insert into public.idea_comments (idea_id, body) values ($1, 'Yes please, duo is my thing')", [I1])));
await eq("…the board counts it", () => as(C, async () => (await one("select comments from public.idea_board() where id = $1", [I1])).comments), 1);
await eq("…the thread shows it", () => as(A, async () => (await q("select author, body, mine from public.idea_thread($1)", [I1])).rows), [{ author: "Bravo", body: "Yes please, duo is my thing", mine: false }]);
await err("can't comment in someone else's name", "42501", () => as(C, () => q("insert into public.idea_comments (idea_id, body, user_id) values ($1, 'fake', $2)", [I1, B])));
await err("one-letter comments are refused", "23514", () => as(C, () => q("insert into public.idea_comments (idea_id, body) values ($1, 'k')", [I1])));
await err("visitors can't read comments", "42501", () => as("anon", () => q("select * from public.idea_comments")));
await eq("Charlie can't delete Bravo's comment", async () => { await as(C, () => q("delete from public.idea_comments")); return (await one("select count(*)::int n from public.idea_comments")).n; }, 1);
await ok("Bravo deletes their own comment", () => as(B, () => q("delete from public.idea_comments where user_id = $1", [B])));
await ok("Charlie comments 10 times", async () => { for (let i = 0; i < 10; i++) await as(C, () => q("insert into public.idea_comments (idea_id, body) values ($1, $2)", [I1, `Comment number ${i}`])); });
await err("…the 11th within 10 minutes is refused", "PT429", () => as(C, () => q("insert into public.idea_comments (idea_id, body) values ($1, 'one more')", [I1])));
await ok("the admin moves the idea to 'building'", () => as(ADMIN, () => q("update public.ideas set status = 'building' where id = $1", [I1])));
await eq("…Alpha earns the contributor badge", () => as(A, async () => (await q("select code from public.player_achievements($1)", [A])).rows.map((r) => r.code)), ["contributor"]);

// --- Clan announcements.
const CL = await ok("Alpha starts a clan", () => as(A, async () => (await one("insert into public.chat_channels (name, tag, description) values ('Night Owls', 'NOWL', 'Late-night squad') returning id")).id));
await err("…no announcements before an admin approves it", "PT409", () => as(A, () => q("select public.set_clan_announcement($1, 'Hello')", [CL])));
await ok("the admin approves the clan; Bravo joins", async () => {
  await as(ADMIN, () => q("select public.review_clan($1, true)", [CL]));
  await as(B, () => q("insert into public.clan_join_requests (channel_id) values ($1)", [CL]));
  await as(A, () => q("select public.accept_clan_request($1, $2)", [CL, B]));
});
await err("Bravo (a member) can't post the announcement", "42501", () => as(B, () => q("select public.set_clan_announcement($1, 'I run this now')", [CL])));
await err("nobody writes announcements directly", "42501", () => as(A, () => q("insert into public.clan_announcements (channel_id, body) values ($1, 'direct')", [CL])));
await ok("Alpha pins: scrims Friday 8pm", () => as(A, () => q("select public.set_clan_announcement($1, '  Scrims Friday 8pm  ')", [CL])));
await eq("…Bravo is notified, Alpha isn't", async () => [await notes(B, "clan_announcement"), await notes(A, "clan_announcement")], [1, 0]);
await eq("…members read it (trimmed)", () => as(B, async () => (await q("select body from public.clan_announcements")).rows), [{ body: "Scrims Friday 8pm" }]);
await eq("…outsiders don't", () => as(C, async () => (await q("select * from public.clan_announcements")).rows.length), 0);
await ok("an admin changes it", () => as(ADMIN, () => q("select public.set_clan_announcement($1, 'Clan rules updated')", [CL])));
await eq("…that's in the audit log", () => audits("clan.announcement"), 1);
await ok("Alpha clears it", () => as(A, () => q("select public.set_clan_announcement($1, '')", [CL])));
await eq("…it's gone", async () => (await one("select count(*)::int n from public.clan_announcements")).n, 0);
await ok("Alpha posts three more this hour", async () => { for (const t of ["One", "Two", "Three"]) await as(A, () => q("select public.set_clan_announcement($1, $2)", [CL, `Update ${t}`])); });
await err("…the 6th in an hour is refused", "PT429", () => as(A, () => q("select public.set_clan_announcement($1, 'Too many')", [CL])));

// --- No links or phone numbers (scams; numbers are private).
await err("no links in a squad post", "PT422", () => post(B, { body: "join my group at chat.whatsapp.com/abc" }));
await err("no phone numbers in 'when you play'", "PT422", () => post(B, { when: "call 077 123 4567" }));
await err("no phone numbers in a join note", "PT422", () => as(C, () => q("select public.request_to_join($1, 'my number +263 77 123 4567')", [PE])));
await err("no links in an idea", "PT422", () => as(D, () => q("insert into public.ideas (body) values ('See www.example.com for my plan')")));
await err("no links in a comment", "PT422", () => as(D, () => q("insert into public.idea_comments (idea_id, body) values ($1, 'details at https://x.io')", [I1])));
await err("no phone numbers in a clan announcement", "PT422", () => as(ADMIN, () => q("select public.set_clan_announcement($1, 'WhatsApp the leader on 0771234567')", [CL])));
await ok("normal text with a score like 3-2 is fine", () => as(D, () => q("insert into public.idea_comments (idea_id, body) values ($1, 'We won 3-2 in the last scrim, more of these')", [I1])));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
