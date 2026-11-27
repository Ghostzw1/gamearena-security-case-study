// Social v4 Stage 4: posts, comments, reactions, the feed, Popular this week, achievements, reports, suggestions (2026-11-27).
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
const call = (who, sql, params) => as(who, () => q(sql, params));
const val = async (who, sql, params) => { const r = await as(who, () => q(sql, params)); const row = r.rows[0]; return row ? Object.values(row)[0] : undefined; };
const ids = async (who, sql, params) => (await as(who, () => q(sql, params))).rows.map((r) => r.id);
const notes = async (u) => (await q("select url from public.notifications where user_id = $1 and kind = 'post_comment'", [u])).rows.map((r) => r.url);
const post = (who, body, vis = "public", media = null) => val(who, "select public.create_post($1, $2, $3)", [body, vis, media]);

// Everyone except Foxtrot is older than a day (Foxtrot is a new account).
await q("update public.profiles set created_at = now() - interval '3 days' where id <> $1", [F]);
// Alpha's friends: Bravo and Charlie. Alpha's clan: Delta. Echo blocks Alpha.
const friends = async (a, b) => { await call(a, "select public.send_friend_request($1)", [b]); await call(b, "select public.respond_friend_request($1, true)", [a]); };
await friends(A, B); await friends(A, C);
const CL = (await as(A, () => one("insert into public.chat_channels (name, tag, description) values ('Night Owls', 'NOWL', 'Late squads') returning id"))).id;
await call(ADMIN, "select public.review_clan($1, true)", [CL]);
await call(D, "insert into public.clan_join_requests (channel_id) values ($1)", [CL]);
await call(A, "select public.accept_clan_request($1, $2)", [CL, D]);
await call(E, "insert into public.user_blocks (blocked_id) values ($1)", [A]);

// ===== Posting =====
const P1 = await ok("Alpha posts to everyone (line breaks allowed)", () => post(A, "GG everyone\nWho's up for scrims tonight?"));
const P2 = await ok("Alpha posts to friends", () => post(A, "Friends only: my new loadout", "friends"));
const P3 = await ok("Alpha posts to the clan", () => post(A, "Clan practice at 7", "clan"));
await err("posts over 500 characters are refused", "23514", () => post(A, "x".repeat(501)));
await err("hidden characters are refused", "23514", () => post(A, "Hi" + String.fromCodePoint(0x202e) + "there"));
await err("an empty post is refused", "23514", () => post(A, "   "));
await err("phone numbers are refused", "PT422", () => post(A, "WhatsApp me on 077 000 0000"));
await err("unknown visibility is refused", "23514", () => post(A, "hello", "secret"));
await err("players can't write to the posts table directly", "42501", () => call(B, "insert into public.posts (body) values ('sneaky')"));
await err("…or edit someone's post", "42501", () => call(B, "update public.posts set body = 'hacked' where id = $1", [P1]));
await err("visitors can't post", "42501", () => post("anon", "hi"));

// Photos: your own upload, in your own folder, really uploaded.
const photo = `${A}/11111111-2222-3333-4444-555555555555.jpg`;
await err("Bravo can't upload into Alpha's folder", "42501", () => call(B, "insert into storage.objects (bucket_id, name) values ('post-media', $1)", [photo]));
await err("a photo that was never uploaded is refused", "42501", () => post(A, "pic", "friends", photo));
await ok("Alpha uploads a photo", () => call(A, "insert into storage.objects (bucket_id, name) values ('post-media', $1)", [photo]));
await err("Bravo can't post Alpha's photo", "42501", () => post(B, "stolen", "public", photo));
await err("only jpg, png or webp names", "23514", async () => { await call(A, "insert into storage.objects (bucket_id, name) values ('post-media', $1)", [`${A}/11111111-2222-3333-4444-555555555555.svg`]); return post(A, null, "public", `${A}/11111111-2222-3333-4444-555555555555.svg`); });
const P4 = await ok("Alpha posts the photo to friends (no text needed)", () => post(A, null, "friends", photo));
const sees = (who) => ids(who, "select id from public.posts where author_id = $1 order by id", [A]);
await eq("a friend sees public and friends posts, not the clan's", () => sees(B), [P1, P2, P4]);
await eq("a clan mate sees public and clan posts, not friends-only", () => sees(D), [P1, P3]);
await eq("a stranger sees public posts only", () => sees(F), [P1]);
await eq("a player who blocked Alpha sees nothing of Alpha", () => sees(E), []);
await eq("Alpha sees all their own posts", () => sees(A), [P1, P2, P3, P4]);
await err("visitors can't read posts", "42501", () => call("anon", "select * from public.posts"));
const media = (who) => as(who, async () => (await q("select name from storage.objects where bucket_id = 'post-media' and name = $1", [photo])).rows.length);
await eq("the photo opens for a friend, not for a stranger or a blocker", async () => [await media(B), await media(F), await media(E)], [1, 0, 0]);

// Rate limits: new accounts 3 a day, banned players none.
for (let i = 1; i <= 3; i++) await post(F, `Hello ${i}`);
await err("a new account's 4th post today is refused", "PT429", () => post(F, "Hello 4"));
await q("insert into public.chat_bans (user_id, reason, banned_by) values ($1, 'test', $2)", [E, ADMIN]);
await err("a banned player can't post", "42501", () => post(E, "hi"));
await q("delete from public.chat_bans where user_id = $1", [E]);

// ===== Comments and notifications =====
const comment = (who, p, body) => val(who, "select public.add_comment($1, $2)", [p, body]);
await ok("Bravo (friend) comments on the friends post", () => comment(B, P2, "Clean loadout"));
await eq("…Alpha is notified, with a link to the post", () => notes(A), [`/posts/${P2}`]);
await ok("Alpha answers on their own post (no notification to themself)", () => comment(A, P2, "Thanks!"));
await ok("Charlie comments too", () => comment(C, P2, "Same here"));
await eq("…still one notification until Alpha opens the post", async () => (await notes(A)).length, 1);
await ok("Alpha opens the post", () => call(A, "select public.mark_post_seen($1)", [P2]));
await eq("…the notification is cleared", async () => (await notes(A)).length, 0);
await ok("Charlie comments again", () => comment(C, P2, "Run it tonight?"));
await eq("…Alpha is notified again", async () => (await notes(A)).length, 1);
await err("a stranger can't comment on a friends post", "PT404", () => comment(F, P2, "hi"));
await err("a blocker can't comment on Alpha's posts", "PT404", () => comment(E, P1, "hi"));
await err("no phone numbers in comments", "PT422", () => comment(B, P1, "call 0770000000"));
await err("comments over 300 characters are refused", "23514", () => comment(B, P1, "x".repeat(301)));
await err("players can't write comments directly", "42501", () => call(B, "insert into public.post_comments (post_id, body) values ($1, 'x')", [P1]));
const FC = await ok("Foxtrot (stranger) comments on the public post", () => comment(F, P1, "First!"));
await ok("Bravo blocks Foxtrot", () => call(B, "insert into public.user_blocks (blocked_id) values ($1)", [F]));
const thread = (who, p) => as(who, async () => (await q("select body from public.post_thread($1)", [p])).rows.map((r) => r.body));
await eq("…Bravo no longer sees Foxtrot's comment; Charlie still does", async () => [await thread(B, P1), await thread(C, P1)], [[], ["First!"]]);
await err("Charlie can't delete Foxtrot's comment", "42501", () => call(C, "select public.delete_comment($1)", [FC]));

// ===== Reactions =====
const react = (who, p, e) => call(who, "select public.react_to_post($1, $2)", [p, e]);
await ok("Bravo reacts 🔥, then changes to 🏆", async () => { await react(B, P1, "fire"); await react(B, P1, "trophy"); });
await ok("Charlie reacts GG", () => react(C, P1, "gg"));
await err("only the fixed set of reactions", "23514", () => react(C, P2, "poop"));
await err("a stranger can't react to a friends post", "PT404", () => react(F, P2, "fire"));
await err("players can't write reactions directly", "42501", () => call(B, "delete from public.post_reactions"));
const detail = (who, p) => as(who, () => one("select reactions, my_reaction, comments from public.post_detail($1)", [p]));
await eq("the post shows real counts and your own reaction", () => detail(B, P1), { reactions: { gg: 1, trophy: 1 }, my_reaction: "trophy", comments: 0 });
await eq("…comment counts skip people you blocked (Charlie sees 1)", async () => (await detail(C, P1)).comments, 1);
await ok("Charlie takes the reaction back", () => react(C, P1, null));
await eq("…an empty reaction also takes it back (typed calls send '')", async () => { await react(C, P1, "gg"); await react(C, P1, ""); return (await detail(C, P1)).reactions; }, { trophy: 1 });
await eq("…counted again", async () => (await detail(C, P1)).reactions, { trophy: 1 });
await react(C, P1, "gg");

// ===== Feed =====
const feed = (who, before = null, limit = 20) => ids(who, "select id from public.home_feed($1, $2)", [before, limit]);
const FP = (await q("select id from public.posts where author_id = $1 order by id", [F])).rows.map((r) => r.id).reverse();
await eq("Bravo's feed: Alpha's public and friends posts, newest first", () => feed(B), [P4, P2, P1]);
await eq("Delta's feed: the clan mate's public and clan posts", () => feed(D), [P3, P1]);
await eq("Foxtrot (no friends) sees only their own posts", () => feed(F), FP);
await eq("Echo (blocked Alpha) sees nothing", () => feed(E), []);
await eq("20 at a time: page 1", () => feed(B, null, 2), [P4, P2]);
await eq("…page 2 starts after the last one seen", async () => feed(B, (await one("select created_at from public.posts where id = $1", [P2])).created_at, 2), [P1]);
await err("visitors have no feed", "42501", () => feed("anon"));

// Official announcements: admins only, labelled, audited.
const ANN = await ok("an admin posts an announcement", () => val(ADMIN, "select public.create_announcement($1, false)", ["Saturday 8 pm: registration opens Friday"]));
const PIN = await ok("…and a pinned one", () => val(ADMIN, "select public.create_announcement($1, true)", ["Read the new community rules"]));
await err("players can't post announcements", "42501", () => call(B, "select public.create_announcement('fake news', true)"));
await eq("…both are logged", () => audits("post.announced"), 2);
await eq("announcements reach everyone's feed (even with no friends)", async () => (await feed(F))[0], ANN);
await eq("pinned ones sit on top instead of in the feed", async () => [(await ids(F, "select id from public.pinned_posts()")), (await feed(F)).includes(PIN)], [[PIN], false]);
await eq("announcements are labelled as such", () => val(F, "select kind from public.post_detail($1)", [ANN]), "announcement");

// Popular this week: public posts with comments or reactions, most first.
await eq("Popular this week: just the public post with activity", () => ids(F, "select id from public.popular_posts()"), [P1]);
await q("update public.posts set created_at = created_at - interval '8 days' where id = $1", [P1]);
await eq("…older than 7 days drops out", () => ids(F, "select id from public.popular_posts()"), []);
await q("update public.posts set created_at = created_at + interval '8 days' where id = $1", [P1]);
await eq("a profile shows only the posts you may see", async () => [await ids(B, "select id from public.player_posts($1, null)", [A]), await ids(E, "select id from public.player_posts($1, null)", [A])], [[P4, P2, P1], []]);

// ===== Achievements (opt-in, verified) =====
const T = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, format, max_players, status) values ('community', 'Proving Grounds', 'solo', 20, 'open') returning id, slug")));
for (const u of [A, B, C]) await call(u, "insert into public.tournament_entries (tournament_id) values ($1)", [T.id]);
for (const u of [A, B, C]) await call(ADMIN, "select public.set_entry_status($1, $2, 'approved')", [T.id, u]);
await call(ADMIN, "update public.tournaments set status = 'live' where id = $1", [T.id]);
for (const [u, place, kills] of [[A, 1, 5], [B, 2, 3], [C, 3, 0]]) await call(ADMIN, "insert into public.match_results (tournament_id, match_no, player_id, placement, kills) values ($1, 1, $2, $3, $4)", [T.id, u, place, kills]);
await call(ADMIN, "update public.tournaments set status = 'completed' where id = $1", [T.id]);
await call(ADMIN, "select public.lock_results($1)", [T.id]);
const SH = await ok("Alpha shares their verified Champion badge", () => val(A, "select public.share_achievement('champion')"));
await eq("…it points at the tournament that earned it", () => as(F, () => one("select kind, achievement_code, tournament_slug from public.post_detail($1)", [SH])), { kind: "achievement", achievement_code: "champion", tournament_slug: T.slug });
await err("…once", "PT409", () => val(A, "select public.share_achievement('champion')"));
await err("Bravo (2nd) can't share Champion", "PT409", () => val(B, "select public.share_achievement('champion')"));
await err("nobody can write an achievement post by hand", "42501", () => call(B, "insert into public.posts (kind, achievement_code) values ('achievement', 'champion')"));

// ===== Deleting =====
await err("Bravo can't delete Alpha's post", "42501", () => call(B, "select public.delete_post($1)", [P1]));
await eq("Alpha deletes the photo post (the app gets the photo path to remove)", () => val(A, "select public.delete_post($1)", [P4]), photo);
await eq("…gone from Bravo's feed, and the photo no longer opens for Bravo", async () => [(await feed(B)).includes(P4), await media(B)], [false, 0]);
await err("…and can't be commented on", "PT404", () => comment(B, P4, "where did it go"));
await ok("an admin deletes Alpha's clan post", () => call(ADMIN, "select public.delete_post($1)", [P3]));
await eq("…logged", () => audits("post.deleted"), 1);

// ===== Reports =====
const report = (who, kind, ref, reason = "spam") => call(who, "insert into public.content_reports (kind, ref, reason) values ($1, $2, $3)", [kind, ref, reason]);
await ok("Bravo reports the friends post", () => report(B, "post", P2));
await err("Foxtrot can't report a post they can't see", "42501", () => report(F, "post", P2));
await ok("Foxtrot reports the public post", () => report(F, "post", P1, "abuse"));
await ok("Charlie reports Foxtrot's comment", () => report(C, "post_comment", FC, "abuse"));
await eq("admins see the reports with a preview", () => as(ADMIN, async () => (await q("select kind, preview from public.admin_content_reports() where kind like 'post%' order by kind, preview")).rows), [
  { kind: "post", preview: "Friends only: my new loadout" },
  { kind: "post", preview: "GG everyone\nWho's up for scrims tonight?" },
  { kind: "post_comment", preview: "First!" },
]);
await ok("the admin removes the public post", () => call(ADMIN, "select public.resolve_content_report('post', 'removed', null, $1)", [P1]));
await eq("…it's gone from feeds", async () => (await feed(B)).includes(P1), false);
await ok("the admin bans Foxtrot for the comment (1 day)", () => call(ADMIN, "select public.resolve_content_report('post_comment', 'banned', 'Rude', $1, null, 1)", [FC]));
await eq("…the comment is hidden (kept for the record)", async () => (await one("select deleted_at is not null d from public.post_comments where id = $1", [FC])).d, true);
await err("…and Foxtrot can't comment while banned", "42501", () => comment(F, P2, "hi"));

// Comment rate limit: 20 per 10 minutes.
let made = 0, limited = false;
for (let i = 0; i < 25 && !limited; i++) {
  try { await comment(C, P2, `spam ${i}`); made++; } catch (e) { limited = e.code === "PT429"; }
}
await eq("Charlie hits the comment limit (2 earlier + 18 now = 20)", () => [made, limited], [18, true]);

// ===== People you may know =====
const suggest = (who) => as(who, async () => (await q("select username, mutual_friends, same_clan from public.suggested_players()")).rows);
await eq("Bravo: Charlie (1 mutual friend: Alpha)", () => suggest(B), [{ username: "Charlie", mutual_friends: 1, same_clan: false }]);
await eq("Delta: Alpha (same clan)", () => suggest(D), [{ username: "Alpha", mutual_friends: 0, same_clan: true }]);
await eq("Echo: nobody (Alpha is blocked)", () => suggest(E), []);
await err("visitors get no suggestions", "42501", () => suggest("anon"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
