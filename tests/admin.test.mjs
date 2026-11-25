// Admin tools: every function must refuse normal players and work for admins.
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

const ADMIN = "00000000-0000-0000-0000-0000000000ad";
const B = "00000000-0000-0000-0000-00000000000b";
const C = "00000000-0000-0000-0000-00000000000c";
for (const id of [ADMIN, B, C]) await db.query("insert into auth.users (id) values ($1)", [id]);
await db.query("insert into public.app_admins (user_id) values ($1)", [ADMIN]);

let pass = 0, fail = 0;
async function as(user, fn) {
  if (user === "anon") await db.exec("set role anon; select set_config('request.jwt.claim.sub', '', false)");
  else { await db.exec("set role authenticated"); await db.query("select set_config('request.jwt.claim.sub', $1, false)", [user]); await db.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify({ sub: user, aal: globalThis.AAL ?? "aal2" })]); }
  try { return await fn(); } finally { await db.exec("reset role"); }
}
const q = (s, p) => db.query(s, p);
async function ok(n, fn) { try { const r = await fn(); pass++; console.log(`PASS  ${n}`); return r; } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }
async function err(n, code, fn) { try { await fn(); fail++; console.log(`FAIL  ${n}: expected ${code}, got success`); } catch (e) { if (e.code === code) { pass++; console.log(`PASS  ${n} (${e.code} ${e.message})`); } else { fail++; console.log(`FAIL  ${n}: expected ${code}, got ${e.code} ${e.message}`); } } }
async function eq(n, fn, exp) { try { const g = await fn(); if (JSON.stringify(g) === JSON.stringify(exp)) { pass++; console.log(`PASS  ${n}`); } else { fail++; console.log(`FAIL  ${n}: got ${JSON.stringify(g)}, expected ${JSON.stringify(exp)}`); } } catch (e) { fail++; console.log(`FAIL  ${n}: ${e.code} ${e.message}`); } }

// Setup: profiles, a message from C, reports from B and ADMIN, two waitlist sign-ups.
for (const [u, name] of [[ADMIN, "Dynasty"], [B, "Viper"], [C, "Cobra"]]) await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'skull-pink')", [name]));
const community = (await q("select id from public.chat_channels where slug = 'codm-community'")).rows[0].id;
const msg = (await as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'you all suck') returning id", [community]))).rows[0].id;
await as(B, () => q("insert into public.chat_reports (message_id, reason) values ($1, 'abuse')", [msg]));
await as(ADMIN, () => q("insert into public.chat_reports (message_id, reason) values ($1, 'spam')", [msg]));
await as("anon", () => q("insert into public.interest_signups (full_name, codm_ign, whatsapp_number, preferred_format, would_pay, contact_consent) values ('Tendai Moyo', 'TM', '+263771111111', 'squad', 'yes', true), ('Rudo Banda', 'RB', '+263772222222', 'duo', 'maybe', true)"));

// Normal player B: every admin tool refuses.
await eq("B: am_i_admin is false", () => as(B, async () => (await q("select public.am_i_admin() a")).rows[0].a), false);
await err("B can't read admin stats", "42501", () => as(B, () => q("select * from public.admin_stats()")));
await err("B can't list open reports", "42501", () => as(B, () => q("select * from public.admin_open_reports()")));
await err("B can't list bans", "42501", () => as(B, () => q("select * from public.admin_active_bans()")));
await err("B can't resolve reports", "42501", () => as(B, () => q("select public.resolve_report(1, 'dismissed')")));
await err("B can't unban", "42501", () => as(B, () => q("select public.unban_player($1)", [C])));
await err("B can't edit report status directly", "42501", () => as(B, () => q("update public.chat_reports set resolved_at = now()")));
await err("anon can't call am_i_admin", "42501", () => as("anon", () => q("select public.am_i_admin()")));
await err("anon can't call delete_chat_message", "42501", () => as("anon", () => q("select public.delete_chat_message(1)")));
await err("anon can't call ban_player", "42501", () => as("anon", () => q("select public.ban_player('00000000-0000-0000-0000-00000000000c', 'x x x', 1)")));
await err("anon can't read stats", "42501", () => as("anon", () => q("select * from public.admin_stats()")));

// Admin: tools work.
await eq("admin: am_i_admin is true", () => as(ADMIN, async () => (await q("select public.am_i_admin() a")).rows[0].a), true);
await eq("admin stats: players, open reports, waitlist yes/maybe/no", () => as(ADMIN, async () => {
  const s = (await q("select * from public.admin_stats()")).rows[0];
  return [Number(s.players), Number(s.open_reports), Number(s.waitlist_total), Number(s.waitlist_yes), Number(s.waitlist_maybe), Number(s.waitlist_no)];
}), [3, 1, 2, 1, 1, 0]);
const reports = await ok("admin lists open reports with message + names", () => as(ADMIN, async () => (await q("select * from public.admin_open_reports()")).rows));
await eq("report row has body, author, reporter, channel, count", async () => {
  const r = reports.find((x) => x.reporter_username === "Viper");
  return [r.body, r.author_username, r.channel_slug, Number(r.report_count)];
}, ["you all suck", "Cobra", "codm-community", 2]);
await err("bad outcome rejected", "22023", () => as(ADMIN, () => q("select public.resolve_report($1, 'whatever')", [reports[0].report_id])));
await ok("admin deletes the message", () => as(ADMIN, () => q("select public.delete_chat_message($1)", [msg])));
await ok("admin bans C for 7 days", () => as(ADMIN, () => q("select public.ban_player($1, 'Abusive language', 7)", [C])));
await ok("admin resolves report as banned", () => as(ADMIN, () => q("select public.resolve_report($1, 'banned')", [reports[0].report_id])));
await eq("both reports on that message are closed", () => as(ADMIN, async () => (await q("select count(*)::int n from public.admin_open_reports()")).rows[0].n), 0);
await eq("ban appears in active bans", () => as(ADMIN, async () => (await q("select username, reason from public.admin_active_bans()")).rows), [{ username: "Cobra", reason: "Abusive language" }]);
await err("banned C can't post", "42501", () => as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'hello')", [community])));
await ok("admin unbans C", () => as(ADMIN, () => q("select public.unban_player($1)", [C])));
await eq("no active bans left", () => as(ADMIN, async () => (await q("select count(*)::int n from public.admin_active_bans()")).rows[0].n), 0);
await ok("unbanned C can post again", () => as(C, () => q("insert into public.chat_messages (channel_id, body) values ($1, 'sorry everyone')", [community])));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
