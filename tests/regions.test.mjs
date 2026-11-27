// Regions + sponsor slots: attack tests.
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

const ADMIN = "00000000-0000-0000-0000-0000000000ad";
const B = "00000000-0000-0000-0000-00000000000b";
for (const id of [ADMIN, B]) await db.query("insert into auth.users (id) values ($1)", [id]);
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

const signup = (cols) => as("anon", () => {
  const row = { full_name: "Thabo Nkosi", codm_ign: "Thabo", whatsapp_number: `+27821${Math.floor(100000 + Math.random() * 899999)}`, preferred_format: "duo", would_pay: "yes", contact_consent: true, ...cols };
  const keys = Object.keys(row);
  return q(`insert into public.interest_signups (${keys.join(",")}) values (${keys.map((_, i) => `$${i + 1}`).join(",")})`, keys.map((k) => row[k]));
});

// Waitlist regional fields
await ok("SA sign-up with ZAR and $3", () => signup({ country: "ZA", display_currency: "ZAR", willing_amount_usd_cents: 300 }));
await ok("Zambia sign-up with ZMW and $2", () => signup({ country: "ZM", display_currency: "ZMW", willing_amount_usd_cents: 200, whatsapp_number: "+260971234567" }));
await ok("old-style sign-up still works (defaults to ZW)", () => signup({ whatsapp_number: "+263771234567" }));
await err("unknown country rejected", "23514", () => signup({ country: "US" }));
await err("bad currency code rejected", "23514", () => signup({ display_currency: "rand" }));
await err("silly amount rejected", "23514", () => signup({ willing_amount_usd_cents: 999999 }));
await err("anon still can't read the waitlist", "42501", () => as("anon", () => q("select * from public.interest_signups")));

// Profiles country
await as(B, () => q("insert into public.profiles (username, avatar_id, country) values ('Thabo', 'op-recon-m', 'ZA')"));
await ok("B changes own country", () => as(B, () => q("update public.profiles set country = 'ZM' where id = $1", [B])));
await err("bad profile country rejected", "23514", () => as(B, () => q("update public.profiles set country = 'XX' where id = $1", [B])));

// Sponsor slots
await err("anon can't create ads", "42501", () => as("anon", () => q("insert into public.sponsored_slots (placement, sponsor, headline, cta_url) values ('hub', 'Evil', 'Click me', 'https://evil.example.com')")));
await err("normal player can't create ads", "42501", () => as(B, () => q("insert into public.sponsored_slots (placement, sponsor, headline, cta_url) values ('hub', 'Evil', 'Click me', 'https://evil.example.com')")));
await as(ADMIN, () => q("insert into public.profiles (username, avatar_id) values ('Dynasty', 'swords-silver')"));
const ad = await ok("admin creates an ad", () => as(ADMIN, async () => (await q("insert into public.sponsored_slots (placement, sponsor, headline, body, cta_label, cta_url) values ('hub', 'Econet', 'Gaming bundles', 'Data for gamers', 'See bundles', 'https://example.co.zw/gaming') returning id")).rows[0].id));
await err("javascript: link rejected", "23514", () => as(ADMIN, () => q("insert into public.sponsored_slots (placement, sponsor, headline, cta_url) values ('hub', 'X', 'Bad link', 'javascript:alert(1)')")));
await err("plain http link rejected", "23514", () => as(ADMIN, () => q("insert into public.sponsored_slots (placement, sponsor, headline, cta_url) values ('hub', 'X', 'Bad link', 'http://example.com')")));
await err("unknown placement rejected", "23514", () => as(ADMIN, () => q("insert into public.sponsored_slots (placement, sponsor, headline, cta_url) values ('popup', 'X', 'Pop', 'https://example.com')")));
await eq("visitors see the running ad", () => as("anon", async () => (await q("select headline from public.sponsored_slots")).rows), [{ headline: "Gaming bundles" }]);
await expectNone("normal player can't pause the ad", () => as(B, async () => (await q("update public.sponsored_slots set active = false where id = $1", [ad])).affectedRows));
await err("admin can't change the ad's link after creation", "42501", () => as(ADMIN, () => q("update public.sponsored_slots set cta_url = 'https://other.example.com' where id = $1", [ad])));
await ok("admin pauses the ad", () => as(ADMIN, () => q("update public.sponsored_slots set active = false where id = $1", [ad])));
await eq("paused ad hidden from visitors", () => as("anon", async () => (await q("select * from public.sponsored_slots")).rows.length), 0);
await eq("admin still sees paused ad", () => as(ADMIN, async () => (await q("select * from public.sponsored_slots")).rows.length), 1);
await ok("admin creates an expired ad", () => as(ADMIN, () => q("insert into public.sponsored_slots (placement, sponsor, headline, cta_url, starts_at, ends_at) values ('chat_lobby', 'Old', 'Expired', 'https://example.com', now() - interval '3 days', now() - interval '1 day')")));
await eq("expired ad hidden from visitors", () => as("anon", async () => (await q("select * from public.sponsored_slots")).rows.length), 0);
await expectNone("normal player can't delete ads", () => as(B, async () => (await q("delete from public.sponsored_slots")).affectedRows));

// Admin breakdown
await err("normal player can't read country breakdown", "42501", () => as(B, () => q("select * from public.admin_waitlist_by_country()")));
await err("anon can't read country breakdown", "42501", () => as("anon", () => q("select * from public.admin_waitlist_by_country()")));
await eq("admin sees per-country numbers", () => as(ADMIN, async () => (await q("select country, signups::int, yes::int, avg_willing_usd_cents::int avg from public.admin_waitlist_by_country() order by country")).rows), [
  { country: "ZA", signups: 1, yes: 1, avg: 300 },
  { country: "ZM", signups: 1, yes: 1, avg: 200 },
  { country: "ZW", signups: 1, yes: 1, avg: null },
]);

async function expectNone(n, fn) { return eq(n, fn, 0); }

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
