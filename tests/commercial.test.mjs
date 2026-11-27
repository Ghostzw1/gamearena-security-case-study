// Social v4 Stage 6: commercial readiness: sponsored slots off by default, blocked categories and wording, Activision approval for tournament sponsors, premium flags (2026-11-27).
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
const call = (who, sql, params) => as(who, () => q(sql, params));
const slot = (who, o = {}) =>
  call(who, "insert into public.sponsored_slots (placement, sponsor, headline, body, cta_url, category) values ($1, $2, $3, $4, $5, $6) returning id", [
    o.placement ?? "feed",
    o.sponsor ?? "Harare Gaming Gear",
    o.headline ?? "New controllers in stock",
    o.body ?? null,
    o.url ?? "https://example.com/controllers",
    o.category ?? "gaming_gear",
  ]);
const visible = (who) => as(who, async () => (await q("select sponsor from public.sponsored_slots order by sponsor")).rows.map((r) => r.sponsor));
const blocked = async (n, o, cat) => {
  try {
    await slot(ADMIN, o);
    fail++;
    console.log(`FAIL  ${n}: expected blocked (${cat}), got success`);
  } catch (e) {
    if (e.code === "PT422" && e.detail === cat) {
      pass++;
      console.log(`PASS  ${n} (${e.code} ${cat})`);
    } else {
      fail++;
      console.log(`FAIL  ${n}: expected PT422 ${cat}, got ${e.code} ${e.detail ?? ""} ${e.message}`);
    }
  }
};

// ===== Switches start off =====
await eq("ads and premium are switched off", () => one("select ads_enabled, premium_enabled from public.app_config"), { ads_enabled: false, premium_enabled: false });

// ===== Sponsored slots =====
await ok("an admin books a real sponsor in the feed", () => slot(ADMIN));
await eq("…with ads off, visitors see no slot", () => visible("anon"), []);
await eq("…and neither do players", () => visible(A), []);
await eq("…the admin still sees the booking in the admin panel", () => visible(ADMIN), ["Harare Gaming Gear"]);
await q("update public.app_config set ads_enabled = true");
await eq("switched on (after G4), visitors see it", () => visible("anon"), ["Harare Gaming Gear"]);
await q("update public.app_config set ads_enabled = false");
await eq("switched off again, it's gone", () => visible("anon"), []);
await err("players can't book slots", "42501", () => slot(A));
await err("never in Chats: no chat placement exists", "23514", () => slot(ADMIN, { placement: "chat_lobby", sponsor: "Chat Ad" }));
await err("a blocked category can't even be chosen", "23514", () => slot(ADMIN, { category: "betting", sponsor: "Some Sponsor" }));

// Blocked wording, anywhere in the ad
await blocked("betting in the headline", { headline: "Bet on the CODM final" }, "gambling");
await blocked("a casino sponsor", { sponsor: "Lucky Casino" }, "gambling");
await blocked("alcohol in the text", { body: "Free beer for every squad" }, "alcohol");
await blocked("a vape shop", { sponsor: "Vape City" }, "tobacco");
await blocked("crypto in the link", { url: "https://bitcoin-deals.example.com/" }, "crypto");
await blocked("adult content", { headline: "XXX streams tonight" }, "adult");
await blocked("a gun shop", { body: "Gun shop opening in Harare" }, "weapons");
await blocked("political ads", { headline: "Vote for change in the election" }, "political");
await ok("ordinary words that only contain those letters still pass", () =>
  slot(ADMIN, { sponsor: "Gunsmith Gear", headline: "Login and win the best headset", body: "Team spirit, pistol grips and an alphabet of skins", category: "tech" }),
);

// ===== Sponsored tournaments: Activision approval =====
const T = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, format, status) values ('community', 'Sponsored Night', 'squad', 'open') returning id"))).id;
await err("a CODM tournament sponsor can't be confirmed without Activision's approval", "23514", () =>
  call(ADMIN, "update public.tournaments set sponsor_name = 'Harare Gaming Gear', sponsor_status = 'confirmed' where id = $1", [T]),
);
await ok("pending is fine while waiting for the approval", () => call(ADMIN, "update public.tournaments set sponsor_name = 'Harare Gaming Gear', sponsor_status = 'pending', sponsor_category = 'gaming_gear' where id = $1", [T]));
await ok("once an admin records the approval, it can be confirmed", () =>
  call(ADMIN, "update public.tournaments set sponsor_publisher_approved = true, sponsor_status = 'confirmed' where id = $1", [T]),
);
const R = (await as(A, () => one("insert into public.tournaments (name, format) values ('My Room', 'solo') returning id"))).id;
await err("a host can't record Activision's approval", "42501", () => call(A, "update public.tournaments set sponsor_publisher_approved = true where id = $1", [R]));
await err("…or pick a sponsor category", "42501", () => call(A, "update public.tournaments set sponsor_category = 'tech' where id = $1", [R]));
await err("a betting sponsor can't sponsor a tournament", "PT422", () => call(ADMIN, "update public.tournaments set sponsor_name = 'Mega Bet' where id = $1", [T]));
await err("blocked categories can't be picked for tournaments either", "23514", () => call(ADMIN, "update public.tournaments set sponsor_category = 'crypto' where id = $1", [T]));

// ===== Premium flags: schema only =====
await eq("everyone starts without premium", async () => (await one("select count(*)::int n from public.profiles where premium")).n, 0);
await err("players can't make themselves premium", "42501", () => call(A, "update public.profiles set premium = true where id = $1", [A]));
await eq("players can't switch ads on", async () => {
  try {
    await call(A, "update public.app_config set ads_enabled = true");
  } catch {
    /* refused */
  }
  return (await one("select ads_enabled from public.app_config")).ads_enabled;
}, false);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
