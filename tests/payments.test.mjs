// Paynow entry payments: attack tests (2026-11-26).
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

let n = 0;
for (const [u, name] of Object.entries(names)) {
  await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [name]));
  await as(u, () => q("insert into public.profile_contacts (whatsapp_number) values ($1)", [`+2637712345${String(n++).padStart(2, "0")}`]));
}

// --- Setup: server secret (only its SHA-256 is stored) and a paid GameArena tournament.
import crypto from "node:crypto";
const SECRET = "test-payments-secret-0123456789abcdef";
await db.query("insert into private.app_settings (key, value) values ('payments_secret_sha256', $1)", [crypto.createHash("sha256").update(SECRET).digest("hex")]);
const S2 = (await one("select id from public.tournaments where slug = 'warzone-unleashed-s2'")).id;
const CUP = (await as(ADMIN, () => one("insert into public.tournaments (kind, name, entry_fee_usd_cents) values ('tournament', 'Paid Cup', 200) returning id"))).id;
await as(ADMIN, () => q("update public.tournaments set status = 'open' where id = $1", [CUP]));
await ok("A registers for the paid tournament", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await eq("a paid-tournament entry waits for its payment", () => as(A, async () => (await one("select status from public.tournament_entries where tournament_id = $1 and user_id = $2", [CUP, A])).status), "pending");
await ok("A registers for free Warzone too", () => as(A, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [S2])));

// Paid entry is licensed in Zimbabwe only: A and B live in Zimbabwe, C in South Africa.
for (const u of [A, B]) await as(u, () => q("update public.profiles set country = 'ZW' where id = $1", [u]));
await as(C, () => q("update public.profiles set country = 'ZA' where id = $1", [C]));
await ok("C (South Africa) registers for the paid tournament", () => as(C, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await err("C can't pay: paid entry isn't open in South Africa", "PT409", () => as(C, () => q("select * from public.start_entry_payment($1, 'web', true)", [CUP])));
await ok("D (no country set) registers too", () => as(D, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
await err("D can't pay until they set Zimbabwe as their country", "PT409", () => as(D, () => q("select * from public.start_entry_payment($1, 'ecocash', true)", [CUP])));

// --- Starting a payment (player).
await err("visitors can't start a payment", "42501", () => as("anon", () => q("select * from public.start_entry_payment($1, 'ecocash', true)", [CUP])));
await err("B can't pay without registering", "PT409", () => as(B, () => q("select * from public.start_entry_payment($1, 'ecocash', true)", [CUP])));
await err("community tournaments are free: nothing to pay", "PT409", () => as(A, () => q("select * from public.start_entry_payment($1, 'ecocash', true)", [S2])));
await err("unknown payment method refused", "22023", () => as(A, () => q("select * from public.start_entry_payment($1, 'bitcoin', true)", [CUP])));
const pay = await ok("A starts an EcoCash payment", () => as(A, () => one("select * from public.start_entry_payment($1, 'ecocash', true)", [CUP])));
await eq("the amount comes from the tournament ($2.00), not the browser", () => pay.amount_minor, 200);
await eq("a card payment (Paynow's own card page) can be started too", () => as(A, async () => (await one("select amount_minor from public.start_entry_payment($1, 'web', true)", [CUP])).amount_minor), 200);
const REF = pay?.payment_reference;
await err("A can't write payments directly", "42501", () => as(A, () => q("insert into public.payments (reference, tournament_id, user_id, amount_minor, method) values ('GA-AAAAAAAAAA', $1, $2, 1, 'ecocash')", [CUP, A])));
await err("A can't mark their own payment paid", "42501", () => as(A, () => q("update public.payments set status = 'paid' where reference = $1", [REF])));
await eq("A sees their own 2 payments (EcoCash + card), nobody else's", () => as(A, async () => (await q("select reference from public.payments")).rows.length), 2);
await eq("B sees none of A's payments", () => as(B, async () => (await q("select reference from public.payments")).rows.length), 0);

// --- Server steps (need PAYMENTS_SECRET).
await err("mark_payment_sent needs the server secret", "42501", () => as("anon", () => q("select public.mark_payment_sent('wrong-secret-wrong-secret-wrong-secret', $1, 'https://www.paynow.co.zw/interface/poll?x=1')", [REF])));
await err("poll URL must be Paynow's own address", "22023", () => as("anon", () => q("select public.mark_payment_sent($1, $2, 'https://evil.example/poll')", [SECRET, REF])));
await ok("server records that Paynow accepted the request", () => as("anon", () => q("select public.mark_payment_sent($1, $2, 'https://www.paynow.co.zw/interface/poll?guid=abc')", [SECRET, REF])));
await eq("…payment is now 'sent'", () => as(A, async () => (await one("select status from public.payments where reference = $1", [REF])).status), "sent");

const confirm = (who, secret, src, status, amount, hashOk) =>
  as(who, async () => (await one("select public.confirm_payment($1, $2, $3, $4, $5, 'PN123', $6, '{}'::jsonb) o", [secret, REF, src, status, amount, hashOk])).o);
await err("a player can't confirm payments (no secret)", "42501", () => confirm(A, "guess-guess-guess-guess-guess-guess-guess", "poll", "Paid", "2.00", true));
await eq("tampered hash: logged, not paid", () => confirm("anon", SECRET, "callback", "Paid", "2.00", false), "bad_hash");
await eq("'Paid' with the wrong amount: not paid", () => confirm("anon", SECRET, "poll", "Paid", "1.00", true), "amount_mismatch");
await eq("…entry still waiting", () => as(A, async () => (await one("select status from public.tournament_entries where tournament_id = $1 and user_id = $2", [CUP, A])).status), "pending");
await eq("not paid yet ('Sent'): stays pending", () => confirm("anon", SECRET, "poll", "Sent", "2.00", true), "pending");
await eq("'Paid' + exact amount + good hash: paid", () => confirm("anon", SECRET, "poll", "Paid", "2.00", true), "paid");
await eq("…entry approved", () => as(A, async () => (await one("select status from public.tournament_entries where tournament_id = $1 and user_id = $2", [CUP, A])).status), "approved");
const paidAt = await as(A, async () => (await one("select paid_at::text from public.payments where reference = $1", [REF])).paid_at);
await eq("a replayed callback changes nothing", () => confirm("anon", SECRET, "callback", "Paid", "2.00", true), "already_paid");
await eq("…paid time unchanged", () => as(A, async () => (await one("select paid_at::text from public.payments where reference = $1", [REF])).paid_at), paidAt);
await eq("a later 'Cancelled' can't undo a paid entry", () => confirm("anon", SECRET, "poll", "Cancelled", "2.00", true), "already_paid");
await eq("unknown reference is logged, nothing changes", () => as("anon", async () => (await one("select public.confirm_payment($1, 'GA-ZZZZZZZZZZ', 'callback', 'Paid', '2.00', 'X', true, '{}'::jsonb) o", [SECRET])).o), "unknown_reference");
await err("A can't pay twice", "PT409", () => as(A, () => q("select * from public.start_entry_payment($1, 'ecocash', true)", [CUP])));

// --- Audit trail.
await eq("players can't read Paynow messages", () => as(A, async () => (await q("select * from public.payment_events")).rows.length), 0);
await eq("admin reads every Paynow message", () => as(ADMIN, async () => (await one("select count(*)::int n from public.payment_events")).n), 7);

// --- Rate limit.
await ok("B registers for the paid tournament", () => as(B, () => q("insert into public.tournament_entries (tournament_id) values ($1)", [CUP])));
for (let i = 0; i < 5; i++) await as(B, () => q("select * from public.start_entry_payment($1, 'onemoney', true)", [CUP]));
await err("6th payment attempt in 10 minutes is refused", "PT429", () => as(B, () => q("select * from public.start_entry_payment($1, 'onemoney', true)", [CUP])));

// --- "I've paid, check": one check per payment every 10 seconds (hardening, 2026-11-26).
const PAY_A = pay?.payment_id;
await err("visitors can't check a payment", "42501", () => as("anon", () => q("select public.claim_payment_check($1)", [PAY_A])));
await err("B can't check A's payment", "PT404", () => as(B, () => q("select public.claim_payment_check($1)", [PAY_A])));
await ok("A checks their own payment", () => as(A, () => q("select public.claim_payment_check($1)", [PAY_A])));
await err("A checking again straight away is refused", "PT429", () => as(A, () => q("select public.claim_payment_check($1)", [PAY_A])));
await err("A can't reset the check timer", "42501", () => as(A, () => q("update public.payments set last_checked_at = null where id = $1", [PAY_A])));
await q("update public.payments set last_checked_at = now() - interval '11 seconds' where id = $1", [PAY_A]);
await ok("after 10 seconds A can check again", () => as(A, () => q("select public.claim_payment_check($1)", [PAY_A])));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
