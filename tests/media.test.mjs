// Chat pictures, videos and stickers: attack tests.
import { PGlite } from "@electric-sql/pglite";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import crypto from "node:crypto";
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
const ADMIN = id("ad"), A = id("0a"), B = id("0b"), C = id("0c");
for (const u of [ADMIN, A, B, C]) await db.query("insert into auth.users (id) values ($1)", [u]);
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

for (const [u, n] of [[ADMIN, "Dynasty"], [A, "Alpha"], [B, "Bravo"], [C, "Charlie"]]) await as(u, () => q("insert into public.profiles (username, avatar_id) values ($1, 'op-recon-m')", [n]));
const community = (await one("select id from public.chat_channels where slug = 'codm-community'")).id;
const file = (owner, ext) => `${owner}/${crypto.randomUUID()}.${ext}`;
const upload = (user, name, size = 200000) => as(user, () => q("insert into storage.objects (bucket_id, name, metadata) values ('chat-media', $1, $2)", [name, JSON.stringify({ size, mimetype: "image/webp" })]));
const post = (user, channel, cols) => as(user, () => {
  const keys = Object.keys(cols);
  return q(`insert into public.chat_messages (channel_id, ${keys.join(", ")}) values ($1, ${keys.map((_, i) => `$${i + 2}`).join(", ")}) returning id`, [channel, ...keys.map((k) => cols[k])]);
});

await eq("the bucket is private", () => one("select public, file_size_limit from storage.buckets where id = 'chat-media'"), { public: false, file_size_limit: 15728640 });

// --- Stickers ---------------------------------------------------------------
await ok("A sends a sticker", () => post(A, community, { sticker_id: "gg-ez" }));
await err("weird sticker ids rejected", "23514", () => post(A, community, { sticker_id: "<script>" }));
await err("empty messages rejected", "23514", () => post(A, community, { body: null }));

// --- Uploads ----------------------------------------------------------------
const pic = file(A, "webp");
await ok("A uploads a picture to their own folder", () => upload(A, pic));
await err("A can't upload into B's folder", "42501", () => upload(A, file(B, "webp")));
await err("visitors can't upload", "42501", () => as("anon", () => q("insert into storage.objects (bucket_id, name) values ('chat-media', $1)", [file(A, "png")])));
await eq("B can't open A's file before it's posted", () => as(B, async () => (await q("select name from storage.objects where name = $1", [pic])).rows.length), 0);
await ok("A posts the picture with a caption", () => post(A, community, { media_path: pic, media_kind: "image", body: "Look at this squad wipe" }));
await eq("B (in the community chat) can now open it", () => as(B, async () => (await q("select name from storage.objects where name = $1", [pic])).rows.length), 1);
await err("B can't attach A's file to their own message", "42501", () => post(B, community, { media_path: pic, media_kind: "image" }));
await err("attaching a file that was never uploaded", "PT422", () => post(A, community, { media_path: file(A, "jpg"), media_kind: "image" }));
const clip = file(A, "mp4");
await upload(A, clip, 9000000);
await err("a video can't pretend to be a picture", "PT422", () => post(A, community, { media_path: clip, media_kind: "image" }));
await ok("A posts the video", () => post(A, community, { media_path: clip, media_kind: "video" }));
const big = file(A, "png");
await upload(A, big, 5000000);
await err("pictures over 3 MB rejected", "PT422", () => post(A, community, { media_path: big, media_kind: "image" }));
await err("sticker + file in one message rejected", "23514", () => post(A, community, { sticker_id: "gg-ez", media_path: pic, media_kind: "image" }));
await err("odd file names rejected (never reach storage)", "PT422", () => post(A, community, { media_path: `${A}/../../etc/passwd`, media_kind: "image" }));
await err("A can't delete B's files", "42501", async () => { const r = await as(A, () => q("delete from storage.objects where name like $1", [`${B}/%`])); if (r.affectedRows === 0) { const e = new Error("none"); e.code = "42501"; throw e; } });

// --- Private chats keep their files private ----------------------------------
const clan = await as(A, async () => (await one("insert into public.chat_channels (name, tag) values ('Wolves', 'WLF') returning id")).id);
await as(ADMIN, () => q("select public.review_clan($1, true)", [clan]));
const secret = file(A, "jpg");
await upload(A, secret);
await ok("A posts a picture in the clan chat", () => post(A, clan, { media_path: secret, media_kind: "image" }));
await eq("C (not in the clan) can't open the clan picture", () => as(C, async () => (await q("select name from storage.objects where name = $1", [secret])).rows.length), 0);
await eq("admin can open it (moderation)", () => as(ADMIN, async () => (await q("select name from storage.objects where name = $1", [secret])).rows.length), 1);
await ok("A deletes the clan message", async () => { const m = (await one("select id from public.chat_messages where media_path = $1", [secret])).id; await as(A, () => q("select public.delete_chat_message($1)", [m])); });
await eq("deleted message: other players can't open the file any more", () => as(B, async () => (await q("select name from storage.objects where name = $1", [secret])).rows.length), 0);

// --- Rate limit ---------------------------------------------------------------
await err("max 10 pictures/videos per 10 minutes", "PT429", async () => {
  for (let i = 0; i < 12; i++) {
    const p = file(B, "webp");
    await upload(B, p);
    await db.query("update public.chat_messages set created_at = created_at - interval '20 seconds' where user_id = $1", [B]);
    await post(B, community, { media_path: p, media_kind: "image" });
  }
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
