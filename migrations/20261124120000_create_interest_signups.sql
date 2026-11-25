-- Milestone 1: interest survey sign-ups.
--
-- Security model (also written up in SECURITY.md):
--   1. RLS is ON. The only policy lets the `anon` role INSERT a row.
--      Nobody can SELECT, UPDATE or DELETE through the public API.
--      You read the sign-ups in the Supabase dashboard, which uses a
--      privileged role that RLS does not apply to.
--   2. Table privileges are trimmed to match RLS: `anon` may insert only the
--      columns a visitor fills in. `id` and `created_at` are always set by the
--      database, so nobody can fake them.
--   3. CHECK constraints repeat the server-side validation, so bad data is
--      rejected even if someone calls the Supabase API directly.
--   4. A trigger rate-limits inserts (per hashed IP and overall) to stop
--      spam floods.

-- A schema that the public API never exposes. Helper functions live here.
create schema if not exists private;
revoke all on schema private from public;

-- ---------------------------------------------------------------------------
-- Table
-- ---------------------------------------------------------------------------
create table public.interest_signups (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  full_name text not null,
  codm_ign text not null,
  whatsapp_number text not null,
  preferred_format text not null,
  would_pay text not null,
  contact_consent boolean not null default false,
  -- HMAC-SHA256 of the visitor's IP, made with a server-only secret.
  -- Used only for rate limiting. The raw IP is never stored.
  ip_hash text,

  constraint interest_signups_full_name_check check (
    char_length(full_name) between 2 and 60
    and full_name = btrim(full_name)
    and full_name !~ '[[:cntrl:]]'
  ),
  -- CODM names often use fancy Unicode, so we allow it. We block control
  -- characters, zero-width characters and text-direction overrides, which
  -- can be used to make one name look like another.
  constraint interest_signups_codm_ign_check check (
    char_length(codm_ign) between 2 and 24
    and codm_ign = btrim(codm_ign)
    and codm_ign !~ '[[:cntrl:]\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]'
  ),
  -- Always stored in international (E.164) format, e.g. +263771234567.
  constraint interest_signups_whatsapp_number_check check (
    whatsapp_number ~ '^\+[1-9][0-9]{7,14}$'
  ),
  -- One sign-up per number, so the "yes" count can't be inflated.
  constraint interest_signups_whatsapp_number_key unique (whatsapp_number),
  constraint interest_signups_preferred_format_check check (
    preferred_format in ('solo', 'duo', 'squad')
  ),
  constraint interest_signups_would_pay_check check (
    would_pay in ('yes', 'maybe', 'no')
  ),
  constraint interest_signups_contact_consent_check check (contact_consent),
  constraint interest_signups_ip_hash_check check (
    ip_hash is null or ip_hash ~ '^[0-9a-f]{64}$'
  )
);

comment on table public.interest_signups is
  'Milestone 1 interest survey. Anonymous insert only; no public read. Contains private WhatsApp numbers.';

create index interest_signups_created_at_idx
  on public.interest_signups (created_at desc);

create index interest_signups_ip_hash_created_at_idx
  on public.interest_signups (ip_hash, created_at desc)
  where ip_hash is not null;

-- ---------------------------------------------------------------------------
-- Privileges + Row Level Security
-- ---------------------------------------------------------------------------
alter table public.interest_signups enable row level security;

-- Supabase grants every API role full access to new tables by default.
-- Take it all away, then give back only what the form needs.
revoke all on table public.interest_signups from public, anon, authenticated;

grant insert (
  full_name,
  codm_ign,
  whatsapp_number,
  preferred_format,
  would_pay,
  contact_consent,
  ip_hash
) on table public.interest_signups to anon;

-- The only policy. With no SELECT / UPDATE / DELETE policies, those
-- operations are denied for every API role.
create policy "Visitors can submit the interest form"
  on public.interest_signups
  for insert
  to anon
  with check (contact_consent);

-- ---------------------------------------------------------------------------
-- Rate limiting
-- ---------------------------------------------------------------------------
-- SECURITY DEFINER lets the trigger count existing rows even though the
-- visitor (anon) can't read the table. `search_path = ''` stops anyone
-- from hijacking it with look-alike objects in another schema.
create function private.interest_signups_rate_limit()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  recent_total integer;
  recent_same_ip integer;
begin
  -- Overall cap: stops a flood from many IPs at once.
  select count(*) into recent_total
  from public.interest_signups
  where created_at > now() - interval '10 minutes';

  if recent_total >= 100 then
    raise exception 'rate_limited' using errcode = 'PT429';
  end if;

  -- Per-IP cap. Kept generous because Zimbabwean mobile networks put many
  -- phones behind one shared IP, and a WhatsApp group can all tap the link
  -- at the same moment.
  if new.ip_hash is not null then
    select count(*) into recent_same_ip
    from public.interest_signups
    where ip_hash = new.ip_hash
      and created_at > now() - interval '10 minutes';

    if recent_same_ip >= 10 then
      raise exception 'rate_limited' using errcode = 'PT429';
    end if;
  end if;

  return new;
end;
$$;

revoke all on function private.interest_signups_rate_limit() from public;

create trigger interest_signups_rate_limit
  before insert on public.interest_signups
  for each row
  execute function private.interest_signups_rate_limit();
