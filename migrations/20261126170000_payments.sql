-- Entry-fee payments through Paynow (owner, 2026-11-26: Zimbabwe Lotteries and
-- Gaming Board licence in hand; built in Paynow TEST mode first).
--
-- CLAUDE.md rule: an entry counts as paid only after the server
--   1. receives Paynow's result callback (or polls when the player returns),
--   2. verifies Paynow's hash with the integration key (server code), and
--   3. polls Paynow and gets status "Paid" with the exact amount.
-- The browser can only start a payment for its own entry and read its own
-- payments; it can never mark anything paid. Only the server, holding
-- PAYMENTS_SECRET (checked here by its SHA-256 hash, like the cron secret),
-- records what Paynow said, through confirm_payment().

create table public.payments (
  id uuid primary key default gen_random_uuid(),
  reference text not null unique,
  tournament_id uuid not null references public.tournaments (id) on delete restrict,
  -- Kept as a financial record if the player deletes their account.
  user_id uuid references public.profiles (id) on delete set null,
  amount_minor integer not null,
  currency text not null default 'USD',
  method text not null,
  status text not null default 'created',
  paynow_reference text,
  poll_url text,
  test_mode boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  paid_at timestamptz,
  constraint payments_amount_check check (amount_minor > 0 and amount_minor <= 100000),
  constraint payments_currency_check check (currency in ('USD')),
  constraint payments_method_check check (method in ('ecocash', 'onemoney', 'web')),
  constraint payments_status_check check (status in ('created', 'sent', 'paid', 'failed', 'cancelled', 'refunded')),
  constraint payments_poll_url_check check (poll_url is null or poll_url like 'https://www.paynow.co.zw/%'),
  constraint payments_reference_check check (reference ~ '^GA-[A-Z0-9]{10}$')
);
create index payments_user_idx on public.payments (user_id);
create index payments_tournament_idx on public.payments (tournament_id);

alter table public.payments enable row level security;
revoke all on table public.payments from anon, authenticated;
grant select on table public.payments to authenticated;
-- Players see their own payments; admins see all. Nobody writes directly.
create policy payments_select_own_or_admin on public.payments
  for select to authenticated
  using (user_id = (select auth.uid()) or (select private.is_admin()));

-- Every message from Paynow (callback or poll), as received, for audits and
-- reconciliation. Admins only.
create table public.payment_events (
  id bigint generated always as identity primary key,
  payment_id uuid references public.payments (id) on delete set null,
  reference text not null,
  source text not null,
  status text,
  amount text,
  paynow_reference text,
  hash_ok boolean not null,
  outcome text not null,
  raw jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint payment_events_source_check check (source in ('callback', 'poll'))
);
create index payment_events_payment_idx on public.payment_events (payment_id);
alter table public.payment_events enable row level security;
revoke all on table public.payment_events from anon, authenticated;
grant select on table public.payment_events to authenticated;
create policy payment_events_admin_select on public.payment_events
  for select to authenticated using ((select private.is_admin()));

-- Server secret: only its SHA-256 hash is stored (private.app_settings).
create function private.check_payments_secret(candidate text)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  expected text;
begin
  select value into expected from private.app_settings where key = 'payments_secret_sha256';
  if expected is null
     or candidate is null
     or char_length(candidate) < 32
     or encode(sha256(convert_to(candidate, 'UTF8')), 'hex') <> expected then
    raise exception 'bad_secret' using errcode = '42501';
  end if;
end;
$$;
revoke all on function private.check_payments_secret(text) from public;

-- Paid tournaments: a new entry waits for its payment (it can't see the room
-- or the players until the payment is confirmed).
create or replace function private.set_entry_status()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  ev record;
begin
  select requires_approval, kind, entry_fee_usd_cents into ev from public.tournaments where id = new.tournament_id;
  new.status := case
    when ev.kind = 'tournament' and ev.entry_fee_usd_cents > 0 then 'pending'
    when ev.requires_approval then 'pending'
    else 'approved'
  end;
  return new;
end;
$$;

-- Player: start paying for their own entry. The amount always comes from the
-- tournament, never from the browser.
create function public.start_entry_payment(t uuid, pay_method text, is_test boolean)
returns table (payment_id uuid, payment_reference text, amount_minor integer)
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  ev record;
  ref text;
  pid uuid;
begin
  if me is null then
    raise exception 'not_signed_in' using errcode = '42501';
  end if;
  if pay_method is null or pay_method not in ('ecocash', 'onemoney', 'web') then
    raise exception 'bad_method' using errcode = '22023';
  end if;
  select id, kind, status, entry_fee_usd_cents into ev from public.tournaments where id = t;
  if ev.id is null then
    raise exception 'not_found' using errcode = 'PT404';
  end if;
  if ev.kind <> 'tournament' or ev.entry_fee_usd_cents <= 0 then
    raise exception 'free_event' using errcode = 'PT409';
  end if;
  if ev.status <> 'open' then
    raise exception 'registration_closed' using errcode = 'PT409';
  end if;
  if not exists (select 1 from public.tournament_entries e where e.tournament_id = t and e.user_id = me) then
    raise exception 'register_first' using errcode = 'PT409';
  end if;
  if exists (select 1 from public.payments p where p.tournament_id = t and p.user_id = me and p.status = 'paid') then
    raise exception 'already_paid' using errcode = 'PT409';
  end if;
  if (select count(*) from public.payments p where p.user_id = me and p.created_at > now() - interval '10 minutes') >= 5 then
    raise exception 'rate_limited' using errcode = 'PT429';
  end if;
  ref := 'GA-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10));
  insert into public.payments (reference, tournament_id, user_id, amount_minor, method, test_mode)
  values (ref, t, me, ev.entry_fee_usd_cents, pay_method, coalesce(is_test, true))
  returning id into pid;
  return query select pid, ref, ev.entry_fee_usd_cents;
end;
$$;
revoke all on function public.start_entry_payment(uuid, text, boolean) from public, anon;
grant execute on function public.start_entry_payment(uuid, text, boolean) to authenticated;

-- Server only: Paynow accepted the request; keep its poll URL (Paynow's own
-- address only, so the server can never be pointed somewhere else).
create function public.mark_payment_sent(server_secret text, ref text, poll text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.check_payments_secret(server_secret);
  if poll is null or poll not like 'https://www.paynow.co.zw/%' then
    raise exception 'bad_poll_url' using errcode = '22023';
  end if;
  update public.payments
  set status = 'sent', poll_url = poll, updated_at = now()
  where reference = ref and status = 'created';
end;
$$;
revoke all on function public.mark_payment_sent(text, text, text) from public;
grant execute on function public.mark_payment_sent(text, text, text) to anon, authenticated;

-- Server only: record what Paynow said, after the server checked the hash.
-- Marks the payment paid ONLY for status "Paid" with the exact amount, once
-- (a repeated or replayed message changes nothing). Every call is logged.
create function public.confirm_payment(
  server_secret text,
  ref text,
  src text,
  pn_status text,
  pn_amount text,
  pn_reference text,
  hash_ok boolean,
  raw jsonb
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  p public.payments;
  outcome text;
  paid_minor integer;
begin
  perform private.check_payments_secret(server_secret);
  if src is null or src not in ('callback', 'poll') then
    raise exception 'bad_source' using errcode = '22023';
  end if;
  select * into p from public.payments where reference = ref for update;
  if p.id is null then
    outcome := 'unknown_reference';
  elsif not coalesce(hash_ok, false) then
    outcome := 'bad_hash';
  elsif p.status = 'paid' then
    outcome := 'already_paid';
  else
    begin
      paid_minor := round(pn_amount::numeric * 100)::integer;
    exception when others then
      paid_minor := null;
    end;
    if lower(coalesce(pn_status, '')) = 'paid' then
      if paid_minor is distinct from p.amount_minor then
        outcome := 'amount_mismatch';
      else
        update public.payments
        set status = 'paid', paid_at = now(), updated_at = now(), paynow_reference = pn_reference
        where id = p.id;
        update public.tournament_entries
        set status = 'approved'
        where tournament_id = p.tournament_id and user_id = p.user_id;
        outcome := 'paid';
      end if;
    elsif lower(coalesce(pn_status, '')) in ('cancelled', 'failed') then
      update public.payments set status = lower(pn_status), updated_at = now() where id = p.id;
      outcome := lower(pn_status);
    else
      outcome := 'pending';
    end if;
  end if;
  insert into public.payment_events (payment_id, reference, source, status, amount, paynow_reference, hash_ok, outcome, raw)
  values (p.id, coalesce(ref, ''), src, pn_status, pn_amount, pn_reference, coalesce(hash_ok, false), outcome, coalesce(raw, '{}'::jsonb));
  return outcome;
end;
$$;
revoke all on function public.confirm_payment(text, text, text, text, text, text, boolean, jsonb) from public;
grant execute on function public.confirm_payment(text, text, text, text, text, text, boolean, jsonb) to anon, authenticated;
