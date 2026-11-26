-- Card payments (Paynow's own card page, method 'web') and a country check
-- (owner, 2026-11-26): paid entry is licensed in Zimbabwe only, and a card
-- works from anywhere, so only players whose profile country is Zimbabwe can
-- start a payment. Same function otherwise (20261126170000_payments.sql).
create or replace function public.start_entry_payment(t uuid, pay_method text, is_test boolean)
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
  -- Paid entry is licensed in Zimbabwe only (owner, 2026-11-26). Cards work
  -- from anywhere, so the player's profile country must be Zimbabwe.
  -- Keep in sync with PAID_ENTRY_COUNTRIES in lib/regions.ts.
  if coalesce((select pr.country from public.profiles pr where pr.id = me), '') <> 'ZW' then
    raise exception 'country_not_open' using errcode = 'PT409';
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
