-- Payments hardening (2026-11-26).
-- "I've paid, check" makes our server ask Paynow and write an audit row, so a
-- player tapping it non-stop could flood Paynow and payment_events. Each
-- payment can now be checked by its owner at most once every 10 seconds.
-- (The public callback route stops unsigned messages before the database, in
-- app/api/paynow/result/route.ts.)

alter table public.payments add column last_checked_at timestamptz;

-- Player: claim the right to check one of your own payments now.
-- PT404 = not yours / unknown, PT429 = checked less than 10 seconds ago.
create function public.claim_payment_check(payment uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := auth.uid();
  p public.payments;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  select * into p from public.payments where id = payment and user_id = me for update;
  if p.id is null then
    raise exception 'unknown_payment' using errcode = 'PT404';
  end if;
  if p.last_checked_at is not null and p.last_checked_at > now() - interval '10 seconds' then
    raise exception 'rate_limited' using errcode = 'PT429';
  end if;
  update public.payments set last_checked_at = now() where id = p.id;
end;
$$;
revoke all on function public.claim_payment_check(uuid) from public, anon;
grant execute on function public.claim_payment_check(uuid) to authenticated;
