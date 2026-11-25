-- Going regional (Zimbabwe, South Africa, Zambia) + sponsor ad slots.

-- ---------------------------------------------------------------------------
-- Waitlist: where people are and how much they'd pay
-- ---------------------------------------------------------------------------
alter table public.interest_signups
  add column country text not null default 'ZW',
  add column display_currency text,
  add column willing_amount_usd_cents integer,
  add constraint interest_signups_country_check check (country in ('ZW', 'ZA', 'ZM', 'OTHER')),
  add constraint interest_signups_display_currency_check check (
    display_currency is null or display_currency ~ '^[A-Z]{3}$'
  ),
  add constraint interest_signups_willing_amount_check check (
    willing_amount_usd_cents is null or willing_amount_usd_cents between 50 and 5000
  );

grant insert (country, display_currency, willing_amount_usd_cents) on table public.interest_signups to anon;

-- ---------------------------------------------------------------------------
-- Profiles: home country (for currency, payment methods, local tournaments)
-- ---------------------------------------------------------------------------
alter table public.profiles
  add column country text,
  add constraint profiles_country_check check (country is null or country in ('ZW', 'ZA', 'ZM', 'OTHER'));

grant insert (country), update (country) on table public.profiles to authenticated;

-- ---------------------------------------------------------------------------
-- Sponsor slots: our own text ads, no third-party scripts or tracking
-- ---------------------------------------------------------------------------
create table public.sponsored_slots (
  id uuid primary key default gen_random_uuid(),
  placement text not null,
  sponsor text not null,
  headline text not null,
  body text,
  cta_label text not null default 'Learn more',
  cta_url text not null,
  country text,
  starts_at timestamptz not null default now(),
  ends_at timestamptz,
  active boolean not null default true,
  created_by uuid default auth.uid() references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),

  constraint sponsored_slots_placement_check check (placement in ('hub', 'codm_home', 'chat_lobby')),
  constraint sponsored_slots_sponsor_check check (char_length(sponsor) between 2 and 40 and sponsor !~ '[[:cntrl:]]'),
  constraint sponsored_slots_headline_check check (char_length(headline) between 3 and 60 and headline !~ '[[:cntrl:]]'),
  constraint sponsored_slots_body_check check (body is null or (char_length(body) <= 140 and body !~ '[[:cntrl:]]')),
  constraint sponsored_slots_cta_label_check check (char_length(cta_label) between 2 and 24 and cta_label !~ '[[:cntrl:]]'),
  -- HTTPS only: no javascript:, data: or plain-http links in ads.
  constraint sponsored_slots_cta_url_check check (
    char_length(cta_url) <= 300 and cta_url ~ '^https://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/[^[:space:]<>"]*)?$'
  ),
  constraint sponsored_slots_country_check check (country is null or country in ('ZW', 'ZA', 'ZM', 'OTHER')),
  constraint sponsored_slots_dates_check check (ends_at is null or ends_at > starts_at)
);

create index sponsored_slots_live_idx on public.sponsored_slots (placement, starts_at) where active;

alter table public.sponsored_slots enable row level security;
revoke all on table public.sponsored_slots from public, anon, authenticated;
grant select on table public.sponsored_slots to anon, authenticated;
grant insert (placement, sponsor, headline, body, cta_label, cta_url, country, starts_at, ends_at, active)
  on table public.sponsored_slots to authenticated;
grant update (active, ends_at) on table public.sponsored_slots to authenticated;
grant delete on table public.sponsored_slots to authenticated;

create policy "Everyone sees ads that are running"
  on public.sponsored_slots for select to anon, authenticated
  using (active and starts_at <= now() and (ends_at is null or ends_at > now()));

create policy "Admins see every ad"
  on public.sponsored_slots for select to authenticated
  using (private.is_admin());

create policy "Admins create ads"
  on public.sponsored_slots for insert to authenticated
  with check (private.is_admin());

create policy "Admins pause or end ads"
  on public.sponsored_slots for update to authenticated
  using (private.is_admin())
  with check (private.is_admin());

create policy "Admins delete ads"
  on public.sponsored_slots for delete to authenticated
  using (private.is_admin());

-- ---------------------------------------------------------------------------
-- Admin: waitlist by country (count, yes answers, average amount they'd pay)
-- ---------------------------------------------------------------------------
create function public.admin_waitlist_by_country()
returns table (country text, signups bigint, yes bigint, avg_willing_usd_cents numeric)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  return query
    select s.country, count(*), count(*) filter (where s.would_pay = 'yes'),
           round(avg(s.willing_amount_usd_cents))
      from public.interest_signups s
     group by s.country
     order by count(*) desc;
end;
$$;
revoke all on function public.admin_waitlist_by_country() from public;
revoke execute on function public.admin_waitlist_by_country() from anon;
grant execute on function public.admin_waitlist_by_country() to authenticated;
