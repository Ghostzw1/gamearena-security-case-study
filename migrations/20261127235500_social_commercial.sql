-- Social directive v4, Stage 6: commercial readiness (Part 9). Prepared, and
-- switched off.
--
-- 1. Master switches in app_config, both off: ads_enabled (sponsored slots;
--    off until G4, because Vercel Hobby is for non-commercial use) and
--    premium_enabled (nothing uses it yet).
-- 2. Sponsored slots: a category from an allowed list, and the database
--    refuses blocked categories and blocked wording (betting and gambling,
--    alcohol, tobacco, crypto, adult, weapons, political) in the sponsor
--    name, headline, text and link. New placements feed / discover / compete;
--    never in Chats (the old chat_lobby placement is gone; no ad ever used it).
--    While ads are off, nobody sees any slot, admins included.
-- 3. Sponsored tournaments: a sponsor of a Call of Duty: Mobile tournament
--    can only be "confirmed" once an admin records that Activision approved
--    it. Same blocked-wording check on the sponsor's name.
-- 4. Premium profiles and clans: flags in the schema only. Players can't set
--    them, nothing reads them, and no core feature will ever need them.
--
-- Live data checked first (2026-11-27): no sponsored slots exist, and no
-- tournament sponsor is confirmed, so nothing existing is changed.
-- Rollback: drop the columns, functions and triggers added here and restore
-- the placement check, the sponsor-status check and the slot select policy
-- from 20261124200000 / 20261126250000.

-- 1. Switches ------------------------------------------------------------------------
alter table public.app_config
  add column ads_enabled boolean not null default false,
  add column premium_enabled boolean not null default false;

-- 2. Blocked categories and wording ---------------------------------------------------
-- Returns the blocked category a text falls into, or null.
create function private.blocked_ad_category(t text)
returns text
language sql
immutable
set search_path = ''
as $$
  select case
    when t is null then null
    when t ~* '\m(bet|bets|betting|bettor|bookie|bookmaker|bookmakers|sportsbook|casino|casinos|gamble|gambling|jackpot|jackpots|poker|roulette|lotto|lottery|lotteries|slot machines?)\M' then 'gambling'
    when t ~* '\m(alcohol|alcoholic|beer|beers|lager|vodka|whisky|whiskey|gin|rum|brandy|wine|wines|liquor|cider)\M' then 'alcohol'
    when t ~* '\m(tobacco|cigarette|cigarettes|cigar|cigars|vape|vapes|vaping|e-cig|hookah|shisha|snuff)\M' then 'tobacco'
    when t ~* '\m(crypto|cryptocurrency|cryptocurrencies|bitcoin|btc|ethereum|usdt|nft|nfts|web3|blockchain|airdrop|memecoin)\M' then 'crypto'
    when t ~* '\m(porn|porno|xxx|nsfw|escort|escorts|onlyfans|sex|sexy|nude|nudes)\M' then 'adult'
    when t ~* '\m(firearm|firearms|ammunition|ammo|gun shop|gun shops|gun store|buy guns)\M' then 'weapons'
    when t ~* '\m(election|elections|vote for|political|politician|politicians|manifesto|referendum)\M' then 'political'
  end;
$$;
revoke all on function private.blocked_ad_category(text) from public;

create function private.refuse_blocked_ad(variadic texts text[])
returns void
language plpgsql
immutable
set search_path = ''
as $$
declare
  t text;
  hit text;
begin
  foreach t in array texts loop
    hit := private.blocked_ad_category(t);
    if hit is not null then
      raise exception 'blocked_ad_category' using errcode = 'PT422', detail = hit;
    end if;
  end loop;
end;
$$;
revoke all on function private.refuse_blocked_ad(text[]) from public;

-- The allowed categories (betting, alcohol, tobacco, crypto, adult, weapons
-- and political ones are simply not on the list).
create function private.ad_category_ok(c text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select c in ('gaming_gear', 'telecom', 'food_drink', 'apparel', 'tech', 'education', 'events', 'local_business', 'other');
$$;
revoke all on function private.ad_category_ok(text) from public;
grant execute on function private.ad_category_ok(text) to anon, authenticated;

alter table public.sponsored_slots drop constraint sponsored_slots_placement_check;
alter table public.sponsored_slots
  add column category text not null default 'other',
  add constraint sponsored_slots_placement_check check (placement in ('hub', 'codm_home', 'feed', 'discover', 'compete')),
  add constraint sponsored_slots_category_check check (private.ad_category_ok(category));
grant insert (category) on table public.sponsored_slots to authenticated;

create function private.guard_sponsored_slot()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.refuse_blocked_ad(new.sponsor, new.headline, new.body, new.cta_label, new.cta_url);
  return new;
end;
$$;
revoke all on function private.guard_sponsored_slot() from public;
create trigger sponsored_slots_blocked_content
  before insert or update on public.sponsored_slots
  for each row execute function private.guard_sponsored_slot();

-- Nobody sees a slot while ads are switched off.
alter policy "Everyone sees ads that are running" on public.sponsored_slots
  using (
    active and starts_at <= now() and (ends_at is null or ends_at > now())
    and coalesce((select c.ads_enabled from public.app_config c limit 1), false)
  );

-- 3. Sponsored tournaments: Activision's approval before "confirmed" -------------------
alter table public.tournaments
  add column sponsor_category text,
  add column sponsor_publisher_approved boolean not null default false,
  add constraint tournaments_sponsor_category_check check (sponsor_category is null or private.ad_category_ok(sponsor_category));
alter table public.tournaments drop constraint tournaments_sponsor_status_check;
alter table public.tournaments add constraint tournaments_sponsor_status_check check (
  sponsor_status in ('none', 'pending', 'confirmed')
  and (sponsor_status <> 'confirmed' or sponsor_name is not null)
  and (sponsor_status <> 'confirmed' or game <> 'codm' or sponsor_publisher_approved)
);
grant insert (sponsor_category, sponsor_publisher_approved) on table public.tournaments to authenticated;
grant update (sponsor_category, sponsor_publisher_approved) on table public.tournaments to authenticated;

create function private.guard_tournament_sponsor()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.is_admin() and (
    (tg_op = 'INSERT' and (new.sponsor_category is not null or new.sponsor_publisher_approved))
    or (tg_op = 'UPDATE' and (new.sponsor_category is distinct from old.sponsor_category
                              or new.sponsor_publisher_approved is distinct from old.sponsor_publisher_approved))
  ) then
    raise exception 'admins_only' using errcode = '42501';
  end if;
  perform private.refuse_blocked_ad(new.sponsor_name);
  return new;
end;
$$;
revoke all on function private.guard_tournament_sponsor() from public;
create trigger tournaments_guard_sponsor
  before insert or update of sponsor_name, sponsor_category, sponsor_publisher_approved on public.tournaments
  for each row execute function private.guard_tournament_sponsor();

-- 4. Premium flags (schema only; no paywall, nothing reads them) -------------------------
alter table public.profiles add column premium boolean not null default false;
alter table public.chat_channels add column premium boolean not null default false;
comment on column public.profiles.premium is 'Prepared for a future optional premium profile. Never gates a core social or competitive feature (directive v4, Part 9). Not settable by players.';
comment on column public.chat_channels.premium is 'Prepared for a future optional premium clan. Never gates a core feature. Not settable by players.';
