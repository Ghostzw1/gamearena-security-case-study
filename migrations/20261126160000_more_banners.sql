-- Three more event banners from the owner's art (2026-11-26), so each
-- tournament can look different: spirit-temple, sakura-raid, inferno.
alter table public.tournaments drop constraint tournaments_banner_check;
alter table public.tournaments
  add constraint tournaments_banner_check check (
    banner in ('spirit-temple', 'sakura-raid', 'inferno', 'codm-hero', 'hub-hero', 'codm', 'pubgm', 'freefire')
  );
