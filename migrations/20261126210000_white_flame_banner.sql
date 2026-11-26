-- Warzone Unleashed gets its own banner (owner, 2026-11-26): the owner's
-- picture, cropped so no logo, word or watermark is left ("white-flame").
alter table public.tournaments drop constraint tournaments_banner_check;
alter table public.tournaments
  add constraint tournaments_banner_check check (
    banner in ('white-flame', 'spirit-temple', 'sakura-raid', 'inferno', 'codm-hero', 'hub-hero', 'codm', 'pubgm', 'freefire')
  );
update public.tournaments set banner = 'white-flame' where slug in ('warzone-unleashed-s1', 'warzone-unleashed-s2');
