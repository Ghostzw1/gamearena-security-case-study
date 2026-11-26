-- Balance the pictures (owner, 2026-11-26: "the app looks girlish"): the
-- current Warzone Unleashed season gets the owner's spirit-temple banner;
-- Season 1 (finished) keeps white-flame.
update public.tournaments set banner = 'spirit-temple' where slug = 'warzone-unleashed-s2';
