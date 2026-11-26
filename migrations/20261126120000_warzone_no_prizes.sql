-- Warzone Unleashed has no prizes (owner's decision, 2026-11-26): players play
-- for the leaderboard. A host or sponsor may still offer prizes later; an
-- admin then sets them in Admin → the event → "Sponsor & prizes".
--
-- Why the guard is paused: tournaments_guard_update only lets a signed-in
-- admin (two-step login) change prizes. This approved data fix runs as the
-- database owner during a migration, so the guard is paused for this one
-- statement and switched straight back on in the same transaction. Undo:
-- set the three prize columns back to 10000 / 5000 / 3000 for both slugs.

alter table public.tournaments disable trigger tournaments_guard_update;

update public.tournaments
set prize_1_usd_cents = 0, prize_2_usd_cents = 0, prize_3_usd_cents = 0
where slug in ('warzone-unleashed-s1', 'warzone-unleashed-s2');

alter table public.tournaments enable trigger tournaments_guard_update;
