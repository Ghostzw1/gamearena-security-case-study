-- One public, read-only list of event cards for the Tournaments tab:
-- event info + its host's public name/avatar/clan tag + player counts.
-- Visitors can't read profiles directly, so this returns only what a
-- tournament poster would show anyway.
create function public.event_cards()
returns table (
  id uuid, slug text, kind text, name text, season integer, status text, format text, mode text,
  sponsor_name text, banner text, starts_at timestamptz, matches integer, max_players integer,
  entry_fee_usd_cents integer, prize_1_usd_cents integer, prize_2_usd_cents integer, prize_3_usd_cents integer,
  players integer, pending integer,
  host_username text, host_avatar text, host_tag text, created_at timestamptz
)
language sql
stable
security definer
set search_path = ''
as $$
  select t.id, t.slug, t.kind, t.name, t.season, t.status, t.format, t.mode,
    t.sponsor_name, t.banner, t.starts_at, t.matches, t.max_players,
    t.entry_fee_usd_cents, t.prize_1_usd_cents, t.prize_2_usd_cents, t.prize_3_usd_cents,
    (select count(*) from public.tournament_entries e where e.tournament_id = t.id and e.status = 'approved')::integer,
    (select count(*) from public.tournament_entries e where e.tournament_id = t.id and e.status = 'pending')::integer,
    h.username, h.avatar_id, h.clan_tag, t.created_at
  from public.tournaments t
  left join lateral (
    select p.username, p.avatar_id, p.clan_tag
    from public.tournament_staff s
    join public.profiles p on p.id = s.user_id
    where s.tournament_id = t.id and s.role = 'host'
    order by s.added_at
    limit 1
  ) h on true
  where t.game = 'codm'
  order by t.created_at desc
  limit 100;
$$;

revoke all on function public.event_cards() from public;
grant execute on function public.event_cards() to anon, authenticated;
