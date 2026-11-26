-- Disputes: one subject input plus a "squad or player" flag instead of two
-- optional inputs (clearer for callers, and the generated types stay exact).
drop function public.open_dispute(uuid, integer, uuid, uuid, text);
create function public.open_dispute(t uuid, match integer, subject uuid, subject_is_squad boolean, why text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  new_id bigint;
  subject_squad uuid := case when subject_is_squad then subject end;
  subject_player uuid := case when not subject_is_squad then subject end;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if not exists (select 1 from public.tournaments where id = t and status in ('live', 'completed')) then
    raise exception 'no_results_yet' using errcode = 'PT409';
  end if;
  if not exists (select 1 from public.tournament_entries where tournament_id = t and user_id = me and status = 'approved') then
    raise exception 'players_only' using errcode = '42501';
  end if;
  if subject is null or subject_is_squad is null then
    raise exception 'bad_subject' using errcode = '22023';
  end if;
  if subject_squad is not null and not exists (select 1 from public.squads where id = subject_squad and tournament_id = t) then
    raise exception 'bad_subject' using errcode = '22023';
  end if;
  if subject_player is not null and not exists (select 1 from public.tournament_entries where tournament_id = t and user_id = subject_player) then
    raise exception 'bad_subject' using errcode = '22023';
  end if;
  perform private.hit_limit('dispute', 5, interval '1 hour');
  insert into public.result_disputes (tournament_id, match_no, squad_id, player_id, raised_by, reason)
  values (t, match, subject_squad, subject_player, me, btrim(why))
  returning id into new_id;
  return new_id;
end;
$$;
revoke all on function public.open_dispute(uuid, integer, uuid, boolean, text) from public, anon;
grant execute on function public.open_dispute(uuid, integer, uuid, boolean, text) to authenticated;
