-- Stage 4 follow-up: the app's typed calls can't send null, so an empty
-- reaction ('') also means "take my reaction back". Same rules otherwise.
-- Rollback: re-run the react_to_post definition from 20261127220000.

create or replace function public.react_to_post(post bigint, p_emoji text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
begin
  if me is null or not private.can_see_post(post) then
    raise exception 'no_post' using errcode = 'PT404';
  end if;
  perform private.hit_limit('reaction', 60, interval '1 minute');
  if nullif(p_emoji, '') is null then
    delete from public.post_reactions where post_id = post and user_id = me;
  else
    insert into public.post_reactions (post_id, user_id, emoji) values (post, me, p_emoji)
    on conflict (post_id, user_id) do update set emoji = excluded.emoji, created_at = now();
  end if;
end;
$$;
