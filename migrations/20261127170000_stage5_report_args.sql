-- Stage 5 follow-up: resolve_content_report gets optional parameters (with
-- defaults) so the app can leave out the ones that don't apply (a player
-- report has no post number; a dismissal has no ban length). Same rules.

drop function public.resolve_content_report(text, bigint, uuid, text, text, integer);

create function public.resolve_content_report(
  p_kind text, p_decision text, p_note text default null, p_ref bigint default null, p_target uuid default null, p_ban_days integer default null
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  subj record;
  note text := nullif(btrim(p_note), '');
begin
  perform private.require_admin();
  if p_decision not in ('dismissed', 'removed', 'banned') then
    raise exception 'bad_decision' using errcode = '22023';
  end if;
  if p_decision = 'removed' and p_kind = 'player' then
    raise exception 'bad_decision' using errcode = '22023';
  end if;
  if p_ban_days is not null and (p_ban_days < 1 or p_ban_days > 365) then
    raise exception 'bad_ban_days' using errcode = '22023';
  end if;
  select * into subj from private.report_subject(p_kind, p_ref, p_target);

  update public.content_reports
     set status = case when p_decision = 'dismissed' then 'dismissed' else 'resolved' end,
         decision = p_decision, decision_note = note, resolved_by = me, resolved_at = now()
   where kind = p_kind and coalesce(ref::text, target::text) = coalesce(p_ref::text, p_target::text) and status = 'open';
  if not found then
    raise exception 'no_open_reports' using errcode = 'PT404';
  end if;

  if p_decision in ('removed', 'banned') then
    case p_kind
      when 'squad_post' then update public.squad_posts set status = 'closed' where id = p_ref;
      when 'idea' then delete from public.ideas where id = p_ref;
      when 'idea_comment' then delete from public.idea_comments where id = p_ref;
      when 'clan' then update public.chat_channels set approved = false where id = p_target and kind = 'clan';
      else null;
    end case;
  end if;
  if p_decision = 'banned' then
    if subj.owner_id is null then
      raise exception 'no_owner' using errcode = 'PT404';
    end if;
    insert into public.chat_bans (user_id, reason, banned_by, banned_until)
    values (subj.owner_id, coalesce(note, 'Broke the community rules'), me,
            case when p_ban_days is null then null else now() + make_interval(days => p_ban_days) end)
    on conflict (user_id) do update
      set reason = excluded.reason, banned_by = excluded.banned_by, banned_until = excluded.banned_until;
  end if;

  perform private.audit('content_report.resolved', null, subj.owner_id,
    jsonb_build_object('kind', p_kind, 'ref', p_ref, 'target', p_target, 'decision', p_decision, 'ban_days', p_ban_days));
end;
$$;

revoke all on function public.resolve_content_report(text, text, text, bigint, uuid, integer) from public, anon;
grant execute on function public.resolve_content_report(text, text, text, bigint, uuid, integer) to authenticated;
