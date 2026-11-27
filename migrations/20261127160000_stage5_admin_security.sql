-- Stage 5: administration and security (docs/MASTER-DIRECTIVE.md §14, §15,
-- §19 TEST 8; audit findings H5, H6, H8 in docs/AUDIT.md).
--
-- 1. Audit log covers every remaining admin/host change: bans, chat-report
--    decisions, app settings, clan approvals and removals, admin rights,
--    staff invites (never the email), sponsor slots, stream-slot and event-
--    report reviews, country-chat resets and content-report decisions.
-- 2. Moderation: players can report squad posts, ideas, idea comments,
--    players and clans (with an optional detail); admins see one queue and
--    record a decision (dismiss / remove / ban + remove) with a note.
-- 3. A chat ban is a community ban: it now also stops new friend requests,
--    squad join requests and reports' targets from posting (posts, ideas,
--    comments and chat were already covered).
-- 4. H6: deleting an account keeps the results and reports that person
--    sent (the reporter becomes "deleted player"), so standings and the
--    evidence trail don't change after the fact.
-- 5. H8: joining a squad locks the squad row, so two players can't overfill
--    it at the same moment.
-- 6. admin_audit_log(): the audit trail with names, for the admin panel.

-- 1. Audit coverage -------------------------------------------------------------
create function private.audit_admin_tables()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  changed jsonb;
begin
  case tg_table_name
    when 'chat_bans' then
      if tg_op = 'DELETE' then
        perform private.audit('player.unbanned', null, old.user_id, '{}'::jsonb);
      else
        perform private.audit('player.banned', null, new.user_id,
          jsonb_build_object('reason', new.reason, 'until', new.banned_until));
      end if;
    when 'chat_reports' then
      if new.resolution is distinct from old.resolution and new.resolution is not null then
        perform private.audit('chat_report.resolved', null, null,
          jsonb_build_object('report', new.id, 'message', new.message_id, 'outcome', new.resolution));
      end if;
    when 'app_config' then
      select jsonb_object_agg(o.key, jsonb_build_array(o.value, n.value)) into changed
      from jsonb_each(to_jsonb(old)) o
      join jsonb_each(to_jsonb(new)) n on n.key = o.key
      where o.value is distinct from n.value and o.key <> 'updated_at';
      if changed is not null then
        perform private.audit('config.changed', null, null, changed);
      end if;
    when 'chat_channels' then
      if tg_op = 'UPDATE' then
        if old.kind = 'clan' and new.approved is distinct from old.approved then
          perform private.audit(case when new.approved then 'clan.approved' else 'clan.suspended' end, null, new.owner_id,
            jsonb_build_object('clan', new.id, 'name', new.name));
        end if;
      elsif old.kind = 'clan' and me is not null and old.owner_id is distinct from me then
        perform private.audit('clan.removed', null, old.owner_id, jsonb_build_object('clan', old.id, 'name', old.name));
      end if;
    when 'app_admins' then
      perform private.audit(case when tg_op = 'DELETE' then 'admin.revoked' else 'admin.granted' end, null,
        coalesce(new.user_id, old.user_id), '{}'::jsonb);
    when 'staff_invites' then
      -- Never the email address: only that an invite exists, for which event and role.
      if tg_op = 'DELETE' then
        perform private.audit('invite.deleted', old.tournament_id, null, jsonb_build_object('role', old.role));
      else
        perform private.audit('invite.created', new.tournament_id, null, jsonb_build_object('role', new.role));
      end if;
    when 'sponsored_slots' then
      perform private.audit(case tg_op when 'INSERT' then 'sponsor_slot.created' when 'UPDATE' then 'sponsor_slot.updated' else 'sponsor_slot.deleted' end, null, null,
        jsonb_build_object('slot', coalesce(new.id, old.id), 'sponsor', coalesce(new.sponsor, old.sponsor),
          'headline', coalesce(new.headline, old.headline)));
    when 'stream_requests' then
      if new.status is distinct from old.status then
        perform private.audit('stream.reviewed', new.tournament_id, new.user_id,
          jsonb_build_object('request', new.id, 'status', jsonb_build_array(old.status, new.status)));
      end if;
    when 'event_reports' then
      if new.status is distinct from old.status then
        perform private.audit('event_report.resolved', new.tournament_id, null,
          jsonb_build_object('report', new.id, 'status', jsonb_build_array(old.status, new.status)));
      end if;
    when 'country_chat_members' then
      if me is not null and old.user_id <> me then
        perform private.audit('country.reset', null, old.user_id, jsonb_build_object('channel', old.channel_id));
      end if;
  end case;
  return coalesce(new, old);
end;
$$;
revoke all on function private.audit_admin_tables() from public;

create trigger chat_bans_audit after insert or update or delete on public.chat_bans
  for each row execute function private.audit_admin_tables();
create trigger chat_reports_audit after update on public.chat_reports
  for each row execute function private.audit_admin_tables();
create trigger app_config_audit after update on public.app_config
  for each row execute function private.audit_admin_tables();
create trigger chat_channels_audit after update of approved or delete on public.chat_channels
  for each row execute function private.audit_admin_tables();
create trigger app_admins_audit after insert or delete on public.app_admins
  for each row execute function private.audit_admin_tables();
create trigger staff_invites_audit after insert or delete on public.staff_invites
  for each row execute function private.audit_admin_tables();
create trigger sponsored_slots_audit after insert or update or delete on public.sponsored_slots
  for each row execute function private.audit_admin_tables();
create trigger stream_requests_audit after update on public.stream_requests
  for each row execute function private.audit_admin_tables();
create trigger event_reports_audit after update on public.event_reports
  for each row execute function private.audit_admin_tables();
create trigger country_chat_members_audit after delete on public.country_chat_members
  for each row execute function private.audit_admin_tables();

-- 2. Moderation queue ------------------------------------------------------------
alter table public.content_reports
  drop constraint content_reports_kind_check,
  drop constraint content_reports_reason_check,
  drop constraint content_reports_once,
  drop constraint content_reports_reporter_id_fkey;
alter table public.content_reports
  alter column ref drop not null,
  alter column reporter_id drop not null,
  add column target uuid,
  add column details text,
  add column decision text,
  add column decision_note text,
  add column resolved_by uuid references public.profiles (id) on delete set null,
  add column resolved_at timestamptz,
  add constraint content_reports_reporter_id_fkey foreign key (reporter_id) references public.profiles (id) on delete set null,
  add constraint content_reports_kind_check check (kind in ('squad_post', 'idea', 'idea_comment', 'player', 'clan')),
  add constraint content_reports_reason_check check (reason in ('spam', 'abuse', 'scam', 'misleading', 'cheating', 'impersonation', 'other')),
  add constraint content_reports_subject_check check (
    (kind in ('squad_post', 'idea', 'idea_comment') and ref is not null and target is null)
    or (kind in ('player', 'clan') and target is not null and ref is null)
  ),
  add constraint content_reports_details_check check (
    details is null or (char_length(details) between 2 and 300 and private.clean_text(details))
  ),
  add constraint content_reports_decision_check check (decision is null or decision in ('dismissed', 'removed', 'banned')),
  add constraint content_reports_decision_note_check check (
    decision_note is null or (char_length(decision_note) between 2 and 200 and private.clean_text(decision_note))
  );
create unique index content_reports_once on public.content_reports (kind, coalesce(ref::text, target::text), reporter_id);
create index content_reports_open_idx on public.content_reports (status, created_at) where status = 'open';
grant insert (target, details) on table public.content_reports to authenticated;

drop policy "Players report as themselves" on public.content_reports;
create policy "Players report what they can see"
  on public.content_reports for insert to authenticated
  with check (
    reporter_id = (select auth.uid())
    and case kind
      when 'squad_post' then exists (select 1 from public.squad_posts s where s.id = ref)
      when 'idea' then exists (select 1 from public.ideas i where i.id = ref)
      when 'idea_comment' then exists (select 1 from public.idea_comments c where c.id = ref)
      when 'player' then target <> (select auth.uid()) and exists (select 1 from public.profiles p where p.id = target)
      when 'clan' then exists (select 1 from public.chat_channels c where c.id = target and c.kind = 'clan')
      else false
    end
  );

create trigger content_reports_text_guard before insert or update of details on public.content_reports
  for each row execute function private.guard_community_text();
create or replace function private.guard_community_text()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  case tg_table_name
    when 'squad_posts' then
      perform private.refuse_links_and_phones(new.body);
      perform private.refuse_links_and_phones(new.availability);
    when 'squad_post_requests' then
      perform private.refuse_links_and_phones(new.message);
    when 'ideas' then
      perform private.refuse_links_and_phones(new.body);
    when 'idea_comments' then
      perform private.refuse_links_and_phones(new.body);
    when 'clan_announcements' then
      perform private.refuse_links_and_phones(new.body);
    when 'content_reports' then
      perform private.refuse_links_and_phones(new.details);
  end case;
  return new;
end;
$$;

-- Who owns the reported thing, and a short preview of it.
create function private.report_subject(p_kind text, p_ref bigint, p_target uuid)
returns table (owner_id uuid, preview text)
language sql
stable
security definer
set search_path = ''
as $$
  select s.author_id, left(coalesce(s.body, s.availability, 'Squad post (' || s.mode || ', ' || s.region || ')'), 300)
    from public.squad_posts s where p_kind = 'squad_post' and s.id = p_ref
  union all
  select i.user_id, left(i.body, 300) from public.ideas i where p_kind = 'idea' and i.id = p_ref
  union all
  select c.user_id, left(c.body, 300) from public.idea_comments c where p_kind = 'idea_comment' and c.id = p_ref
  union all
  select p.id, p.username from public.profiles p where p_kind = 'player' and p.id = p_target
  union all
  select c.owner_id, coalesce('[' || c.tag || '] ', '') || c.name || coalesce(': ' || c.description, '')
    from public.chat_channels c where p_kind = 'clan' and c.id = p_target and c.kind = 'clan';
$$;
revoke all on function private.report_subject(text, bigint, uuid) from public;

-- Admin queue: open reports grouped by what was reported.
create function public.admin_content_reports()
returns table (
  kind text, ref bigint, target uuid, reports integer, reasons text[], details text[], first_at timestamptz,
  preview text, owner_id uuid, owner_name text, owner_key text
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  return query
    select r.kind, r.ref, r.target, count(*)::integer,
      array_agg(distinct r.reason), array_remove(array_agg(r.details order by r.created_at), null),
      min(r.created_at), s.preview, s.owner_id, p.username, p.username_key
    from public.content_reports r
    left join lateral private.report_subject(r.kind, r.ref, r.target) s on true
    left join public.profiles p on p.id = s.owner_id
    where r.status = 'open'
    group by r.kind, r.ref, r.target, s.preview, s.owner_id, p.username, p.username_key
    order by count(*) desc, min(r.created_at)
    limit 100;
end;
$$;

-- Admin decision on everything reported about one thing.
--   dismissed: nothing wrong.  removed: take the content down (a squad post
--   is closed, an idea or comment deleted, a clan suspended).  banned: ban
--   the owner from the community (days, or null = permanent) and remove the
--   content. Every decision is written to the audit log.
create function public.resolve_content_report(
  p_kind text, p_ref bigint, p_target uuid, p_decision text, p_note text, p_ban_days integer
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

-- 3. A ban is a community ban --------------------------------------------------------
create function private.refuse_banned()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if private.is_banned() then
    raise exception 'banned' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function private.refuse_banned() from public;
create trigger friendships_refuse_banned before insert on public.friendships
  for each row execute function private.refuse_banned();
create trigger squad_post_requests_refuse_banned before insert on public.squad_post_requests
  for each row execute function private.refuse_banned();
create trigger clan_announcements_refuse_banned before insert or update on public.clan_announcements
  for each row execute function private.refuse_banned();

-- 4. H6: results and reports outlive the account that sent them ---------------------
alter table public.match_results
  drop constraint match_results_reporter_id_fkey,
  alter column reporter_id drop not null,
  add constraint match_results_reporter_id_fkey foreign key (reporter_id) references public.profiles (id) on delete set null;
alter table public.chat_reports
  drop constraint chat_reports_reporter_id_fkey,
  alter column reporter_id drop not null,
  add constraint chat_reports_reporter_id_fkey foreign key (reporter_id) references public.profiles (id) on delete set null;
alter table public.event_reports
  drop constraint event_reports_reporter_id_fkey,
  alter column reporter_id drop not null,
  add constraint event_reports_reporter_id_fkey foreign key (reporter_id) references public.profiles (id) on delete set null;

-- 5. H8: lock the squad while joining -----------------------------------------------
create or replace function public.join_squad(squad_code text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  sq public.squads;
  tour public.tournaments;
  entry public.tournament_entries;
begin
  if not exists (select 1 from public.profiles where id = (select auth.uid())) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  -- "for update": a second player joining at the same moment waits here
  -- until this join is finished, then sees the new count.
  select * into sq from public.squads where code = upper(btrim(squad_code)) and not is_random for update;
  if not found then
    raise exception 'unknown_code' using errcode = 'PT404';
  end if;
  select * into tour from public.tournaments where id = sq.tournament_id;
  if tour.status <> 'open' then
    raise exception 'registration_closed' using errcode = 'PT409';
  end if;
  if (select count(*) from public.tournament_entries where squad_id = sq.id) >= private.squad_size(tour.format) then
    raise exception 'squad_full' using errcode = 'PT409';
  end if;
  -- Fair play: two of this month's top 10 can't team up in GameArena tournaments.
  if tour.kind = 'tournament' and private.is_top10((select auth.uid())) and exists (
    select 1 from public.tournament_entries e
    where e.squad_id = sq.id and private.is_top10(e.user_id)
  ) then
    raise exception 'top10_together' using errcode = 'PT409';
  end if;

  select * into entry from public.tournament_entries where tournament_id = tour.id and user_id = (select auth.uid());
  if found then
    if entry.squad_id = sq.id then
      return sq.name;
    end if;
    if entry.squad_id is not null then
      raise exception 'already_in_squad' using errcode = 'PT409';
    end if;
    update public.tournament_entries set squad_id = sq.id, team_mode = 'fixed'
      where tournament_id = tour.id and user_id = (select auth.uid());
  else
    insert into public.tournament_entries (tournament_id, user_id, team_mode, squad_id)
    values (tour.id, (select auth.uid()), 'fixed', sq.id);
  end if;
  return sq.name;
end;
$$;

-- 6. The audit trail with names (admins only) -------------------------------------
create function public.admin_audit_log(p_action text, p_limit integer)
returns table (
  id bigint, at timestamptz, action text, actor_name text, actor_admin boolean,
  tournament_name text, target_name text, detail jsonb
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  return query
    select a.id, a.at, a.action, coalesce(actor.username, case when a.actor is null then 'System' else 'Deleted player' end),
      a.actor_admin, t.name, target.username, a.detail
    from public.audit_log a
    left join public.profiles actor on actor.id = a.actor
    left join public.tournaments t on t.id = a.tournament_id
    left join public.profiles target on target.id = a.target
    where p_action is null or p_action = '' or a.action like p_action || '%'
    order by a.at desc, a.id desc
    limit least(greatest(coalesce(p_limit, 100), 1), 300);
end;
$$;

revoke all on function public.admin_content_reports() from public, anon;
revoke all on function public.resolve_content_report(text, bigint, uuid, text, text, integer) from public, anon;
revoke all on function public.admin_audit_log(text, integer) from public, anon;
grant execute on function public.admin_content_reports() to authenticated;
grant execute on function public.resolve_content_report(text, bigint, uuid, text, text, integer) to authenticated;
grant execute on function public.admin_audit_log(text, integer) to authenticated;

-- An account deletion clears match_results.reporter_id (H6). That isn't a
-- result change, so the result audit now fires only on real edits.
drop trigger match_results_audit on public.match_results;
create trigger match_results_audit
  after insert or delete or update of placement, kills, squad_id, player_id on public.match_results
  for each row execute function private.audit_results();

-- The results bot's checks run when a result's numbers change, not when an
-- account deletion clears who reported it (that would wrongly refuse the
-- deletion, because nobody is signed in during it).
drop trigger match_results_check on public.match_results;
create trigger match_results_check
  before insert or update of tournament_id, match_no, squad_id, player_id, placement, kills on public.match_results
  for each row execute function private.check_match_result();
