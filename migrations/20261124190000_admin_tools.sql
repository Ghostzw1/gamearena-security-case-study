-- Admin panel tools. Every function here checks private.is_admin() itself,
-- so calling them through the API as a normal player does nothing but fail.

-- Reports get a status so the admin queue only shows what's still open.
alter table public.chat_reports
  add column resolved_at timestamptz,
  add column resolved_by uuid references auth.users (id) on delete set null,
  add column resolution text,
  add constraint chat_reports_resolution_check check (
    resolution is null or resolution in ('deleted', 'banned', 'dismissed')
  );

create index chat_reports_open_idx on public.chat_reports (created_at desc) where resolved_at is null;

create function private.require_admin()
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not private.is_admin() then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
end;
$$;
revoke all on function private.require_admin() from public;
grant execute on function private.require_admin() to authenticated;

-- "Am I an admin?" (lets the app show the admin link; reveals nothing else).
create function public.am_i_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_admin();
$$;
revoke all on function public.am_i_admin() from public;
grant execute on function public.am_i_admin() to authenticated;

-- Close a report (and every other open report on the same message).
create function public.resolve_report(report_id bigint, outcome text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  target_message bigint;
begin
  perform private.require_admin();
  if outcome not in ('deleted', 'banned', 'dismissed') then
    raise exception 'bad_outcome' using errcode = '22023';
  end if;
  select message_id into target_message from public.chat_reports where id = report_id;
  if target_message is null then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  update public.chat_reports
     set resolved_at = now(), resolved_by = (select auth.uid()), resolution = outcome
   where message_id = target_message and resolved_at is null;
end;
$$;
revoke all on function public.resolve_report(bigint, text) from public;
grant execute on function public.resolve_report(bigint, text) to authenticated;

create function public.unban_player(target uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  delete from public.chat_bans where user_id = target;
end;
$$;
revoke all on function public.unban_player(uuid) from public;
grant execute on function public.unban_player(uuid) to authenticated;

-- Open reports with everything the admin needs to decide, in one call.
create function public.admin_open_reports()
returns table (
  report_id bigint,
  reason text,
  reported_at timestamptz,
  report_count bigint,
  message_id bigint,
  body text,
  message_deleted boolean,
  sent_at timestamptz,
  author_id uuid,
  author_username text,
  reporter_username text,
  channel_name text,
  channel_slug text
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  return query
    select r.id, r.reason, r.created_at,
           count(*) over (partition by r.message_id),
           m.id, m.body, m.deleted_at is not null, m.created_at,
           m.user_id, author.username, reporter.username,
           c.name, c.slug
      from public.chat_reports r
      join public.chat_messages m on m.id = r.message_id
      join public.chat_channels c on c.id = m.channel_id
      left join public.profiles author on author.id = m.user_id
      left join public.profiles reporter on reporter.id = r.reporter_id
     where r.resolved_at is null
     order by r.created_at desc
     limit 100;
end;
$$;
revoke all on function public.admin_open_reports() from public;
grant execute on function public.admin_open_reports() to authenticated;

create function public.admin_active_bans()
returns table (user_id uuid, username text, reason text, banned_until timestamptz, banned_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  return query
    select b.user_id, p.username, b.reason, b.banned_until, b.created_at
      from public.chat_bans b
      left join public.profiles p on p.id = b.user_id
     where b.banned_until is null or b.banned_until > now()
     order by b.created_at desc;
end;
$$;
revoke all on function public.admin_active_bans() from public;
grant execute on function public.admin_active_bans() to authenticated;

-- Headline numbers, including progress towards the 30 "yes" goal.
create function public.admin_stats()
returns table (
  players bigint,
  messages_24h bigint,
  clans bigint,
  open_reports bigint,
  active_bans bigint,
  waitlist_total bigint,
  waitlist_yes bigint,
  waitlist_maybe bigint,
  waitlist_no bigint
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  return query select
    (select count(*) from public.profiles),
    (select count(*) from public.chat_messages where created_at > now() - interval '24 hours' and deleted_at is null),
    (select count(*) from public.chat_channels where kind = 'clan'),
    (select count(distinct message_id) from public.chat_reports where resolved_at is null),
    (select count(*) from public.chat_bans where banned_until is null or banned_until > now()),
    (select count(*) from public.interest_signups),
    (select count(*) from public.interest_signups where would_pay = 'yes'),
    (select count(*) from public.interest_signups where would_pay = 'maybe'),
    (select count(*) from public.interest_signups where would_pay = 'no');
end;
$$;
revoke all on function public.admin_stats() from public;
grant execute on function public.admin_stats() to authenticated;

-- Supabase grants every API role EXECUTE on new functions by default.
-- Visitors (anon) must not reach any signed-in-only function, so take it
-- away explicitly (the functions also check permissions themselves).
revoke execute on function public.am_i_admin() from anon;
revoke execute on function public.resolve_report(bigint, text) from anon;
revoke execute on function public.unban_player(uuid) from anon;
revoke execute on function public.admin_open_reports() from anon;
revoke execute on function public.admin_active_bans() from anon;
revoke execute on function public.admin_stats() from anon;
revoke execute on function public.delete_my_account() from anon;
revoke execute on function public.delete_chat_message(bigint) from anon;
revoke execute on function public.ban_player(uuid, text, integer) from anon;
