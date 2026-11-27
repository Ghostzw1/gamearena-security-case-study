-- Social directive v4, Stage 3: community (Parts 8.4 and 8.8).
--
-- Why:
-- Clans: roles (leader = 'owner', officer, member); invitations; recruiting
--   on/off with requirements text; a drawn banner from the gallery; member
--   management (promote, demote, remove, transfer leadership). Leaders and
--   officers manage, the database enforces who may do what, and every
--   clan-leader action writes the audit log (Part 10).
-- Squads: a squad post is a planned session. Modes MP / BR / Ranked / Custom,
--   when = Now / Tonight / Saturday / a time, voice, a note of up to 140
--   characters. Posts end 2 hours after their start (queries filter on
--   expires_at, no cron). One open post per player per game. Accepted players
--   join an automatically created squad chat (instead of being made friends),
--   and the post closes when it's full.
--
-- Production had 0 clans and 0 open squad posts when this was written, so no
-- data moves are needed.
-- Rollback: drop the new functions, table clan_invites and index
-- squad_posts_one_open_per_game; restore the replaced functions from
-- 20261127140000 / 20261127190000 and the role/mode/kind checks.

-- 1. Clan roles, recruiting, banner -----------------------------------------------
alter table public.clan_members drop constraint clan_members_role_check;
alter table public.clan_members add constraint clan_members_role_check check (role in ('owner', 'officer', 'member'));

alter table public.chat_channels
  add column recruiting boolean not null default true,
  add column requirements text,
  add column banner text,
  add constraint chat_channels_requirements_check check (
    requirements is null or (char_length(requirements) between 2 and 140 and private.clean_text(requirements))
  ),
  add constraint chat_channels_banner_check check (
    banner is null or banner in ('night', 'ember', 'jade', 'violet', 'ice', 'gold', 'storm', 'dusk')
  );

create function private.clan_role(clan uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select m.role from public.clan_members m
  join public.chat_channels c on c.id = m.channel_id and c.kind = 'clan'
  where m.channel_id = clan and m.user_id = (select auth.uid());
$$;
revoke all on function private.clan_role(uuid) from public;
grant execute on function private.clan_role(uuid) to authenticated;

create function private.is_clan_manager(clan uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(private.clan_role(clan) in ('owner', 'officer'), false);
$$;
revoke all on function private.is_clan_manager(uuid) from public;
grant execute on function private.is_clan_manager(uuid) to authenticated;

alter policy "Requester, clan master and admins see requests" on public.clan_join_requests
  using (user_id = (select auth.uid()) or private.is_clan_manager(channel_id) or private.is_admin());
alter policy "Requester cancels, clan master or admin declines" on public.clan_join_requests
  using (user_id = (select auth.uid()) or private.is_clan_manager(channel_id) or private.is_admin());
alter policy "Players ask to join an approved clan" on public.clan_join_requests
  with check (
    user_id = (select auth.uid())
    and not private.is_banned()
    and exists (select 1 from public.chat_channels c where c.id = channel_id and c.kind = 'clan' and c.approved and c.recruiting)
    and not exists (select 1 from public.clan_members m where m.channel_id = clan_join_requests.channel_id and m.user_id = (select auth.uid()))
  );
-- Officers can leave too; the leader hands over or deletes the clan first.
alter policy "Members can leave, admins can remove" on public.clan_members
  using ((user_id = (select auth.uid()) and role in ('member', 'officer')) or private.is_admin());

create or replace function public.accept_clan_request(clan uuid, player uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not (private.is_clan_manager(clan) or private.is_admin()) then
    raise exception 'clan_master_only' using errcode = '42501';
  end if;
  if not exists (select 1 from public.clan_join_requests where channel_id = clan and user_id = player) then
    raise exception 'no_request' using errcode = 'PT404';
  end if;
  if exists (select 1 from public.chat_channels where kind = 'clan' and owner_id = player and id <> clan) then
    raise exception 'owns_clan' using errcode = 'PT409';
  end if;
  delete from public.clan_members where user_id = player and role in ('member', 'officer');
  insert into public.clan_members (channel_id, user_id, role) values (clan, player, 'member');
  delete from public.clan_join_requests where user_id = player;
  delete from public.clan_invites where user_id = player;
end;
$$;

-- Leader: clan details (description, recruiting, requirements, banner).
create function public.update_clan(clan uuid, p_description text, p_recruiting boolean, p_requirements text, p_banner text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if coalesce(private.clan_role(clan), '') <> 'owner' then
    raise exception 'leader_only' using errcode = '42501';
  end if;
  update public.chat_channels
     set description = nullif(btrim(p_description), ''),
         recruiting = coalesce(p_recruiting, true),
         requirements = nullif(btrim(p_requirements), ''),
         banner = nullif(p_banner, '')
   where id = clan and kind = 'clan';
  perform private.audit('clan.updated', null, null, jsonb_build_object('clan', clan, 'recruiting', p_recruiting));
end;
$$;

-- Leader: promote to officer or back to member.
create function public.set_clan_role(clan uuid, player uuid, new_role text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if coalesce(private.clan_role(clan), '') <> 'owner' then
    raise exception 'leader_only' using errcode = '42501';
  end if;
  if new_role not in ('officer', 'member') or player = (select auth.uid()) then
    raise exception 'bad_role' using errcode = 'PT422';
  end if;
  update public.clan_members set role = new_role where channel_id = clan and user_id = player and role <> 'owner';
  if not found then
    raise exception 'not_a_member' using errcode = 'PT404';
  end if;
  perform private.audit('clan.role_changed', null, player, jsonb_build_object('clan', clan, 'role', new_role));
end;
$$;

-- Leader removes anyone; officers remove members only.
create function public.remove_clan_member(clan uuid, player uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  mine text := private.clan_role(clan);
  theirs text;
begin
  select role into theirs from public.clan_members where channel_id = clan and user_id = player;
  if theirs is null then
    raise exception 'not_a_member' using errcode = 'PT404';
  end if;
  if player = (select auth.uid()) or theirs = 'owner'
     or not (mine = 'owner' or (mine = 'officer' and theirs = 'member')) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  delete from public.clan_members where channel_id = clan and user_id = player;
  perform private.audit('clan.member_removed', null, player, jsonb_build_object('clan', clan));
end;
$$;

-- Leader hands the clan to another member (the old leader becomes an officer).
create function public.transfer_clan_leadership(clan uuid, player uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
begin
  if coalesce(private.clan_role(clan), '') <> 'owner' then
    raise exception 'leader_only' using errcode = '42501';
  end if;
  if player = me or not exists (select 1 from public.clan_members where channel_id = clan and user_id = player) then
    raise exception 'not_a_member' using errcode = 'PT404';
  end if;
  update public.clan_members set role = 'officer' where channel_id = clan and user_id = me;
  update public.clan_members set role = 'owner' where channel_id = clan and user_id = player;
  update public.chat_channels set owner_id = player where id = clan and kind = 'clan';
  perform private.audit('clan.leader_transferred', null, player, jsonb_build_object('clan', clan, 'from', me));
end;
$$;

-- Announcements: leader and officers (admins too, audited).
create or replace function public.set_clan_announcement(clan uuid, text_body text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  c public.chat_channels;
  msg text := nullif(btrim(text_body), '');
begin
  select * into c from public.chat_channels where id = clan and kind = 'clan';
  if c.id is null or not (private.is_clan_manager(clan) or private.is_admin()) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if not c.approved then
    raise exception 'clan_not_approved' using errcode = 'PT409';
  end if;
  perform private.hit_limit('clan_announcement', 5, interval '1 hour');
  if not private.is_clan_manager(clan) then
    perform private.audit('clan.announcement', null, c.owner_id, jsonb_build_object('clan', c.id, 'cleared', msg is null));
  end if;
  if msg is null then
    delete from public.clan_announcements where channel_id = clan;
  else
    insert into public.clan_announcements (channel_id, body, posted_by) values (clan, msg, (select auth.uid()))
    on conflict (channel_id) do update set body = excluded.body, posted_by = excluded.posted_by, posted_at = now();
    perform private.notify(m.user_id, 'clan_announcement', null, 'cl:' || c.id || ':' || extract(epoch from now())::bigint,
      coalesce('[' || c.tag || '] ', '') || c.name, left(msg, 160), '/chats/' || c.slug)
    from public.clan_members m where m.channel_id = clan and m.user_id <> (select auth.uid());
  end if;
end;
$$;

-- 2. Clan invitations --------------------------------------------------------------
create table public.clan_invites (
  channel_id uuid not null references public.chat_channels (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  invited_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (channel_id, user_id)
);
alter table public.clan_invites enable row level security;
revoke all on table public.clan_invites from public, anon, authenticated;
grant select on table public.clan_invites to authenticated;
create policy "The invited player and the clan's managers see invites"
  on public.clan_invites for select to authenticated
  using (user_id = (select auth.uid()) or private.is_clan_manager(channel_id));

alter table public.notifications drop constraint notifications_kind_check;
alter table public.notifications add constraint notifications_kind_check check (kind in (
  'match_5h', 'match_1h', 'room', 'friend_request', 'friend_accepted', 'message',
  'entry_approved', 'entry_rejected', 'dispute_answered', 'checkin_open', 'event_cancelled',
  'squad_request', 'squad_answered', 'clan_announcement', 'clan_invite'
));

create function public.invite_to_clan(clan uuid, player uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  c public.chat_channels;
  who public.profiles;
begin
  select * into c from public.chat_channels where id = clan and kind = 'clan';
  if c.id is null or not private.is_clan_manager(clan) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if not c.approved then
    raise exception 'clan_not_approved' using errcode = 'PT409';
  end if;
  if player = me or not exists (select 1 from public.profiles where id = player) then
    raise exception 'unknown_player' using errcode = 'PT404';
  end if;
  if private.blocked_either(me, player) then
    raise exception 'blocked' using errcode = 'PT409';
  end if;
  if exists (select 1 from public.clan_members where channel_id = clan and user_id = player) then
    raise exception 'already_member' using errcode = 'PT409';
  end if;
  perform private.hit_limit('clan_invite', 20, interval '1 day');
  insert into public.clan_invites (channel_id, user_id, invited_by) values (clan, player, me) on conflict do nothing;
  select * into who from public.profiles where id = me;
  perform private.notify(player, 'clan_invite', null, 'ci:' || clan::text,
    coalesce('[' || c.tag || '] ', '') || c.name, who.username || ' invited you to join their clan.', '/chats/' || c.slug);
end;
$$;

-- The invited player answers. Joining moves you out of your old clan
-- (leaders must hand over or delete theirs first).
create function public.answer_clan_invite(clan uuid, accept boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
begin
  if not exists (select 1 from public.clan_invites where channel_id = clan and user_id = me) then
    raise exception 'no_invite' using errcode = 'PT404';
  end if;
  if accept then
    if exists (select 1 from public.chat_channels where kind = 'clan' and owner_id = me and id <> clan) then
      raise exception 'owns_clan' using errcode = 'PT409';
    end if;
    delete from public.clan_members where user_id = me and role in ('member', 'officer');
    insert into public.clan_members (channel_id, user_id, role) values (clan, me, 'member');
    delete from public.clan_join_requests where user_id = me;
    delete from public.clan_invites where user_id = me;
  else
    delete from public.clan_invites where channel_id = clan and user_id = me;
  end if;
end;
$$;

-- 3. Squad chats (kind 'squad', same membership table as groups) ----------------------
alter table public.chat_channels drop constraint chat_channels_kind_check;
alter table public.chat_channels add constraint chat_channels_kind_check
  check (kind in ('community', 'clan', 'country', 'event', 'dm', 'group', 'squad'));

create or replace function private.can_read_channel(target uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
      select 1 from public.chat_channels c
      where c.id = target
        and (
          c.kind = 'community'
          or (c.kind = 'clan' and c.approved and exists (
            select 1 from public.clan_members m
            where m.channel_id = target and m.user_id = (select auth.uid())
          ))
          or (c.kind = 'country' and exists (
            select 1 from public.country_chat_members m
            where m.channel_id = target and m.user_id = (select auth.uid())
          ))
          or (c.kind = 'event' and (private.is_approved_entrant(c.tournament_id) or private.is_staff(c.tournament_id)))
          or (c.kind = 'dm' and (select auth.uid()) in (c.dm_low, c.dm_high))
          or (c.kind in ('group', 'squad') and private.is_group_member(target))
        )
    )
    -- Admins read every chat except private messages, groups and squad chats (only reported messages).
    or (private.is_admin() and not exists (select 1 from public.chat_channels c where c.id = target and c.kind in ('dm', 'group', 'squad')));
$$;

alter policy "Signed-in players can browse channels and clans" on public.chat_channels
  using (
    (kind <> 'clan' or approved or owner_id = (select auth.uid()) or private.is_admin())
    and (kind <> 'dm' or (select auth.uid()) in (dm_low, dm_high))
    and (kind not in ('group', 'squad') or private.is_group_member(id))
  );

drop function public.my_unread_counts();
drop function public.my_groups();
create function public.my_groups()
returns table (id uuid, slug text, name text, kind text, members integer, last_body text, last_at timestamptz, unread integer, is_owner boolean)
language sql
stable
security definer
set search_path = ''
as $$
  select c.id, c.slug, c.name, c.kind,
    (select count(*) from public.group_members g2 where g2.channel_id = c.id)::integer,
    lm.body, lm.created_at,
    (select count(*) from public.chat_messages m
      where m.channel_id = c.id and m.user_id <> (select auth.uid()) and m.deleted_at is null
        and m.created_at > greatest(g.joined_at, coalesce((select r.last_read_at from public.dm_reads r where r.channel_id = c.id and r.user_id = (select auth.uid())), '-infinity'::timestamptz)))::integer,
    g.role = 'owner'
  from public.group_members g
  join public.chat_channels c on c.id = g.channel_id and c.kind in ('group', 'squad')
  left join lateral (
    select m.body, m.created_at from public.chat_messages m
    where m.channel_id = c.id and m.deleted_at is null
    order by m.created_at desc limit 1
  ) lm on true
  where g.user_id = (select auth.uid())
  order by coalesce(lm.created_at, c.created_at) desc;
$$;
create function public.my_unread_counts()
returns table (notifications integer, messages integer)
language sql
stable
security definer
set search_path = ''
as $$
  select
    (select count(*) from public.notifications n where n.user_id = (select auth.uid()) and n.read_at is null and n.created_at > now() - interval '30 days')::integer,
    ((select coalesce(sum(c.unread), 0) from public.my_conversations() c)
     + (select coalesce(sum(g.unread), 0) from public.my_groups() g))::integer;
$$;

create or replace function public.mark_chat_read(conversation text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  c public.chat_channels;
begin
  select * into c from public.chat_channels where slug = conversation and kind in ('dm', 'group', 'squad');
  if c.id is null or me is null or not (
    (c.kind = 'dm' and me in (c.dm_low, c.dm_high)) or (c.kind in ('group', 'squad') and private.is_group_member(c.id))
  ) then
    raise exception 'unknown_conversation' using errcode = 'PT404';
  end if;
  insert into public.dm_reads (channel_id, user_id, last_read_at) values (c.id, me, now())
  on conflict (channel_id, user_id) do update set last_read_at = excluded.last_read_at;
  delete from public.notifications where user_id = me and kind = 'message' and ref in ('c:' || c.id::text, 'g:' || c.id::text);
end;
$$;

create or replace function public.leave_group(grp uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  was_owner boolean;
  heir uuid;
begin
  delete from public.group_members where channel_id = grp and user_id = me returning role = 'owner' into was_owner;
  if was_owner is null then
    raise exception 'not_a_member' using errcode = 'PT404';
  end if;
  select user_id into heir from public.group_members where channel_id = grp order by joined_at limit 1;
  if heir is null then
    delete from public.chat_channels where id = grp and kind in ('group', 'squad');
  elsif was_owner then
    update public.group_members set role = 'owner' where channel_id = grp and user_id = heir;
    update public.chat_channels set owner_id = heir where id = grp;
  end if;
end;
$$;

create or replace function private.notify_dm()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  c public.chat_channels;
  who public.profiles;
  other uuid;
begin
  select * into c from public.chat_channels where id = new.channel_id;
  if c.kind in ('group', 'squad') then
    select * into who from public.profiles where id = new.user_id;
    perform private.notify(g.user_id, 'message', null, 'g:' || c.id::text,
      'New messages in ' || c.name, who.username || ': new message', '/chats/' || c.slug)
    from public.group_members g where g.channel_id = c.id and g.user_id <> new.user_id;
    return new;
  end if;
  if c.kind <> 'dm' then
    return new;
  end if;
  other := case when c.dm_low = new.user_id then c.dm_high else c.dm_low end;
  select * into who from public.profiles where id = new.user_id;
  perform private.notify(other, 'message', null, 'c:' || c.id::text,
    case when c.dm_status = 'request' and c.dm_request_from = new.user_id then 'Message request' else 'New message' end,
    who.username || case when c.dm_status = 'request' and c.dm_request_from = new.user_id
                         then ' wants to message you. Accept, ignore or block.'
                         else ' sent you a message.' end,
    '/chats/' || c.slug);
  return new;
end;
$$;

-- Push categories: clan invites follow the clan switch.
create or replace function private.notify(p_user uuid, p_kind text, p_tournament uuid, p_ref text, p_title text, p_body text, p_url text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  np public.notification_prefs;
  push boolean;
begin
  select * into np from public.notification_prefs where user_id = p_user;
  push := case
    when np.user_id is null then true
    when p_kind = 'message' then np.message_alerts
    when p_kind in ('friend_request', 'friend_accepted') then np.social_alerts
    when p_kind in ('squad_request', 'squad_answered') then np.squad_alerts
    when p_kind in ('clan_announcement', 'clan_invite') then np.clan_alerts
    when p_kind in ('entry_approved', 'entry_rejected', 'dispute_answered', 'checkin_open', 'event_cancelled') then np.tournament_alerts
    else true
  end;
  if p_tournament is null then
    insert into public.notifications (user_id, kind, tournament_id, ref, title, body, url, pushed_at)
    values (p_user, p_kind, null, p_ref, left(p_title, 80), left(p_body, 200), p_url, case when push then null else now() end)
    on conflict (user_id, kind, ref) where tournament_id is null do nothing;
  else
    insert into public.notifications (user_id, kind, tournament_id, ref, title, body, url, pushed_at)
    values (p_user, p_kind, p_tournament, p_ref, left(p_title, 80), left(p_body, 200), p_url, case when push then null else now() end)
    on conflict (user_id, kind, tournament_id) do nothing;
  end if;
end;
$$;

-- 4. Squad posts v4 -------------------------------------------------------------------
alter table public.squad_posts drop constraint squad_posts_mode_check;
alter table public.squad_posts
  add constraint squad_posts_mode_check check (mode in ('br', 'mp', 'ranked', 'custom')),
  add column when_kind text not null default 'now',
  add column starts_at timestamptz not null default now(),
  add column voice text not null default 'in_game',
  add column chat_id uuid references public.chat_channels (id) on delete set null,
  add constraint squad_posts_when_check check (when_kind in ('now', 'tonight', 'saturday', 'time')),
  add constraint squad_posts_voice_check check (voice in ('in_game', 'whatsapp', 'discord', 'no_mic'));
create unique index squad_posts_one_open_per_game on public.squad_posts (author_id, game) where status = 'open';

drop function public.create_squad_post(text, text, text, integer, text[], text, text, integer);
create function public.create_squad_post(
  p_mode text, p_region text, p_rank text, p_needed integer, p_when text, p_starts_at timestamptz, p_voice text, p_body text
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  local_today timestamp := date_trunc('day', now() at time zone 'Africa/Harare');
  dow integer := extract(dow from now() at time zone 'Africa/Harare')::integer;
  v_start timestamptz;
  note text := nullif(btrim(p_body), '');
  new_id bigint;
begin
  if me is null or not exists (select 1 from public.profiles where id = me) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  if private.is_banned() then
    raise exception 'banned' using errcode = '42501';
  end if;
  if note is not null and char_length(note) > 140 then
    raise exception 'note_too_long' using errcode = 'PT422';
  end if;
  v_start := case p_when
    when 'now' then now()
    when 'tonight' then greatest(now(), (local_today + interval '20 hours') at time zone 'Africa/Harare')
    when 'saturday' then (local_today + make_interval(days => (6 - dow + 7) % 7) + interval '20 hours') at time zone 'Africa/Harare'
    when 'time' then p_starts_at
    else null
  end;
  if p_when = 'saturday' and v_start <= now() then
    v_start := v_start + interval '7 days';
  end if;
  if v_start is null or v_start < now() - interval '5 minutes' or v_start > now() + interval '7 days' then
    raise exception 'bad_time' using errcode = 'PT422';
  end if;
  -- Your expired posts don't count against the one-open-post rule.
  update public.squad_posts set status = 'closed' where author_id = me and status = 'open' and expires_at <= now();
  if exists (select 1 from public.squad_posts where author_id = me and game = 'codm' and status = 'open') then
    raise exception 'already_open' using errcode = 'PT409';
  end if;
  perform private.hit_limit('squad_post', 3, interval '1 day');
  insert into public.squad_posts (author_id, mode, region, rank, needed, roles, availability, body, when_kind, starts_at, voice, expires_at)
  values (me, p_mode, p_region, coalesce(p_rank, 'any'), p_needed, '{}', null, note, p_when, v_start, coalesce(p_voice, 'in_game'),
          v_start + interval '2 hours')
  returning id into new_id;
  return new_id;
end;
$$;

drop function public.squad_board();
create function public.squad_board()
returns table (
  id bigint, mode text, region text, rank text, needed integer, filled integer, voice text, when_kind text,
  starts_at timestamptz, body text, created_at timestamptz, expires_at timestamptz, status text,
  author text, author_key text, author_tag text, author_avatar text,
  mine boolean, my_request text, pending integer, chat_slug text
)
language sql
stable
security definer
set search_path = ''
as $$
  select s.id, s.mode, s.region, s.rank, s.needed,
    (select count(*) from public.squad_post_requests r where r.post_id = s.id and r.status = 'accepted')::integer,
    s.voice, s.when_kind, s.starts_at, s.body, s.created_at, s.expires_at, s.status,
    p.username, p.username_key, p.clan_tag, p.avatar_id,
    s.author_id = (select auth.uid()),
    (select r.status from public.squad_post_requests r where r.post_id = s.id and r.user_id = (select auth.uid())),
    case when s.author_id = (select auth.uid())
      then (select count(*) from public.squad_post_requests r where r.post_id = s.id and r.status = 'pending')::integer
      else 0 end,
    -- The squad chat, only for people in it.
    (select c.slug from public.chat_channels c where c.id = s.chat_id and private.is_group_member(c.id))
  from public.squad_posts s
  join public.profiles p on p.id = s.author_id
  where (select auth.uid()) is not null
    and ((s.status = 'open' and s.expires_at > now()) or s.author_id = (select auth.uid())
         or exists (select 1 from public.squad_post_requests r where r.post_id = s.id and r.user_id = (select auth.uid()) and r.status = 'accepted'))
    and not private.blocked_either(s.author_id, (select auth.uid()))
  order by s.author_id = (select auth.uid()) desc, s.starts_at, s.created_at desc
  limit 100;
$$;

-- Accept: the player joins the squad chat (created on the first accept); the
-- post closes itself when it's full. Decline: nothing else changes.
create or replace function public.answer_join_request(post bigint, player uuid, accept boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  p public.squad_posts;
  author_name text;
  cid uuid;
begin
  select * into p from public.squad_posts where id = post and author_id = me;
  if p.id is null then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if not exists (select 1 from public.squad_post_requests where post_id = post and user_id = player and status = 'pending') then
    raise exception 'no_request' using errcode = 'PT404';
  end if;
  if accept then
    cid := p.chat_id;
    if cid is null then
      select username into author_name from public.profiles where id = me;
      insert into public.chat_channels (kind, name, owner_id, approved)
      values ('squad', 'Squad · ' || left(author_name, 16), me, true)
      returning id into cid;
      insert into public.group_members (channel_id, user_id, role) values (cid, me, 'owner');
      update public.squad_posts set chat_id = cid where id = post;
    end if;
    insert into public.group_members (channel_id, user_id) values (cid, player) on conflict do nothing;
  end if;
  update public.squad_post_requests set status = case when accept then 'accepted' else 'declined' end
  where post_id = post and user_id = player and status = 'pending';
  if accept and (select count(*) from public.squad_post_requests where post_id = post and status = 'accepted') >= p.needed then
    update public.squad_posts set status = 'closed' where id = post;
  end if;
end;
$$;

create or replace function private.notify_squad_requests()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  p public.squad_posts;
  who public.profiles;
  chat_slug text;
begin
  select * into p from public.squad_posts where id = new.post_id;
  if tg_op = 'INSERT' then
    select * into who from public.profiles where id = new.user_id;
    perform private.notify(p.author_id, 'squad_request', null, 'sq:' || p.id || ':' || new.user_id,
      'Someone wants to join', who.username || ' asked to join your squad.', '/discover/squads');
  elsif new.status <> old.status and new.status in ('accepted', 'declined') then
    select * into who from public.profiles where id = p.author_id;
    select slug into chat_slug from public.chat_channels where id = p.chat_id;
    perform private.notify(new.user_id, 'squad_answered', null, 'sq:' || p.id,
      case when new.status = 'accepted' then 'You''re in the squad' else 'Squad request declined' end,
      case when new.status = 'accepted' then who.username || ' accepted you. Plan the game in the squad chat.'
           else who.username || ' found other players this time.' end,
      case when new.status = 'accepted' and chat_slug is not null then '/chats/' || chat_slug else '/discover/squads' end);
  end if;
  return new;
end;
$$;

revoke all on function public.update_clan(uuid, text, boolean, text, text) from public, anon;
revoke all on function public.set_clan_role(uuid, uuid, text) from public, anon;
revoke all on function public.remove_clan_member(uuid, uuid) from public, anon;
revoke all on function public.transfer_clan_leadership(uuid, uuid) from public, anon;
revoke all on function public.invite_to_clan(uuid, uuid) from public, anon;
revoke all on function public.answer_clan_invite(uuid, boolean) from public, anon;
revoke all on function public.create_squad_post(text, text, text, integer, text, timestamptz, text, text) from public, anon;
revoke all on function public.squad_board() from public, anon;
revoke all on function public.my_groups() from public, anon;
revoke all on function public.my_unread_counts() from public, anon;
grant execute on function public.update_clan(uuid, text, boolean, text, text) to authenticated;
grant execute on function public.set_clan_role(uuid, uuid, text) to authenticated;
grant execute on function public.remove_clan_member(uuid, uuid) to authenticated;
grant execute on function public.transfer_clan_leadership(uuid, uuid) to authenticated;
grant execute on function public.invite_to_clan(uuid, uuid) to authenticated;
grant execute on function public.answer_clan_invite(uuid, boolean) to authenticated;
grant execute on function public.create_squad_post(text, text, text, integer, text, timestamptz, text, text) to authenticated;
grant execute on function public.squad_board() to authenticated;
grant execute on function public.my_groups() to authenticated;
grant execute on function public.my_unread_counts() to authenticated;
