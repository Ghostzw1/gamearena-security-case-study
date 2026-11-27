-- Social directive v4, Stage 2: core social (Parts 5.10, 8.5, 8.6, 8.7).
--
-- Why:
-- 1. Privacy settings: who can see my profile (adds "friends"), who can
--    message me (everyone → their first message lands in Requests / friends
--    and clan mates / nobody), whether my online status shows; self-reported
--    CODM rank; onboarding and "Get set up" markers.
-- 2. Message requests: strangers can reach you if you allow it; their
--    conversation waits in your Requests folder (accept, ignore or block).
--    Until you answer they can send at most 3 messages. Replying accepts.
-- 3. Group chats: friends-only groups (up to 50), owner manages members,
--    anyone can leave. Private like DMs: admins only see reported messages.
-- 4. Unread counts for groups (same read marks as DMs) and one notification
--    per conversation until it's read ("New messages in <group>").
-- 5. Push categories: messages, friends, squads, clans, tournaments.
-- 6. Presence (online, typing) on private Realtime channels: only people who
--    can read a chat can join its presence channel.
--
-- Rollback: drop the functions and table group_members created here,
-- restore can_post/can_read_channel/open_dm/my_conversations/my_unread_counts/
-- private.notify from 20261127130000, and drop the added columns.

-- 1. Privacy settings -------------------------------------------------------------
alter table public.profiles
  add column message_privacy text not null default 'everyone',
  add column show_online boolean not null default true,
  add column codm_rank text,
  add column onboarded_at timestamptz,
  add column setup_dismissed_at timestamptz,
  add constraint profiles_message_privacy_check check (message_privacy in ('everyone', 'friends', 'nobody')),
  add constraint profiles_codm_rank_check check (
    codm_rank is null or codm_rank in ('rookie', 'veteran', 'elite', 'pro', 'master', 'grandmaster', 'legendary')
  );
alter table public.profiles drop constraint profiles_visibility_check;
alter table public.profiles add constraint profiles_visibility_check
  check (profile_visibility in ('everyone', 'players', 'friends', 'private'));
grant update (message_privacy, show_online, codm_rank, onboarded_at, setup_dismissed_at) on table public.profiles to authenticated;

create or replace function private.can_see_details(player uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    (select auth.uid()) = player
    or private.is_admin()
    or (select case p.profile_visibility
                 when 'everyone' then true
                 when 'players' then (select auth.uid()) is not null
                 when 'friends' then private.are_friends((select auth.uid()), player)
                 else false
               end
        from public.profiles p where p.id = player),
    false)
$$;

-- Do two players share an approved clan?
create function private.share_clan(a uuid, b uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.clan_members m1
    join public.clan_members m2 on m2.channel_id = m1.channel_id
    join public.chat_channels c on c.id = m1.channel_id and c.approved
    where m1.user_id = a and m2.user_id = b
  );
$$;
revoke all on function private.share_clan(uuid, uuid) from public;

-- May `sender` start a conversation with `target`?
create function private.may_message(sender uuid, target uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select sender is not null and sender <> target
    and not private.blocked_either(sender, target)
    and (
      private.are_friends(sender, target)
      or coalesce((select case p.message_privacy
                            when 'everyone' then true
                            when 'friends' then private.share_clan(sender, target)
                            else false
                          end
                   from public.profiles p where p.id = target), false)
    );
$$;
revoke all on function private.may_message(uuid, uuid) from public;

-- 2. Message requests -------------------------------------------------------------
alter table public.chat_channels
  add column dm_status text,
  add column dm_request_from uuid references public.profiles (id) on delete set null,
  add constraint chat_channels_dm_status_check check (dm_status is null or dm_status in ('friends', 'open', 'request', 'ignored'));
-- 'friends': started between friends, writable only while they're friends.
-- 'open': an accepted request, writable by both. 'request' / 'ignored': waiting.
update public.chat_channels set dm_status = 'friends' where kind = 'dm';

-- 3. Group chats (kind 'group') ----------------------------------------------------
alter table public.chat_channels drop constraint chat_channels_kind_check;
alter table public.chat_channels add constraint chat_channels_kind_check
  check (kind in ('community', 'clan', 'country', 'event', 'dm', 'group'));

create table public.group_members (
  channel_id uuid not null references public.chat_channels (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  role text not null default 'member',
  joined_at timestamptz not null default now(),
  primary key (channel_id, user_id),
  constraint group_members_role_check check (role in ('owner', 'member'))
);
create index group_members_user_idx on public.group_members (user_id);
alter table public.group_members enable row level security;
revoke all on table public.group_members from public, anon, authenticated;
grant select on table public.group_members to authenticated;

create function private.is_group_member(target uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.group_members g where g.channel_id = target and g.user_id = (select auth.uid()));
$$;
revoke all on function private.is_group_member(uuid) from public;
grant execute on function private.is_group_member(uuid) to authenticated;

create policy "Members see their group's members"
  on public.group_members for select to authenticated
  using (private.is_group_member(channel_id));

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
          or (c.kind = 'group' and private.is_group_member(target))
        )
    )
    -- Admins read every chat except private messages and groups (only reported messages).
    or (private.is_admin() and not exists (select 1 from public.chat_channels c where c.id = target and c.kind in ('dm', 'group')));
$$;

create or replace function private.can_post(target uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.can_read_channel(target)
    and not private.is_banned()
    and exists (select 1 from public.profiles where id = (select auth.uid()))
    and not exists (
      select 1 from public.chat_channels c
      where c.id = target and c.kind = 'dm'
        and (
          private.blocked_either(c.dm_low, c.dm_high)
          or not (
            private.are_friends(c.dm_low, c.dm_high)
            or c.dm_status = 'open'
            -- The person who received a request may always reply (that accepts it).
            or (c.dm_status in ('request', 'ignored') and (select auth.uid()) is distinct from c.dm_request_from)
            -- The sender may send up to 3 messages while it waits.
            or (c.dm_status = 'request' and (select auth.uid()) = c.dm_request_from
                and (select count(*) from public.chat_messages m where m.channel_id = c.id and m.user_id = (select auth.uid())) < 3)
          )
        )
    );
$$;

alter policy "Signed-in players can browse channels and clans" on public.chat_channels
  using (
    (kind <> 'clan' or approved or owner_id = (select auth.uid()) or private.is_admin())
    and (kind <> 'dm' or (select auth.uid()) in (dm_low, dm_high))
    and (kind <> 'group' or private.is_group_member(id))
  );

-- Open (or create) a conversation. Friends: straight in. Others: allowed by
-- the target's "who can message me", lands in their Requests, rate-limited
-- (3 a day for accounts younger than 24 hours, 10 otherwise).
create or replace function public.open_dm(other uuid)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  found_slug text;
  status text;
begin
  if me is null or not exists (select 1 from public.profiles where id = me) then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if other = me then
    raise exception 'not_yourself' using errcode = 'PT409';
  end if;
  if not exists (select 1 from public.profiles where id = other) then
    raise exception 'unknown_player' using errcode = 'PT404';
  end if;
  if private.blocked_either(me, other) then
    raise exception 'blocked' using errcode = 'PT409';
  end if;
  select slug into found_slug from public.chat_channels
  where kind = 'dm' and dm_low = least(me, other) and dm_high = greatest(me, other);
  if found_slug is not null then
    -- A chat from when you were friends: if you're not friends any more, a new
    -- message from you is a request again (if they take requests).
    update public.chat_channels set dm_status = 'request', dm_request_from = me
     where slug = found_slug and dm_status = 'friends'
       and not private.are_friends(me, other) and private.may_message(me, other);
    return found_slug;
  end if;
  if private.are_friends(me, other) then
    status := 'friends';
  elsif private.may_message(me, other) then
    status := 'request';
    perform private.hit_limit('dm_request',
      case when (select p.created_at from public.profiles p where p.id = me) > now() - interval '24 hours' then 3 else 10 end,
      interval '1 day');
  else
    raise exception 'messages_closed' using errcode = 'PT409';
  end if;
  insert into public.chat_channels (kind, name, owner_id, dm_low, dm_high, approved, dm_status, dm_request_from)
  values ('dm', 'Direct message', null, least(me, other), greatest(me, other), true, status,
          case when status = 'request' then me else null end)
  returning slug into found_slug;
  return found_slug;
end;
$$;

-- Answer a message request: accept (it becomes a normal chat) or ignore (it
-- leaves Requests; you can still accept later; they can't send more).
create function public.answer_message_request(conversation text, accept boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
begin
  update public.chat_channels
     set dm_status = case when accept then 'open' else 'ignored' end
   where slug = conversation and kind = 'dm' and dm_status in ('request', 'ignored')
     and me in (dm_low, dm_high) and dm_request_from is distinct from me;
  if not found then
    raise exception 'no_request' using errcode = 'PT404';
  end if;
end;
$$;

-- Replying to a request accepts it.
create function private.accept_request_on_reply()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.chat_channels
     set dm_status = 'open'
   where id = new.channel_id and kind = 'dm' and dm_status in ('request', 'ignored')
     and dm_request_from is distinct from new.user_id;
  return new;
end;
$$;
revoke all on function private.accept_request_on_reply() from public;
create trigger chat_messages_accept_request
  after insert on public.chat_messages
  for each row execute function private.accept_request_on_reply();

drop function public.my_unread_counts();
drop function public.my_conversations();
create function public.my_conversations()
returns table (
  slug text, other_id uuid, username text, username_key text, avatar_id text, clan_tag text,
  last_body text, last_at timestamptz, unread integer, can_reply boolean, status text, incoming_request boolean
)
language sql
stable
security definer
set search_path = ''
as $$
  select c.slug, p.id, p.username, p.username_key, p.avatar_id, p.clan_tag,
    lm.body, lm.created_at,
    (select count(*) from public.chat_messages m
      where m.channel_id = c.id and m.user_id <> (select auth.uid()) and m.deleted_at is null
        and m.created_at > coalesce((select r.last_read_at from public.dm_reads r where r.channel_id = c.id and r.user_id = (select auth.uid())), '-infinity'::timestamptz))::integer,
    not private.blocked_either(c.dm_low, c.dm_high) and (
      private.are_friends(c.dm_low, c.dm_high) or c.dm_status = 'open'
      or (c.dm_status in ('request', 'ignored') and c.dm_request_from is distinct from (select auth.uid()))
      or (c.dm_status = 'request' and (select count(*) from public.chat_messages m where m.channel_id = c.id and m.user_id = (select auth.uid())) < 3)
    ),
    coalesce(c.dm_status, 'open'),
    c.dm_status in ('request', 'ignored') and c.dm_request_from is distinct from (select auth.uid()) and not private.are_friends(c.dm_low, c.dm_high)
  from public.chat_channels c
  join public.profiles p on p.id = case when c.dm_low = (select auth.uid()) then c.dm_high else c.dm_low end
  left join lateral (
    select m.body, m.created_at from public.chat_messages m
    where m.channel_id = c.id and m.deleted_at is null
      and not exists (select 1 from public.user_blocks b where b.blocker_id = (select auth.uid()) and b.blocked_id = m.user_id)
    order by m.created_at desc limit 1
  ) lm on true
  where c.kind = 'dm' and (select auth.uid()) in (c.dm_low, c.dm_high)
    -- Requests you ignored and conversations with people you blocked stay out of the list.
    and not (c.dm_status = 'ignored' and c.dm_request_from is distinct from (select auth.uid()))
    and not exists (select 1 from public.user_blocks b where b.blocker_id = (select auth.uid()) and b.blocked_id = p.id)
  order by coalesce(lm.created_at, c.created_at) desc;
$$;

-- Groups -----------------------------------------------------------------------------
create function public.create_group(group_name text, members uuid[])
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  others uuid[];
  g public.chat_channels;
  m uuid;
begin
  if me is null or not exists (select 1 from public.profiles where id = me) then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if private.is_banned() then
    raise exception 'banned' using errcode = '42501';
  end if;
  select coalesce(array_agg(distinct x), '{}') into others from unnest(coalesce(members, '{}')) x where x <> me;
  if cardinality(others) < 1 or cardinality(others) > 49 then
    raise exception 'bad_member_count' using errcode = 'PT422';
  end if;
  foreach m in array others loop
    if not private.are_friends(me, m) or private.blocked_either(me, m) then
      raise exception 'friends_only' using errcode = 'PT409';
    end if;
  end loop;
  perform private.hit_limit('group_create', 5, interval '1 day');
  insert into public.chat_channels (kind, name, owner_id, approved)
  values ('group', btrim(group_name), me, true)
  returning * into g;
  insert into public.group_members (channel_id, user_id, role) values (g.id, me, 'owner');
  insert into public.group_members (channel_id, user_id) select g.id, unnest(others);
  return g.slug;
end;
$$;

create function public.add_group_members(grp uuid, members uuid[])
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  m uuid;
begin
  if not exists (select 1 from public.group_members where channel_id = grp and user_id = me and role = 'owner') then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  foreach m in array coalesce(members, '{}') loop
    if not private.are_friends(me, m) or private.blocked_either(me, m) then
      raise exception 'friends_only' using errcode = 'PT409';
    end if;
  end loop;
  insert into public.group_members (channel_id, user_id)
  select grp, x from unnest(members) x on conflict do nothing;
  if (select count(*) from public.group_members where channel_id = grp) > 50 then
    raise exception 'group_full' using errcode = 'PT409';
  end if;
end;
$$;

create function public.remove_group_member(grp uuid, player uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from public.group_members where channel_id = grp and user_id = (select auth.uid()) and role = 'owner')
     or player = (select auth.uid()) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  delete from public.group_members where channel_id = grp and user_id = player;
end;
$$;

-- Leave a group. If the owner leaves, the longest-standing member takes over;
-- the last one out deletes the group.
create function public.leave_group(grp uuid)
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
    delete from public.chat_channels where id = grp and kind = 'group';
  elsif was_owner then
    update public.group_members set role = 'owner' where channel_id = grp and user_id = heir;
    update public.chat_channels set owner_id = heir where id = grp;
  end if;
end;
$$;

create function public.my_groups()
returns table (id uuid, slug text, name text, members integer, last_body text, last_at timestamptz, unread integer, is_owner boolean)
language sql
stable
security definer
set search_path = ''
as $$
  select c.id, c.slug, c.name,
    (select count(*) from public.group_members g2 where g2.channel_id = c.id)::integer,
    lm.body, lm.created_at,
    (select count(*) from public.chat_messages m
      where m.channel_id = c.id and m.user_id <> (select auth.uid()) and m.deleted_at is null
        and m.created_at > greatest(g.joined_at, coalesce((select r.last_read_at from public.dm_reads r where r.channel_id = c.id and r.user_id = (select auth.uid())), '-infinity'::timestamptz)))::integer,
    g.role = 'owner'
  from public.group_members g
  join public.chat_channels c on c.id = g.channel_id and c.kind = 'group'
  left join lateral (
    select m.body, m.created_at from public.chat_messages m
    where m.channel_id = c.id and m.deleted_at is null
    order by m.created_at desc limit 1
  ) lm on true
  where g.user_id = (select auth.uid())
  order by coalesce(lm.created_at, c.created_at) desc;
$$;

-- Read marks for private chats and groups (clears that chat's notification).
create function public.mark_chat_read(conversation text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  c public.chat_channels;
begin
  select * into c from public.chat_channels where slug = conversation and kind in ('dm', 'group');
  if c.id is null or me is null or not (
    (c.kind = 'dm' and me in (c.dm_low, c.dm_high)) or (c.kind = 'group' and private.is_group_member(c.id))
  ) then
    raise exception 'unknown_conversation' using errcode = 'PT404';
  end if;
  insert into public.dm_reads (channel_id, user_id, last_read_at) values (c.id, me, now())
  on conflict (channel_id, user_id) do update set last_read_at = excluded.last_read_at;
  delete from public.notifications where user_id = me and kind = 'message' and ref in ('c:' || c.id::text, 'g:' || c.id::text);
end;
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

-- 4./5. Notifications: new paths, push categories, group messages ------------------
alter table public.notifications drop constraint notifications_url_check;
alter table public.notifications add constraint notifications_url_check check (
  char_length(url) <= 200
  and url ~ '^/((codm|chats|compete|discover|players|notifications|me)(/[a-z0-9-]+)*)?(#[a-z0-9-]+)?$'
);

alter table public.notification_prefs
  add column message_alerts boolean not null default true,
  add column squad_alerts boolean not null default true,
  add column clan_alerts boolean not null default true,
  add column tournament_alerts boolean not null default true;
grant insert (message_alerts, squad_alerts, clan_alerts, tournament_alerts),
  update (message_alerts, squad_alerts, clan_alerts, tournament_alerts) on table public.notification_prefs to authenticated;

-- One notification row per event, always listed in the app; a phone push only
-- for the categories the player switched on.
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
    when p_kind = 'clan_announcement' then np.clan_alerts
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

-- Private messages and requests: one notification per conversation until read.
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
  if c.kind = 'group' then
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

-- 6. Presence on private Realtime channels ("presence:<chat id>"). Only when the
-- Realtime schema exists (it doesn't in the PGlite tests).
do $presence$
begin
  if exists (select 1 from pg_namespace where nspname = 'realtime')
     and exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'realtime' and c.relname = 'messages') then
    execute $p$
      create policy "Chat members can use the chat's presence channel"
        on realtime.messages for select to authenticated
        using (
          realtime.messages.extension in ('presence', 'broadcast')
          and (select realtime.topic()) like 'presence:%'
          and private.can_read_channel(substring((select realtime.topic()) from 10)::uuid)
        )
    $p$;
    execute $p$
      create policy "Chat members can announce themselves on the presence channel"
        on realtime.messages for insert to authenticated
        with check (
          realtime.messages.extension in ('presence', 'broadcast')
          and (select realtime.topic()) like 'presence:%'
          and private.can_read_channel(substring((select realtime.topic()) from 10)::uuid)
        )
    $p$;
  end if;
end;
$presence$;

revoke all on function public.answer_message_request(text, boolean) from public, anon;
revoke all on function public.create_group(text, uuid[]) from public, anon;
revoke all on function public.add_group_members(uuid, uuid[]) from public, anon;
revoke all on function public.remove_group_member(uuid, uuid) from public, anon;
revoke all on function public.leave_group(uuid) from public, anon;
revoke all on function public.my_groups() from public, anon;
revoke all on function public.mark_chat_read(text) from public, anon;
revoke all on function public.my_conversations() from public, anon;
revoke all on function public.my_unread_counts() from public, anon;
grant execute on function public.answer_message_request(text, boolean) to authenticated;
grant execute on function public.create_group(text, uuid[]) to authenticated;
grant execute on function public.add_group_members(uuid, uuid[]) to authenticated;
grant execute on function public.remove_group_member(uuid, uuid) to authenticated;
grant execute on function public.leave_group(uuid) to authenticated;
grant execute on function public.my_groups() to authenticated;
grant execute on function public.mark_chat_read(text) to authenticated;
grant execute on function public.my_conversations() to authenticated;
grant execute on function public.my_unread_counts() to authenticated;
