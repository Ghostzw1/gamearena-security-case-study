-- Player profiles, community + clan chat, and moderation.
--
-- Security model (also in SECURITY.md):
--   * Every table has RLS. Only signed-in players (`authenticated`) can touch
--     any of it; visitors (`anon`) can only check if a username is free.
--   * Ownership columns (id / user_id / owner_id / reporter_id) default to
--     auth.uid() and are NOT granted for insert, so nobody can act as
--     someone else.
--   * WhatsApp numbers live in their own table that only the owner can read.
--   * Chat: you read a channel only if it's a community channel or a clan
--     you belong to. Messages are filtered for links and phone numbers
--     (scam + privacy protection) and rate limited. Blocked players' messages
--     never reach you. Banned players can't post.
--   * Helper functions are SECURITY DEFINER with an empty search_path and
--     live in the `private` schema, which the API doesn't expose.

-- RLS policies below call helpers in `private`.
grant usage on schema private to authenticated;

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------
create function private.touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

-- ---------------------------------------------------------------------------
-- Admins and bans (no API access at all; managed in the dashboard / SQL)
-- ---------------------------------------------------------------------------
create table public.app_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.app_admins enable row level security;
revoke all on table public.app_admins from public, anon, authenticated;

create table public.chat_bans (
  user_id uuid primary key references auth.users (id) on delete cascade,
  reason text not null check (char_length(reason) between 3 and 200),
  banned_by uuid references auth.users (id) on delete set null,
  banned_until timestamptz, -- null = permanent
  created_at timestamptz not null default now()
);
alter table public.chat_bans enable row level security;
revoke all on table public.chat_bans from public, anon, authenticated;

create function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.app_admins where user_id = (select auth.uid())
  );
$$;

create function private.is_banned()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.chat_bans
    where user_id = (select auth.uid())
      and (banned_until is null or banned_until > now())
  );
$$;

-- ---------------------------------------------------------------------------
-- Profiles (public: name, avatar, game info)
-- ---------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key default auth.uid() references auth.users (id) on delete cascade,
  username text not null,
  avatar_id text not null,
  codm_ign text,
  preferred_format text,
  age_confirmed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- Plain letters/digits/underscore: no look-alike characters in chat names.
  constraint profiles_username_check check (username ~ '^[A-Za-z0-9_]{3,20}$'),
  constraint profiles_avatar_id_check check (
    char_length(avatar_id) <= 40 and avatar_id ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
  ),
  constraint profiles_codm_ign_check check (
    codm_ign is null or (
      char_length(codm_ign) between 2 and 24
      and codm_ign = btrim(codm_ign)
      and codm_ign !~ '[[:cntrl:]\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]'
    )
  ),
  constraint profiles_preferred_format_check check (
    preferred_format is null or preferred_format in ('solo', 'duo', 'squad')
  )
);

-- "Ghost" and "ghost" can't both exist.
create unique index profiles_username_lower_key on public.profiles (lower(username));

create trigger profiles_touch_updated_at
  before update on public.profiles
  for each row execute function private.touch_updated_at();

alter table public.profiles enable row level security;
revoke all on table public.profiles from public, anon, authenticated;
grant select on table public.profiles to authenticated;
grant insert (username, avatar_id, codm_ign, preferred_format) on table public.profiles to authenticated;
grant update (username, avatar_id, codm_ign, preferred_format) on table public.profiles to authenticated;

create policy "Signed-in players can see profiles"
  on public.profiles for select to authenticated
  using (true);

create policy "Players create their own profile"
  on public.profiles for insert to authenticated
  with check (id = (select auth.uid()));

create policy "Players edit their own profile"
  on public.profiles for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- ---------------------------------------------------------------------------
-- Private contact details (owner only)
-- ---------------------------------------------------------------------------
create table public.profile_contacts (
  id uuid primary key default auth.uid() references public.profiles (id) on delete cascade,
  whatsapp_number text,
  updated_at timestamptz not null default now(),
  constraint profile_contacts_whatsapp_check check (
    whatsapp_number is null or whatsapp_number ~ '^\+[1-9][0-9]{7,14}$'
  )
);

create trigger profile_contacts_touch_updated_at
  before update on public.profile_contacts
  for each row execute function private.touch_updated_at();

alter table public.profile_contacts enable row level security;
revoke all on table public.profile_contacts from public, anon, authenticated;
grant select on table public.profile_contacts to authenticated;
grant insert (whatsapp_number) on table public.profile_contacts to authenticated;
grant update (whatsapp_number) on table public.profile_contacts to authenticated;

create policy "Players see only their own contact details"
  on public.profile_contacts for select to authenticated
  using (id = (select auth.uid()));

create policy "Players add their own contact details"
  on public.profile_contacts for insert to authenticated
  with check (id = (select auth.uid()));

create policy "Players change their own contact details"
  on public.profile_contacts for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- Sign-up form: "is this username free?" Works before signing in.
create function public.is_username_available(candidate text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select candidate ~ '^[A-Za-z0-9_]{3,20}$'
    and not exists (
      select 1 from public.profiles where lower(username) = lower(candidate)
    );
$$;
revoke all on function public.is_username_available(text) from public;
grant execute on function public.is_username_available(text) to anon, authenticated;

-- "Delete my account": removes the login and, through ON DELETE CASCADE,
-- the profile, contacts, clans owned, memberships, messages and reports.
create function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is null then
    raise exception 'not_signed_in' using errcode = '42501';
  end if;
  delete from auth.users where id = (select auth.uid());
end;
$$;
revoke all on function public.delete_my_account() from public;
grant execute on function public.delete_my_account() to authenticated;

-- ---------------------------------------------------------------------------
-- Chat channels: community (made by us) and clans (made by players)
-- ---------------------------------------------------------------------------
create table public.chat_channels (
  id uuid primary key default gen_random_uuid(),
  game text not null default 'codm',
  kind text not null default 'clan',
  slug text not null default substr(replace(gen_random_uuid()::text, '-', ''), 1, 12),
  name text not null,
  tag text,
  description text,
  owner_id uuid default auth.uid() references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),

  constraint chat_channels_game_check check (game in ('codm', 'pubgm', 'freefire', 'efootball', 'chess')),
  constraint chat_channels_kind_check check (kind in ('community', 'clan')),
  constraint chat_channels_slug_check check (slug ~ '^[a-z0-9-]{3,40}$'),
  constraint chat_channels_slug_key unique (slug),
  constraint chat_channels_name_check check (
    char_length(name) between 3 and 24
    and name = btrim(name)
    and name !~ '[[:cntrl:]\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]'
  ),
  constraint chat_channels_tag_check check (tag is null or tag ~ '^[A-Z0-9]{2,5}$'),
  constraint chat_channels_description_check check (
    description is null or (char_length(description) <= 140 and description !~ '[[:cntrl:]]')
  ),
  constraint chat_channels_clan_owner_check check (kind = 'community' or owner_id is not null)
);

-- Clan names are unique per game; each player can own one clan (anti-spam).
create unique index chat_channels_clan_name_key on public.chat_channels (game, lower(name)) where kind = 'clan';
create unique index chat_channels_one_clan_per_owner on public.chat_channels (owner_id) where kind = 'clan';

create table public.clan_members (
  channel_id uuid not null references public.chat_channels (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'member')),
  joined_at timestamptz not null default now(),
  primary key (channel_id, user_id)
);
create index clan_members_user_idx on public.clan_members (user_id);

-- Can the current player read this channel?
create function private.can_read_channel(target uuid)
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
          or exists (
            select 1 from public.clan_members m
            where m.channel_id = target and m.user_id = (select auth.uid())
          )
        )
    )
    or private.is_admin();
$$;

-- Can the current player post in this channel?
create function private.can_post(target uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.can_read_channel(target)
    and not private.is_banned()
    and exists (select 1 from public.profiles where id = (select auth.uid()));
$$;

revoke all on function private.is_admin() from public;
revoke all on function private.is_banned() from public;
revoke all on function private.can_read_channel(uuid) from public;
revoke all on function private.can_post(uuid) from public;
grant execute on function private.is_admin() to authenticated;
grant execute on function private.is_banned() to authenticated;
grant execute on function private.can_read_channel(uuid) to authenticated;
grant execute on function private.can_post(uuid) to authenticated;

alter table public.chat_channels enable row level security;
revoke all on table public.chat_channels from public, anon, authenticated;
grant select on table public.chat_channels to authenticated;
grant insert (game, name, tag, description) on table public.chat_channels to authenticated;
grant delete on table public.chat_channels to authenticated;

create policy "Signed-in players can browse channels and clans"
  on public.chat_channels for select to authenticated
  using (true);

create policy "Players can start a clan"
  on public.chat_channels for insert to authenticated
  with check (
    kind = 'clan'
    and owner_id = (select auth.uid())
    and not private.is_banned()
  );

create policy "Clan owners and admins can delete a clan"
  on public.chat_channels for delete to authenticated
  using (
    (kind = 'clan' and owner_id = (select auth.uid()))
    or private.is_admin()
  );

-- The clan's creator automatically becomes its owner-member.
create function private.add_clan_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.kind = 'clan' then
    insert into public.clan_members (channel_id, user_id, role)
    values (new.id, new.owner_id, 'owner');
  end if;
  return new;
end;
$$;
revoke all on function private.add_clan_owner() from public;

create trigger chat_channels_add_clan_owner
  after insert on public.chat_channels
  for each row execute function private.add_clan_owner();

alter table public.clan_members enable row level security;
revoke all on table public.clan_members from public, anon, authenticated;
grant select on table public.clan_members to authenticated;
grant insert (channel_id) on table public.clan_members to authenticated;
grant delete on table public.clan_members to authenticated;

create policy "Signed-in players can see clan members"
  on public.clan_members for select to authenticated
  using (true);

create policy "Players can join a clan"
  on public.clan_members for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and role = 'member'
    and not private.is_banned()
    and exists (
      select 1 from public.chat_channels c
      where c.id = channel_id and c.kind = 'clan'
    )
  );

-- Owners leave by deleting the clan instead.
create policy "Members can leave, admins can remove"
  on public.clan_members for delete to authenticated
  using (
    (user_id = (select auth.uid()) and role = 'member')
    or private.is_admin()
  );

-- Caps: 10 clans per player, 100 players per clan.
create function private.clan_member_limits()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select count(*) from public.clan_members where user_id = new.user_id) >= 10 then
    raise exception 'too_many_clans' using errcode = 'PT422';
  end if;
  if (select count(*) from public.clan_members where channel_id = new.channel_id) >= 100 then
    raise exception 'clan_full' using errcode = 'PT422';
  end if;
  return new;
end;
$$;
revoke all on function private.clan_member_limits() from public;

create trigger clan_members_limits
  before insert on public.clan_members
  for each row execute function private.clan_member_limits();

-- ---------------------------------------------------------------------------
-- Blocks (a player's private block list)
-- ---------------------------------------------------------------------------
create table public.user_blocks (
  blocker_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  blocked_id uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  constraint user_blocks_not_self check (blocker_id <> blocked_id)
);

alter table public.user_blocks enable row level security;
revoke all on table public.user_blocks from public, anon, authenticated;
grant select on table public.user_blocks to authenticated;
grant insert (blocked_id) on table public.user_blocks to authenticated;
grant delete on table public.user_blocks to authenticated;

create policy "Players see their own block list"
  on public.user_blocks for select to authenticated
  using (blocker_id = (select auth.uid()));

create policy "Players block others"
  on public.user_blocks for insert to authenticated
  with check (blocker_id = (select auth.uid()));

create policy "Players unblock others"
  on public.user_blocks for delete to authenticated
  using (blocker_id = (select auth.uid()));

-- ---------------------------------------------------------------------------
-- Messages
-- ---------------------------------------------------------------------------
create table public.chat_messages (
  id bigint generated always as identity primary key,
  channel_id uuid not null references public.chat_channels (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  deleted_by uuid references auth.users (id) on delete set null,

  constraint chat_messages_body_check check (
    char_length(body) between 1 and 500
    and body = btrim(body)
    and body !~ '[[:cntrl:]\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]'
  )
);
create index chat_messages_channel_created_idx on public.chat_messages (channel_id, created_at desc);
create index chat_messages_user_created_idx on public.chat_messages (user_id, created_at desc);

alter table public.chat_messages enable row level security;
revoke all on table public.chat_messages from public, anon, authenticated;
grant select on table public.chat_messages to authenticated;
grant insert (channel_id, body) on table public.chat_messages to authenticated;

create policy "Players read channels they belong to"
  on public.chat_messages for select to authenticated
  using (
    deleted_at is null
    and private.can_read_channel(channel_id)
    and not exists (
      select 1 from public.user_blocks b
      where b.blocker_id = (select auth.uid()) and b.blocked_id = chat_messages.user_id
    )
  );

create policy "Players post as themselves where allowed"
  on public.chat_messages for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and private.can_post(channel_id)
  );

-- Content filter + rate limit, enforced in the database so nothing can skip it.
create function private.check_chat_message()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  last_10s integer;
  last_minute integer;
begin
  -- Links are how scams spread. Block anything URL-shaped.
  if new.body ~* '(https?://|www\.|\m[a-z0-9-]+\.(com|net|org|co|io|me|ly|gg|xyz|link|site|online|app|zw|za|info|biz|tk)\M)' then
    raise exception 'no_links' using errcode = 'PT422';
  end if;

  -- Phone numbers are private (and a scam route). 9+ digits in a row,
  -- ignoring spaces, dots, dashes and brackets.
  if regexp_replace(new.body, '[[:space:].()-]', '', 'g') ~ '[0-9]{9,}' then
    raise exception 'no_phone_numbers' using errcode = 'PT422';
  end if;

  select count(*) filter (where created_at > now() - interval '10 seconds'),
         count(*)
    into last_10s, last_minute
    from public.chat_messages
   where user_id = new.user_id
     and created_at > now() - interval '1 minute';

  if last_10s >= 5 or last_minute >= 20 then
    raise exception 'rate_limited' using errcode = 'PT429';
  end if;

  return new;
end;
$$;
revoke all on function private.check_chat_message() from public;

create trigger chat_messages_check
  before insert on public.chat_messages
  for each row execute function private.check_chat_message();

-- Authors and admins can remove a message (soft delete keeps it for disputes).
create function public.delete_chat_message(message_id bigint)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.chat_messages
     set deleted_at = now(), deleted_by = (select auth.uid())
   where id = message_id
     and deleted_at is null
     and (user_id = (select auth.uid()) or private.is_admin());
  if not found then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
end;
$$;
revoke all on function public.delete_chat_message(bigint) from public;
grant execute on function public.delete_chat_message(bigint) to authenticated;

-- ---------------------------------------------------------------------------
-- Reports (players report, only admins read)
-- ---------------------------------------------------------------------------
create table public.chat_reports (
  id bigint generated always as identity primary key,
  message_id bigint not null references public.chat_messages (id) on delete cascade,
  reporter_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  reason text not null check (reason in ('spam', 'abuse', 'scam', 'cheating', 'other')),
  created_at timestamptz not null default now(),
  constraint chat_reports_once unique (message_id, reporter_id)
);

alter table public.chat_reports enable row level security;
revoke all on table public.chat_reports from public, anon, authenticated;
grant select on table public.chat_reports to authenticated;
grant insert (message_id, reason) on table public.chat_reports to authenticated;

create policy "Players report messages they can see"
  on public.chat_reports for insert to authenticated
  with check (
    reporter_id = (select auth.uid())
    -- Runs with the reporter's own permissions, so RLS on messages applies.
    and exists (select 1 from public.chat_messages m where m.id = message_id)
  );

create policy "Only admins read reports"
  on public.chat_reports for select to authenticated
  using (private.is_admin());

-- Admin tool: ban a player from chat (days null = permanent).
create function public.ban_player(target uuid, reason text, days integer default null)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.is_admin() then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  insert into public.chat_bans (user_id, reason, banned_by, banned_until)
  values (target, reason, (select auth.uid()),
          case when days is null then null else now() + make_interval(days => days) end)
  on conflict (user_id) do update
    set reason = excluded.reason,
        banned_by = excluded.banned_by,
        banned_until = excluded.banned_until;
end;
$$;
revoke all on function public.ban_player(uuid, text, integer) from public;
grant execute on function public.ban_player(uuid, text, integer) to authenticated;

-- ---------------------------------------------------------------------------
-- Live updates: new messages are pushed to subscribed players (RLS applies)
-- ---------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    alter publication supabase_realtime add table public.chat_messages;
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- Starter community channels
-- ---------------------------------------------------------------------------
insert into public.chat_channels (game, kind, slug, name, description, owner_id) values
  ('codm', 'community', 'codm-community', 'CODM Community', 'Everyone playing Call of Duty: Mobile on GameArena.', null),
  ('codm', 'community', 'codm-find-squad', 'Find a squad', 'Looking for teammates? Post your role, rank and when you play.', null);
