-- Pictures, videos and stickers in chat.
--
-- Security model (also in SECURITY.md):
--   * Files live in a PRIVATE bucket (chat-media): nothing is public; the app
--     shows them through short-lived signed links.
--   * Players can only upload into their own folder (<their id>/...). The
--     bucket only accepts images and videos, max 15 MB; pictures max 3 MB.
--   * A file can only be attached to a message by the player who uploaded it,
--     and only after it really exists. The server also checks the first bytes
--     of the file (magic bytes) before posting it.
--   * You can only open a file if you can read the chat message it's in
--     (same rules as the chat itself: clan, country, event chats…).
--   * Max 10 pictures/videos per player per 10 minutes.
--   * Stickers are just an id: drawn by the app, nothing uploaded.

alter table public.chat_messages alter column body drop not null;
alter table public.chat_messages drop constraint chat_messages_body_check;
alter table public.chat_messages
  add column sticker_id text,
  add column media_path text,
  add column media_kind text;
alter table public.chat_messages
  add constraint chat_messages_body_check check (
    body is null or (char_length(body) between 1 and 500 and body = btrim(body) and private.clean_text(body))
  ),
  add constraint chat_messages_sticker_check check (sticker_id is null or sticker_id ~ '^[a-z0-9-]{2,40}$'),
  add constraint chat_messages_media_kind_check check (
    (media_path is null) = (media_kind is null) and (media_kind is null or media_kind in ('image', 'video'))
  ),
  add constraint chat_messages_media_path_check check (
    media_path is null or media_path ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}\.(jpg|png|webp|gif|mp4|webm|mov)$'
  ),
  add constraint chat_messages_has_content check (
    num_nonnulls(body, sticker_id, media_path) >= 1 and not (sticker_id is not null and media_path is not null)
  );
create index chat_messages_media_idx on public.chat_messages (media_path) where media_path is not null;

grant insert (sticker_id, media_path, media_kind) on table public.chat_messages to authenticated;

-- The private bucket.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'chat-media', 'chat-media', false, 15728640,
  array['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm', 'video/quicktime']
)
on conflict (id) do update
  set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

-- Attaching a file to a message.
create function private.check_chat_media()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  meta jsonb;
begin
  if new.media_path is null then
    return new;
  end if;
  if split_part(new.media_path, '/', 1) <> coalesce((select auth.uid())::text, '-') then
    raise exception 'not_your_upload' using errcode = '42501';
  end if;
  select o.metadata into meta from storage.objects o where o.bucket_id = 'chat-media' and o.name = new.media_path;
  if not found then
    raise exception 'upload_missing' using errcode = 'PT422';
  end if;
  if (new.media_kind = 'image') <> (new.media_path ~ '\.(jpg|png|webp|gif)$') then
    raise exception 'bad_media' using errcode = 'PT422';
  end if;
  if new.media_kind = 'image' and coalesce((meta ->> 'size')::bigint, 0) > 3145728 then
    raise exception 'image_too_big' using errcode = 'PT422';
  end if;
  if (
    select count(*) from public.chat_messages
    where user_id = new.user_id and media_path is not null and created_at > now() - interval '10 minutes'
  ) >= 10 then
    raise exception 'media_rate_limited' using errcode = 'PT429';
  end if;
  return new;
end;
$$;
revoke all on function private.check_chat_media() from public;

create trigger chat_messages_media
  before insert on public.chat_messages
  for each row execute function private.check_chat_media();

-- Can I open this file? Only if I can read a (not deleted) message with it.
create function private.can_see_media(path text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.chat_messages m
    where m.media_path = path and m.deleted_at is null and private.can_read_channel(m.channel_id)
  );
$$;
revoke all on function private.can_see_media(text) from public;
grant execute on function private.can_see_media(text) to authenticated;

create policy "Chat media: upload into your own folder"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'chat-media'
    and (storage.foldername(name))[1] = (select auth.uid())::text
    and not private.is_banned()
  );

create policy "Chat media: open files from chats you can read"
  on storage.objects for select to authenticated
  using (
    bucket_id = 'chat-media'
    and ((storage.foldername(name))[1] = (select auth.uid())::text or private.can_see_media(name))
  );

create policy "Chat media: delete your own uploads"
  on storage.objects for delete to authenticated
  using (bucket_id = 'chat-media' and (storage.foldername(name))[1] = (select auth.uid())::text);
