-- Stage 4b follow-up: the chat's "no links, no phone numbers" rule now also
-- covers squad posts, join notes, ideas, idea comments and clan
-- announcements. Links are how scams spread; phone numbers are private.
-- Same patterns as private.check_chat_message (20261124180000).

create function private.refuse_links_and_phones(t text)
returns void
language plpgsql
immutable
set search_path = ''
as $$
begin
  if t is null then
    return;
  end if;
  if t ~* '(https?://|www\.|\m[a-z0-9-]+\.(com|net|org|co|io|me|ly|gg|xyz|link|site|online|app|zw|za|info|biz|tk)\M)' then
    raise exception 'no_links' using errcode = 'PT422';
  end if;
  if regexp_replace(t, '[[:space:].()-]', '', 'g') ~ '[0-9]{9,}' then
    raise exception 'no_phone_numbers' using errcode = 'PT422';
  end if;
end;
$$;
revoke all on function private.refuse_links_and_phones(text) from public;

create function private.guard_community_text()
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
  end case;
  return new;
end;
$$;
revoke all on function private.guard_community_text() from public;
grant execute on function private.refuse_links_and_phones(text) to authenticated;

create trigger squad_posts_text_guard before insert or update of body, availability on public.squad_posts
  for each row execute function private.guard_community_text();
create trigger squad_post_requests_text_guard before insert or update of message on public.squad_post_requests
  for each row execute function private.guard_community_text();
create trigger ideas_text_guard before insert or update of body on public.ideas
  for each row execute function private.guard_community_text();
create trigger idea_comments_text_guard before insert or update of body on public.idea_comments
  for each row execute function private.guard_community_text();
create trigger clan_announcements_text_guard before insert or update of body on public.clan_announcements
  for each row execute function private.guard_community_text();
