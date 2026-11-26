-- Invite a host or streamer by email before they have an account
-- (owner's request, 2026-11-26). When someone with that email creates their
-- GameArena profile, they join the event's staff automatically and the
-- invite is removed.
--
-- Privacy: invite emails are visible to admins only (RLS) and never to
-- players. Emails are never written into migrations or code: an admin adds
-- invites in the live database.
--
-- Security note: email confirmation is off (SECURITY.md), so an email
-- address isn't proven to belong to the person who signs up with it. An
-- admin should check the staff list after an invite is claimed.

create table public.staff_invites (
  id bigint generated always as identity primary key,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  email text not null,
  role text not null default 'host',
  created_at timestamptz not null default now(),
  constraint staff_invites_role_check check (role in ('host', 'streamer')),
  constraint staff_invites_email_check check (
    email = lower(btrim(email))
    and char_length(email) between 5 and 254
    and email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'
  ),
  constraint staff_invites_unique unique (tournament_id, email)
);

alter table public.staff_invites enable row level security;
revoke all on table public.staff_invites from anon, authenticated;
grant select, insert, delete on table public.staff_invites to authenticated;

-- Admins only (two-step login). Everyone else sees and changes nothing.
create policy staff_invites_admin_select on public.staff_invites
  for select to authenticated using ((select private.is_admin()));
create policy staff_invites_admin_insert on public.staff_invites
  for insert to authenticated with check ((select private.is_admin()));
create policy staff_invites_admin_delete on public.staff_invites
  for delete to authenticated using ((select private.is_admin()));

-- When a profile is created, claim any invites for that account's email.
create function private.claim_staff_invites()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  em text;
begin
  select lower(u.email) into em from auth.users u where u.id = new.id;
  if em is null then
    return new;
  end if;
  insert into public.tournament_staff (tournament_id, user_id, role)
  select i.tournament_id, new.id, i.role
  from public.staff_invites i
  where i.email = em
  on conflict (tournament_id, user_id) do update set role = excluded.role;
  delete from public.staff_invites where email = em;
  return new;
end;
$$;

revoke all on function private.claim_staff_invites() from public;

create trigger profiles_claim_staff_invites
  after insert on public.profiles
  for each row execute function private.claim_staff_invites();
