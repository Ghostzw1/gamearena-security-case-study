-- Admin powers need two-step login: password AND a 6-digit code from an
-- authenticator app (Supabase MFA, TOTP).
--
-- Security model (also in SECURITY.md):
--   * private.is_admin() is only true when the session has finished the
--     second step (JWT claim aal = 'aal2'). Every admin check in the app
--     (RLS policies, admin functions, the admin panel) goes through it, so a
--     stolen password alone gives no admin powers at all.
--   * Without the code an admin is treated like a normal player.
--   * admin_status() tells the signed-in admin (and only them) what to do
--     next: set up the app, enter a code, or nothing.
--   * Lost phone? Remove the factor in the Supabase dashboard
--     (Authentication → Users → the user → MFA factors), then set up again.

create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.app_admins where user_id = (select auth.uid()))
    and coalesce((select auth.jwt() ->> 'aal'), '') = 'aal2';
$$;

-- 'none' (not an admin), 'needs_setup' (no authenticator app yet),
-- 'needs_code' (app set up, code not entered this session), 'ok'.
create function public.admin_status()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when not exists (select 1 from public.app_admins where user_id = (select auth.uid())) then 'none'
    when coalesce((select auth.jwt() ->> 'aal'), '') = 'aal2' then 'ok'
    when exists (
      select 1 from auth.mfa_factors f
      where f.user_id = (select auth.uid()) and f.status::text = 'verified' and f.factor_type::text = 'totp'
    ) then 'needs_code'
    else 'needs_setup'
  end;
$$;

revoke all on function public.admin_status() from public, anon;
grant execute on function public.admin_status() to authenticated;
