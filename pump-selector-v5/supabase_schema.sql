-- PZONE Pump Selector V5 — Supabase schema
-- Safe to run in Supabase SQL Editor.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role text not null default 'engineer' check (role in ('admin','engineer','viewer')),
  created_at timestamptz not null default now()
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  client text,
  location text,
  status text not null default 'Active',
  notes text,
  created_at timestamptz not null default now()
);

create table if not exists public.saved_selections (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  project_id uuid references public.projects(id) on delete cascade,
  pump_id text not null,
  maker text,
  model text,
  flow numeric,
  required_head numeric,
  calculated_head numeric,
  delta_h numeric,
  data_quality text,
  source text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.saved_selections enable row level security;

create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.claim_admin()
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then return false; end if;
  if exists(select 1 from public.profiles where role='admin') then return false; end if;
  insert into public.profiles(id,full_name,role)
  values(auth.uid(), coalesce((select raw_user_meta_data->>'full_name' from auth.users where id=auth.uid()), 'Administrator'),'admin')
  on conflict(id) do update set role='admin';
  return true;
end;
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles(id,full_name,role)
  values(new.id, coalesce(new.raw_user_meta_data->>'full_name', new.email), 'engineer')
  on conflict(id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

drop policy if exists "profiles own or admin select" on public.profiles;
create policy "profiles own or admin select" on public.profiles for select
using (id=auth.uid() or public.is_admin());

drop policy if exists "profiles own insert" on public.profiles;
create policy "profiles own insert" on public.profiles for insert
with check (id=auth.uid());

drop policy if exists "projects owner or admin select" on public.projects;
create policy "projects owner or admin select" on public.projects for select
using (owner_id=auth.uid() or public.is_admin());

drop policy if exists "projects owner insert" on public.projects;
create policy "projects owner insert" on public.projects for insert
with check (owner_id=auth.uid());

drop policy if exists "projects owner or admin update" on public.projects;
create policy "projects owner or admin update" on public.projects for update
using (owner_id=auth.uid() or public.is_admin());

drop policy if exists "projects owner or admin delete" on public.projects;
create policy "projects owner or admin delete" on public.projects for delete
using (owner_id=auth.uid() or public.is_admin());

drop policy if exists "selections owner or admin select" on public.saved_selections;
create policy "selections owner or admin select" on public.saved_selections for select
using (owner_id=auth.uid() or public.is_admin());

drop policy if exists "selections owner insert" on public.saved_selections;
create policy "selections owner insert" on public.saved_selections for insert
with check (owner_id=auth.uid());

drop policy if exists "selections owner or admin update" on public.saved_selections;
create policy "selections owner or admin update" on public.saved_selections for update
using (owner_id=auth.uid() or public.is_admin());

drop policy if exists "selections owner or admin delete" on public.saved_selections;
create policy "selections owner or admin delete" on public.saved_selections for delete
using (owner_id=auth.uid() or public.is_admin());

grant execute on function public.claim_admin() to authenticated;
grant execute on function public.is_admin() to authenticated;