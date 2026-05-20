create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

do $$
begin
  create type public.user_role as enum ('owner', 'coordinator', 'worker');
exception
  when duplicate_object then null;
end $$;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role public.user_role not null,
  full_name text not null,
  phone text,
  avatar_url text
);

create table if not exists public.sites (
  id uuid primary key default extensions.gen_random_uuid(),
  name text not null,
  location text,
  owner_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'active'
);

create table if not exists public.material_requests (
  id uuid primary key default extensions.gen_random_uuid(),
  site_id uuid not null references public.sites(id) on delete cascade,
  worker_id uuid not null references public.profiles(id) on delete cascade,
  coordinator_id uuid references public.profiles(id) on delete set null,
  item_name text not null,
  quantity numeric(12, 2) not null check (quantity > 0),
  urgency text not null default 'normal',
  status text not null default 'pending',
  notes text,
  invoice_url text,
  created_at timestamptz not null default now()
);

create table if not exists public.salary_requests (
  id uuid primary key default extensions.gen_random_uuid(),
  worker_id uuid not null references public.profiles(id) on delete cascade,
  site_id uuid not null references public.sites(id) on delete cascade,
  amount numeric(12, 2) not null check (amount > 0),
  period_start date not null,
  period_end date not null,
  status text not null default 'pending',
  receipt_url text,
  notes text,
  created_at timestamptz not null default now(),
  check (period_end >= period_start)
);

create table if not exists public.transactions (
  id uuid primary key default extensions.gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  coordinator_id uuid references public.profiles(id) on delete set null,
  type text not null,
  amount numeric(12, 2) not null check (amount > 0),
  currency text not null default 'USD' check (char_length(currency) = 3),
  proof_url text,
  status text not null default 'pending',
  created_at timestamptz not null default now()
);

create index if not exists sites_owner_id_idx on public.sites(owner_id);
create index if not exists material_requests_site_id_idx on public.material_requests(site_id);
create index if not exists material_requests_worker_id_idx on public.material_requests(worker_id);
create index if not exists material_requests_coordinator_id_idx on public.material_requests(coordinator_id);
create index if not exists salary_requests_worker_id_idx on public.salary_requests(worker_id);
create index if not exists salary_requests_site_id_idx on public.salary_requests(site_id);
create index if not exists transactions_owner_id_idx on public.transactions(owner_id);
create index if not exists transactions_coordinator_id_idx on public.transactions(coordinator_id);

create or replace function public.current_user_role()
returns public.user_role
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;

create or replace function public.owns_site(target_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.sites
    where id = target_site_id
      and owner_id = auth.uid()
  )
$$;

create or replace function public.can_access_site(target_site_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.owns_site(target_site_id)
    or exists (
      select 1
      from public.material_requests
      where site_id = target_site_id
        and (worker_id = auth.uid() or coordinator_id = auth.uid())
    )
    or exists (
      select 1
      from public.salary_requests
      where site_id = target_site_id
        and worker_id = auth.uid()
    )
$$;

create or replace function public.can_access_profile(target_profile_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select target_profile_id = auth.uid()
    or (
      public.current_user_role() = 'owner'
      and (
        exists (
          select 1
          from public.material_requests mr
          join public.sites s on s.id = mr.site_id
          where s.owner_id = auth.uid()
            and target_profile_id in (mr.worker_id, mr.coordinator_id)
        )
        or exists (
          select 1
          from public.salary_requests sr
          join public.sites s on s.id = sr.site_id
          where s.owner_id = auth.uid()
            and sr.worker_id = target_profile_id
        )
        or exists (
          select 1
          from public.transactions
          where owner_id = auth.uid()
            and coordinator_id = target_profile_id
        )
      )
    )
    or (
      public.current_user_role() = 'coordinator'
      and (
        exists (
          select 1
          from public.material_requests
          where coordinator_id = auth.uid()
            and worker_id = target_profile_id
        )
        or exists (
          select 1
          from public.transactions
          where coordinator_id = auth.uid()
            and owner_id = target_profile_id
        )
      )
    )
    or (
      public.current_user_role() = 'worker'
      and exists (
        select 1
        from public.material_requests
        where worker_id = auth.uid()
          and coordinator_id = target_profile_id
      )
    )
$$;

create or replace function public.prevent_profile_role_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(auth.role(), '') <> 'service_role' and new.role is distinct from old.role then
    raise exception 'profile role cannot be changed by client updates';
  end if;

  return new;
end
$$;

drop trigger if exists prevent_profile_role_change on public.profiles;
create trigger prevent_profile_role_change
before update of role on public.profiles
for each row execute function public.prevent_profile_role_change();

alter table public.profiles enable row level security;
alter table public.sites enable row level security;
alter table public.material_requests enable row level security;
alter table public.salary_requests enable row level security;
alter table public.transactions enable row level security;

drop policy if exists "Profiles are visible to related users" on public.profiles;
create policy "Profiles are visible to related users"
on public.profiles
for select
to authenticated
using (public.can_access_profile(id));

drop policy if exists "Users can create their own profile" on public.profiles;
create policy "Users can create their own profile"
on public.profiles
for insert
to authenticated
with check (id = auth.uid());

drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile"
on public.profiles
for update
to authenticated
using (id = auth.uid())
with check (id = auth.uid());

drop policy if exists "Sites are visible to participants" on public.sites;
create policy "Sites are visible to participants"
on public.sites
for select
to authenticated
using (public.can_access_site(id));

drop policy if exists "Owners can create their own sites" on public.sites;
create policy "Owners can create their own sites"
on public.sites
for insert
to authenticated
with check (public.current_user_role() = 'owner' and owner_id = auth.uid());

drop policy if exists "Owners can update their own sites" on public.sites;
create policy "Owners can update their own sites"
on public.sites
for update
to authenticated
using (public.current_user_role() = 'owner' and owner_id = auth.uid())
with check (public.current_user_role() = 'owner' and owner_id = auth.uid());

drop policy if exists "Owners can delete their own sites" on public.sites;
create policy "Owners can delete their own sites"
on public.sites
for delete
to authenticated
using (public.current_user_role() = 'owner' and owner_id = auth.uid());

drop policy if exists "Material requests are visible to involved users" on public.material_requests;
create policy "Material requests are visible to involved users"
on public.material_requests
for select
to authenticated
using (worker_id = auth.uid() or coordinator_id = auth.uid() or public.owns_site(site_id));

drop policy if exists "Workers can create their own material requests" on public.material_requests;
create policy "Workers can create their own material requests"
on public.material_requests
for insert
to authenticated
with check (public.current_user_role() = 'worker' and worker_id = auth.uid());

drop policy if exists "Assigned coordinators and owners can update material requests" on public.material_requests;
create policy "Assigned coordinators and owners can update material requests"
on public.material_requests
for update
to authenticated
using (coordinator_id = auth.uid() or public.owns_site(site_id))
with check (coordinator_id = auth.uid() or public.owns_site(site_id));

drop policy if exists "Owners can delete material requests for their sites" on public.material_requests;
create policy "Owners can delete material requests for their sites"
on public.material_requests
for delete
to authenticated
using (public.owns_site(site_id));

drop policy if exists "Salary requests are visible to workers and site owners" on public.salary_requests;
create policy "Salary requests are visible to workers and site owners"
on public.salary_requests
for select
to authenticated
using (worker_id = auth.uid() or public.owns_site(site_id));

drop policy if exists "Workers can create their own salary requests" on public.salary_requests;
create policy "Workers can create their own salary requests"
on public.salary_requests
for insert
to authenticated
with check (public.current_user_role() = 'worker' and worker_id = auth.uid());

drop policy if exists "Workers and owners can update salary requests" on public.salary_requests;
create policy "Workers and owners can update salary requests"
on public.salary_requests
for update
to authenticated
using (worker_id = auth.uid() or public.owns_site(site_id))
with check (worker_id = auth.uid() or public.owns_site(site_id));

drop policy if exists "Owners can delete salary requests for their sites" on public.salary_requests;
create policy "Owners can delete salary requests for their sites"
on public.salary_requests
for delete
to authenticated
using (public.owns_site(site_id));

drop policy if exists "Transactions are visible to involved users" on public.transactions;
create policy "Transactions are visible to involved users"
on public.transactions
for select
to authenticated
using (owner_id = auth.uid() or coordinator_id = auth.uid());

drop policy if exists "Owners can create their own transactions" on public.transactions;
create policy "Owners can create their own transactions"
on public.transactions
for insert
to authenticated
with check (public.current_user_role() = 'owner' and owner_id = auth.uid());

drop policy if exists "Owners and coordinators can update their transactions" on public.transactions;
create policy "Owners and coordinators can update their transactions"
on public.transactions
for update
to authenticated
using (owner_id = auth.uid() or coordinator_id = auth.uid())
with check (owner_id = auth.uid() or coordinator_id = auth.uid());

drop policy if exists "Owners can delete their transactions" on public.transactions;
create policy "Owners can delete their transactions"
on public.transactions
for delete
to authenticated
using (owner_id = auth.uid());

grant usage on schema public to authenticated;
grant usage on schema extensions to authenticated;
grant all on public.profiles to authenticated;
grant all on public.sites to authenticated;
grant all on public.material_requests to authenticated;
grant all on public.salary_requests to authenticated;
grant all on public.transactions to authenticated;
revoke all on function public.current_user_role() from public;
revoke all on function public.owns_site(uuid) from public;
revoke all on function public.can_access_site(uuid) from public;
revoke all on function public.can_access_profile(uuid) from public;
grant execute on function public.current_user_role() to authenticated;
grant execute on function public.owns_site(uuid) to authenticated;
grant execute on function public.can_access_site(uuid) to authenticated;
grant execute on function public.can_access_profile(uuid) to authenticated;
