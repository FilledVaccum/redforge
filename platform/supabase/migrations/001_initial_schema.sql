-- ═══════════════════════════════════════════════════════════════
-- RedForge Platform — Initial Database Schema
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- ═══════════════════════════════════════════════════════════════

-- ── Profiles (extends auth.users) ────────────────────────────
create table if not exists public.profiles (
  id            uuid references auth.users on delete cascade primary key,
  email         text,
  full_name     text,
  company       text,
  role          text,
  avatar_url    text,
  stripe_customer_id    text unique,
  subscription_tier     text default 'free' check (subscription_tier in ('free', 'starter', 'professional', 'enterprise')),
  subscription_status   text default 'inactive' check (subscription_status in ('inactive', 'active', 'canceled', 'past_due')),
  scans_used    int default 0,
  scans_limit   int default 0,
  created_at    timestamptz default now(),
  updated_at    timestamptz default now()
);

comment on table public.profiles is 'User profiles linked to Supabase auth. One row per user.';

-- ── Scans ────────────────────────────────────────────────────
create table if not exists public.scans (
  id              uuid default gen_random_uuid() primary key,
  user_id         uuid references public.profiles(id) on delete cascade not null,

  -- Configuration
  provider        text not null,
  model           text,
  endpoint_url    text,
  system_prompt   text,
  probe_ids       text[],
  enable_mutations boolean default false,
  mutation_strategies text[],
  max_payloads    int,

  -- Status
  status          text default 'pending'
                  check (status in ('pending', 'running', 'completed', 'failed', 'canceled')),

  -- Results (populated after scan completes)
  risk_score      numeric(4,2),
  total_probes    int,
  passed          int,
  failed_critical int default 0,
  failed_high     int default 0,
  failed_medium   int default 0,
  failed_low      int default 0,
  results         jsonb,
  report_url      text,

  -- Timestamps
  started_at      timestamptz,
  completed_at    timestamptz,
  created_at      timestamptz default now()
);

create index idx_scans_user_id on public.scans(user_id);
create index idx_scans_status on public.scans(status);
create index idx_scans_created_at on public.scans(created_at desc);

comment on table public.scans is 'LLM security scan configurations and results.';

-- ── Subscriptions ────────────────────────────────────────────
create table if not exists public.subscriptions (
  id                        uuid default gen_random_uuid() primary key,
  user_id                   uuid references public.profiles(id) on delete cascade not null,
  stripe_subscription_id    text unique,
  stripe_price_id           text,
  tier                      text not null check (tier in ('starter', 'professional', 'enterprise')),
  status                    text default 'active'
                            check (status in ('active', 'canceled', 'past_due', 'incomplete')),
  current_period_start      timestamptz,
  current_period_end        timestamptz,
  cancel_at_period_end      boolean default false,
  created_at                timestamptz default now(),
  updated_at                timestamptz default now()
);

create index idx_subscriptions_user_id on public.subscriptions(user_id);

comment on table public.subscriptions is 'Stripe subscription records.';

-- ── Scan Findings (individual probe results) ─────────────────
create table if not exists public.scan_findings (
  id            uuid default gen_random_uuid() primary key,
  scan_id       uuid references public.scans(id) on delete cascade not null,
  probe_id      text not null,
  probe_name    text,
  owasp_id      text,
  severity      text check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  status        text check (status in ('pass', 'fail')),
  score         numeric(4,2),
  payload       text,
  response      text,
  evidence      text,
  created_at    timestamptz default now()
);

create index idx_findings_scan_id on public.scan_findings(scan_id);

comment on table public.scan_findings is 'Individual probe results per scan.';

-- ═══════════════════════════════════════════════════════════════
-- Row Level Security
-- ═══════════════════════════════════════════════════════════════

alter table public.profiles enable row level security;
alter table public.scans enable row level security;
alter table public.subscriptions enable row level security;
alter table public.scan_findings enable row level security;

-- Profiles: users see and edit only their own
create policy "Users can view own profile"
  on public.profiles for select using (auth.uid() = id);
create policy "Users can update own profile"
  on public.profiles for update using (auth.uid() = id);

-- Scans: users see and create only their own
create policy "Users can view own scans"
  on public.scans for select using (auth.uid() = user_id);
create policy "Users can insert own scans"
  on public.scans for insert with check (auth.uid() = user_id);
create policy "Users can update own scans"
  on public.scans for update using (auth.uid() = user_id);

-- Subscriptions: users see only their own
create policy "Users can view own subscriptions"
  on public.subscriptions for select using (auth.uid() = user_id);

-- Scan findings: users see findings for their own scans
create policy "Users can view own scan findings"
  on public.scan_findings for select
  using (
    scan_id in (select id from public.scans where user_id = auth.uid())
  );

-- ═══════════════════════════════════════════════════════════════
-- Triggers
-- ═══════════════════════════════════════════════════════════════

-- Auto-create profile when a new user signs up
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', '')
  );
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Auto-update updated_at on profile changes
create or replace function public.update_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger profiles_updated_at
  before update on public.profiles
  for each row execute function public.update_updated_at();

create trigger subscriptions_updated_at
  before update on public.subscriptions
  for each row execute function public.update_updated_at();
