-- =====================================================================
--  BEC · Buscar, Emprender, Contratar  —  Esquema completo de Supabase
--  Pegar TODO en: Supabase → SQL Editor → New query → Run
--  Es seguro ejecutarlo más de una vez.
--
--  PASOS
--   1. Extensiones y roles / funciones base (incl. bloqueos, demo/real, copias)
--   2. Tablas (sincronización "docs", registro de actividad, Hub v2,
--      + empresas, publicaciones, transacciones, ajustes) y columnas nuevas
--   3. Funciones y triggers (guardas de seguridad, avisos, inventario,
--      separación demo/real, updated_at automático)
--   4. Vistas (job_cards, service_cards)
--   5. RPC (my_status, my_summary, adm_stats, adm_users, adm_user_set, admin_action)
--   6. Políticas RLS (+ aislamiento demo/real y permisos mínimos por tabla)
--   7. Almacenamiento (buckets: media, gallery, kyc, id-docs, resumes) + Realtime
--   8. Índices de búsqueda
--   9. Sistema de copias de seguridad
--  10. Separación entre datos de demostración y datos reales
--  11. Propietario / administrador  (EDITA TU CORREO AL FINAL)
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. BASE
-- ---------------------------------------------------------------------
create extension if not exists pgcrypto;

create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin','moderator')),
  created_at timestamptz not null default now()
);
alter table public.user_roles enable row level security;   -- sin políticas: solo funciones del servidor

create or replace function public.jwt_email() returns text
language sql stable as $$ select lower(coalesce(auth.jwt()->>'email','')) $$;

create or replace function public.is_admin() returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then return false; end if;
  return coalesce(auth.jwt()->'app_metadata'->>'role','') = 'admin'
      or exists (select 1 from public.user_roles where user_id = auth.uid() and role = 'admin');
end $$;

create or replace function public.is_staff() returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then return false; end if;
  return public.is_admin()
      or exists (select 1 from public.user_roles where user_id = auth.uid() and role = 'moderator');
end $$;

-- Búsqueda por texto parcial (ilike '%x%'); la usan los índices de la sección 8
create extension if not exists pg_trgm with schema extensions;

-- Hora de actualización automática (se conecta a cada tabla en la sección 3)
create or replace function public.touch_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end $$;

-- ¿Estamos restaurando una copia de seguridad? (desactiva reglas de negocio y avisos)
create or replace function public.restoring() returns boolean
language sql stable set search_path = '' as $$
  select coalesce(current_setting('app.restoring', true), '') = 'on'
$$;

-- ¿Hay un bloqueo entre yo y otra persona (en cualquier dirección)?
create or replace function public.blocked_with(p_other uuid) returns boolean
language plpgsql stable security definer set search_path = '' as $$
begin
  return exists (
    select 1 from public.blocks b
     where (b.blocker = p_other and b.blocked = auth.uid())
        or (b.blocker = auth.uid() and b.blocked = p_other));
end $$;

-- ¿La cuenta actual es de DEMOSTRACIÓN? (false = datos reales)
create or replace function public.my_demo() returns boolean
language plpgsql stable security definer set search_path = '' as $$
begin
  return coalesce((select p.is_demo from public.profiles p where p.id = auth.uid()), false);
end $$;

-- Un registro solo es visible si es del mismo "mundo" (demo / real) que el usuario, o si es staff
create or replace function public.in_my_realm(row_is_demo boolean) returns boolean
language plpgsql stable security definer set search_path = '' as $$
begin
  return public.is_staff() or row_is_demo = public.my_demo();
end $$;

revoke all on function public.blocked_with(uuid), public.my_demo(), public.in_my_realm(boolean) from public, anon;
grant execute on function public.blocked_with(uuid), public.my_demo(), public.in_my_realm(boolean) to authenticated;

-- ---------------------------------------------------------------------
-- 2. TABLAS
-- ---------------------------------------------------------------------

-- 2.1 Sincronización de la app (todo lo que guarda index.html: users, jobs, svc, mk, posts,
--     chats, apps, cits, reqs, notes, reps, orders, kyc, pays)
create table if not exists public.docs (
  col        text not null,
  id         text not null,
  data       jsonb,
  del        boolean not null default false,
  members    text[],
  updated_at timestamptz not null default clock_timestamp(),
  primary key (col, id)
);
create index if not exists docs_updated_idx on public.docs (updated_at);
create index if not exists docs_members_idx on public.docs using gin (members);
alter table public.docs enable row level security;

-- 2.2 Registro de actividad (inicios de sesión, cuentas nuevas, acciones de admin)
create table if not exists public.activity_log (
  id          bigint generated always as identity primary key,
  actor       uuid,
  actor_email text,
  action      text not null,
  summary     text,
  created_at  timestamptz not null default now()
);
create index if not exists activity_log_created_idx on public.activity_log (created_at desc);
alter table public.activity_log enable row level security;

-- 2.3 Hub v2
create table if not exists public.profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  full_name    text not null default '',
  kind         text not null default 'seeker' check (kind in ('seeker','company','pro')),
  province     text,
  municipality text,
  verified     boolean not null default false,
  blocked      boolean not null default false,
  resume_path  text,
  created_at   timestamptz not null default now()
);

create table if not exists public.notification_prefs (
  user_id      uuid primary key references auth.users(id) on delete cascade,
  messages     boolean not null default true,
  applications boolean not null default true,
  shortlist    boolean not null default true,
  appointments boolean not null default true,
  requests     boolean not null default true
);

create table if not exists public.jobs (
  id           uuid primary key default gen_random_uuid(),
  owner        uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  title        text not null check (char_length(title) between 3 and 120),
  body         text check (char_length(body) <= 3000),
  province     text,
  municipality text,
  status       text not null default 'pending' check (status in ('pending','active','paused','removed')),
  created_at   timestamptz not null default now()
);
create index if not exists jobs_status_idx on public.jobs (status, created_at desc);

create table if not exists public.services (
  id           uuid primary key default gen_random_uuid(),
  owner        uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  kind         text not null default 'service' check (kind in ('service','product')),
  title        text not null check (char_length(title) between 3 and 120),
  category     text not null default 'Otros',
  subcategory  text,
  province     text,
  municipality text,
  price        text,
  body         text check (char_length(body) <= 3000),
  available    boolean not null default true,
  gallery      text[] not null default '{}',
  status       text not null default 'pending' check (status in ('pending','active','paused','removed')),
  created_at   timestamptz not null default now()
);
create index if not exists services_status_idx on public.services (status, created_at desc);

create table if not exists public.products (
  id           uuid primary key default gen_random_uuid(),
  seller       uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  name         text not null check (char_length(name) between 2 and 120),
  category     text not null default 'Otros',
  price        numeric(12,2) not null check (price >= 0),
  stock        integer not null default 1 check (stock >= 0),
  description  text check (char_length(description) <= 3000),
  images       text[] not null default '{}',
  province     text,
  municipality text,
  status       text not null default 'pending' check (status in ('pending','active','paused','removed')),
  created_at   timestamptz not null default now()
);
create index if not exists products_status_idx on public.products (status, created_at desc);

create table if not exists public.applications (
  id         uuid primary key default gen_random_uuid(),
  job_id     uuid not null references public.jobs(id) on delete cascade,
  applicant  uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  status     text not null default 'applied' check (status in ('applied','shortlisted','rejected','withdrawn')),
  created_at timestamptz not null default now(),
  unique (job_id, applicant)
);

create table if not exists public.service_requests (
  id         uuid primary key default gen_random_uuid(),
  service_id uuid not null references public.services(id) on delete cascade,
  client     uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  provider   uuid references public.profiles(id) on delete cascade,
  status     text not null default 'open' check (status in ('open','accepted','done','cancelled','declined')),
  note       text check (char_length(note) <= 500),
  created_at timestamptz not null default now()
);

create table if not exists public.reviews (
  id         uuid primary key default gen_random_uuid(),
  request_id uuid not null unique references public.service_requests(id) on delete cascade,
  service_id uuid references public.services(id) on delete cascade,
  author     uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  rating     integer not null check (rating between 1 and 5),
  body       text check (char_length(body) <= 600),
  created_at timestamptz not null default now()
);

create table if not exists public.appointments (
  id             uuid primary key default gen_random_uuid(),
  organizer      uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  invitee        uuid not null references public.profiles(id) on delete cascade,
  application_id uuid references public.applications(id) on delete set null,
  starts_at      timestamptz not null,
  status         text not null default 'pending' check (status in ('pending','accepted','rejected')),
  created_at     timestamptz not null default now()
);

create table if not exists public.messages (
  id           uuid primary key default gen_random_uuid(),
  sender_id    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  body         text not null check (char_length(body) between 1 and 2000),
  read_at      timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists messages_rec_idx on public.messages (recipient_id, read_at);
create index if not exists messages_pair_idx on public.messages (sender_id, recipient_id, created_at);

create table if not exists public.notifications (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users(id) on delete cascade,
  kind       text,
  body       text not null,
  read       boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_idx on public.notifications (user_id, created_at desc);

create table if not exists public.blocks (
  blocker uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  blocked uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker, blocked),
  check (blocker <> blocked)
);

create table if not exists public.reports (
  id          uuid primary key default gen_random_uuid(),
  reporter    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  target_type text not null check (target_type in ('job','service','product','user')),
  target_id   text not null,
  reason      text not null check (char_length(reason) >= 5),
  status      text not null default 'open' check (status in ('open','resolved')),
  created_at  timestamptz not null default now()
);

create table if not exists public.verifications (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  doc_path   text not null,
  status     text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);

create table if not exists public.audit_log (
  id         bigint generated always as identity primary key,
  actor      uuid,
  action     text not null,
  target     text,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id               uuid primary key default gen_random_uuid(),
  buyer            uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  seller           uuid not null references public.profiles(id) on delete cascade,
  status           text not null default 'pending' check (status in ('pending','confirmed','preparing','shipped','delivered','cancelled','refunded')),
  total            numeric(12,2) not null default 0,
  payment_method   text not null default 'cash' check (payment_method in ('cash','transfer','card')),
  delivery_address text,
  created_at       timestamptz not null default now()
);

create table if not exists public.order_items (
  id         uuid primary key default gen_random_uuid(),
  order_id   uuid not null references public.orders(id) on delete cascade,
  product_id uuid not null references public.products(id),
  name       text,
  quantity   integer not null check (quantity >= 1),
  unit_price numeric(12,2) not null default 0
);

alter table public.profiles           enable row level security;
alter table public.notification_prefs enable row level security;
alter table public.jobs               enable row level security;
alter table public.services           enable row level security;
alter table public.products           enable row level security;
alter table public.applications       enable row level security;
alter table public.service_requests   enable row level security;
alter table public.reviews            enable row level security;
alter table public.appointments       enable row level security;
alter table public.messages           enable row level security;
alter table public.notifications      enable row level security;
alter table public.blocks             enable row level security;
alter table public.reports            enable row level security;
alter table public.verifications      enable row level security;
alter table public.audit_log          enable row level security;
alter table public.orders             enable row level security;
alter table public.order_items        enable row level security;

-- 2.4 Tablas nuevas (vienen del esquema "Job Search")
create table if not exists public.companies (
  id           uuid primary key default gen_random_uuid(),
  owner        uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  name         text not null check (char_length(btrim(name)) between 2 and 120),
  rnc          text,                                  -- RNC dominicano (opcional)
  description  text check (char_length(description) <= 2000),
  website      text,
  phone        text,
  province     text,
  municipality text,
  logo_path    text,                                  -- ruta en el bucket "gallery"
  verified     boolean not null default false,
  status       text not null default 'active' check (status in ('active','suspended')),
  is_demo      boolean not null default false,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- Publicaciones de la comunidad
create table if not exists public.posts (
  id          uuid primary key default gen_random_uuid(),
  author      uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  body        text check (char_length(body) <= 3000),
  media_paths text[] not null default '{}',           -- fotos/videos en el bucket "gallery"
  status      text not null default 'active' check (status in ('active','hidden','removed')),
  is_demo     boolean not null default false,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  check (coalesce(char_length(btrim(body)),0) > 0 or coalesce(array_length(media_paths,1),0) > 0)
);

create table if not exists public.post_comments (
  id         uuid primary key default gen_random_uuid(),
  post_id    uuid not null references public.posts(id) on delete cascade,
  author     uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  body       text not null check (char_length(btrim(body)) between 1 and 1000),
  is_demo    boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.post_likes (
  post_id    uuid not null references public.posts(id) on delete cascade,
  user_id    uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  is_demo    boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

-- Registro contable de todo dinero que se mueve.
-- Solo se crea desde el servidor (service_role / Edge Function), nunca desde el navegador.
create table if not exists public.transactions (
  id                 uuid primary key default gen_random_uuid(),
  payer              uuid not null references public.profiles(id) on delete restrict,
  payee              uuid references public.profiles(id) on delete restrict,
  order_id           uuid references public.orders(id) on delete restrict,
  service_request_id uuid references public.service_requests(id) on delete restrict,
  job_id             uuid references public.jobs(id) on delete restrict,       -- p. ej. empleo destacado
  kind               text not null check (kind in ('order','service','job_promotion','refund','fee')),
  amount             numeric(12,2) not null check (amount >= 0),
  currency           char(3) not null default 'DOP',
  method             text check (method in ('cash','transfer','card')),
  status             text not null default 'pending' check (status in ('pending','paid','failed','refunded','cancelled')),
  provider_ref       text,                            -- id del procesador de pagos
  is_demo            boolean not null default false,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now(),
  check (num_nonnulls(order_id, service_request_id, job_id) = 1)               -- apunta a EXACTAMENTE una cosa
);

-- Ajustes globales (solo admin)
create table if not exists public.app_settings (
  key        text primary key,
  value      jsonb not null,
  updated_at timestamptz not null default now()
);
insert into public.app_settings (key, value) values
  ('demo_enabled', 'true'::jsonb),
  ('backup_retention_days', '30'::jsonb)
on conflict (key) do nothing;

alter table public.companies     enable row level security;
alter table public.posts         enable row level security;
alter table public.post_comments enable row level security;
alter table public.post_likes    enable row level security;
alter table public.transactions  enable row level security;
alter table public.app_settings  enable row level security;

-- 2.5 Columnas nuevas en tablas que ya existían (todas con valor por defecto: no rompen nada)
alter table public.profiles add column if not exists headline    text check (char_length(headline) <= 160);
alter table public.profiles add column if not exists bio         text check (char_length(bio) <= 2000);
alter table public.profiles add column if not exists avatar_path text;           -- ruta en el bucket "gallery"
alter table public.profiles add column if not exists updated_at  timestamptz not null default now();

alter table public.jobs add column if not exists company_id      uuid references public.companies(id) on delete set null;
alter table public.jobs add column if not exists category        text;
alter table public.jobs add column if not exists employment_type text check (employment_type in ('full_time','part_time','hourly','temporary','contract'));
alter table public.jobs add column if not exists salary_min      numeric(12,2) check (salary_min >= 0);
alter table public.jobs add column if not exists salary_max      numeric(12,2) check (salary_max >= 0);
alter table public.jobs add column if not exists currency        char(3) not null default 'DOP';
alter table public.jobs add column if not exists remote          boolean not null default false;
alter table public.jobs add column if not exists expires_at      timestamptz default (now() + interval '60 days');
alter table public.jobs add column if not exists updated_at      timestamptz not null default now();
alter table public.jobs add column if not exists search tsvector generated always as (
  to_tsvector('spanish', coalesce(title,'') || ' ' || coalesce(body,'') || ' ' || coalesce(category,''))) stored;
alter table public.jobs drop constraint if exists jobs_status_check;
alter table public.jobs add  constraint jobs_status_check check (status in ('pending','active','paused','closed','removed'));
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'jobs_salary_range' and conrelid = 'public.jobs'::regclass) then
    alter table public.jobs add constraint jobs_salary_range
      check (salary_max is null or salary_min is null or salary_max >= salary_min);
  end if;
end $$;

alter table public.services add column if not exists updated_at timestamptz not null default now();
alter table public.services add column if not exists search tsvector generated always as (
  to_tsvector('spanish', coalesce(title,'') || ' ' || coalesce(body,'') || ' ' || coalesce(category,'') || ' ' || coalesce(subcategory,''))) stored;

alter table public.products add column if not exists currency   char(3) not null default 'DOP';
alter table public.products add column if not exists updated_at timestamptz not null default now();
alter table public.products add column if not exists search tsvector generated always as (
  to_tsvector('spanish', coalesce(name,'') || ' ' || coalesce(description,'') || ' ' || coalesce(category,''))) stored;

-- Postulaciones: nota de presentación, fecha en que la empresa la vio, y estados "viewed" / "accepted"
alter table public.applications add column if not exists cover_note text check (char_length(cover_note) <= 1000);
alter table public.applications add column if not exists viewed_at  timestamptz;
alter table public.applications add column if not exists updated_at timestamptz not null default now();
alter table public.applications drop constraint if exists applications_status_check;
alter table public.applications add  constraint applications_status_check
  check (status in ('applied','viewed','shortlisted','rejected','accepted','withdrawn'));

alter table public.service_requests add column if not exists updated_at timestamptz not null default now();

alter table public.appointments add column if not exists request_id uuid references public.service_requests(id) on delete set null;
alter table public.appointments add column if not exists location   text;
alter table public.appointments add column if not exists note       text check (char_length(note) <= 500);
alter table public.appointments add column if not exists updated_at timestamptz not null default now();
alter table public.appointments drop constraint if exists appointments_status_check;
alter table public.appointments add  constraint appointments_status_check
  check (status in ('pending','accepted','rejected','cancelled','done'));

alter table public.orders add column if not exists currency   char(3) not null default 'DOP';
alter table public.orders add column if not exists note       text check (char_length(note) <= 500);
alter table public.orders add column if not exists updated_at timestamptz not null default now();

alter table public.reports drop constraint if exists reports_target_type_check;
alter table public.reports add  constraint reports_target_type_check
  check (target_type in ('job','service','product','user','post','message'));
alter table public.reports drop constraint if exists reports_status_check;
alter table public.reports add  constraint reports_status_check check (status in ('open','resolved','dismissed'));

alter table public.verifications add column if not exists reviewed_by uuid references auth.users(id) on delete set null;
alter table public.verifications add column if not exists reviewed_at timestamptz;

alter table public.notification_prefs add column if not exists updated_at timestamptz not null default now();
alter table public.audit_log          add column if not exists detail     jsonb;

-- Marca de "datos de demostración" en todas las tablas de negocio (false = dato real)
do $$
declare t text;
begin
  foreach t in array array['profiles','jobs','applications','services','service_requests','messages',
    'appointments','products','orders','order_items','reviews','reports','verifications','notifications']
  loop
    execute format('alter table public.%I add column if not exists is_demo boolean not null default false', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 3. FUNCIONES Y TRIGGERS
-- ---------------------------------------------------------------------

-- 3.1 Avisos internos (solo los triggers pueden llamarla)
create or replace function public.notify(uid uuid, k text, msg text, pref text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if uid is null or uid = auth.uid() or public.restoring() then return; end if;
  if pref is not null and exists (
       select 1 from public.notification_prefs np
        where np.user_id = uid and not coalesce((to_jsonb(np)->>pref)::boolean, true)) then
    return;
  end if;
  insert into public.notifications(user_id, kind, body, is_demo)
    values (uid, k, msg, coalesce((select p.is_demo from public.profiles p where p.id = uid), false));
end $$;
revoke all on function public.notify(uuid,text,text,text) from public, anon, authenticated;

create or replace function public.pname(uid uuid) returns text
language sql stable security definer set search_path = public as $$
  select coalesce(nullif(full_name,''), 'Alguien') from public.profiles where id = uid
$$;

create or replace function public.not_blocked() returns boolean
language sql stable security definer set search_path = public as $$
  select not coalesce((select blocked from public.profiles where id = auth.uid()), false)
$$;

-- 3.2 Alta de usuario nuevo: perfil + preferencias + registro de actividad
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public, auth as $$
declare nm text;
begin
  nm := coalesce(nullif(new.raw_user_meta_data->>'full_name',''),
                 nullif(trim(coalesce(new.raw_user_meta_data->>'nm','') || ' ' || coalesce(new.raw_user_meta_data->>'ap','')),''), '');
  insert into public.profiles(id, full_name) values (new.id, nm) on conflict do nothing;
  insert into public.notification_prefs(user_id) values (new.id) on conflict do nothing;
  insert into public.activity_log(actor, actor_email, action, summary)
    values (new.id, lower(new.email), 'signup', 'Creó su cuenta');
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create or replace function public.log_login() returns trigger
language plpgsql security definer set search_path = public, auth as $$
begin
  insert into public.activity_log(actor, actor_email, action, summary)
    values (new.id, lower(new.email), 'login', 'Inició sesión');
  return new;
end $$;
drop trigger if exists on_auth_user_login on auth.users;
create trigger on_auth_user_login after update of last_sign_in_at on auth.users
  for each row when (new.last_sign_in_at is distinct from old.last_sign_in_at)
  execute function public.log_login();

-- 3.3 docs: sello de tiempo + guardas (nadie puede darse verificación, quitarse un baneo,
--     cambiar de dueño una publicación ni aprobar su propia identidad)
create or replace function public.docs_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  adm  boolean := auth.uid() is null or public.is_admin();
  me   text    := public.jwt_email();
  okey text;
  prot text[]  := array['vf','blk','plan','adm','vfAt','blkAt'];
begin
  new.updated_at := clock_timestamp();
  if new.data is null or adm then return new; end if;

  if new.col = 'users' then
    if tg_op = 'INSERT' then
      new.data := new.data - prot;
    elsif new.id = me then
      new.data := (new.data - prot) ||
        coalesce((select jsonb_object_agg(k, old.data->k) from unnest(prot) k where old.data ? k), '{}'::jsonb);
    else  -- otra persona solo puede añadir una calificación de empresa (crt)
      new.data := old.data || case when new.data ? 'crt' then jsonb_build_object('crt', new.data->'crt') else '{}'::jsonb end;
    end if;

  elsif new.col in ('jobs','mk','svc','posts') then
    okey := case when new.col in ('jobs','mk') then 'o' else 'u' end;
    if tg_op = 'UPDATE' then
      if old.data ? okey then new.data := jsonb_set(new.data, array[okey], old.data->okey); end if;
      new.data := (new.data - 'hid') || case when old.data ? 'hid' then jsonb_build_object('hid', old.data->'hid') else '{}'::jsonb end;
    else
      new.data := new.data - 'hid';
    end if;

  elsif new.col = 'kyc' then
    new.data := jsonb_set(new.data, '{st}',
      case when tg_op = 'UPDATE' and old.data->>'st' = 'ok' then '"ok"'::jsonb else '"pend"'::jsonb end);

  elsif new.col = 'pays' then
    new.data := jsonb_set(new.data, '{st}',
      case when tg_op = 'UPDATE' then coalesce(old.data->'st','"Pendiente"'::jsonb) else '"Pendiente"'::jsonb end);
  end if;
  return new;
end $$;
drop trigger if exists docs_guard_t on public.docs;
create trigger docs_guard_t before insert or update on public.docs
  for each row execute function public.docs_guard();

-- 3.4 profiles: nadie se verifica ni se desbloquea solo
create or replace function public.profiles_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or public.is_staff() then return new; end if;
  if tg_op = 'INSERT' then
    new.verified := false; new.blocked := false;
  else
    new.verified := old.verified; new.blocked := old.blocked;
  end if;
  return new;
end $$;
drop trigger if exists profiles_guard_t on public.profiles;
create trigger profiles_guard_t before insert or update on public.profiles
  for each row execute function public.profiles_guard();

-- 3.5 Publicaciones (empleos, servicios, productos): estado inicial y cambios permitidos
--     Los verificados publican directo; el resto queda "pending" hasta que el staff apruebe.
create or replace function public.listing_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare own uuid; staff boolean := auth.uid() is null or public.is_staff();
begin
  if public.restoring() then return new; end if;
  own := coalesce(to_jsonb(new)->>'owner', to_jsonb(new)->>'seller')::uuid;   -- products usa "seller"; el resto "owner"
  if tg_op = 'INSERT' then
    if not staff then
      new.status := case when coalesce((select verified from public.profiles where id = own), false) then 'active' else 'pending' end;
    end if;
  elsif not staff and new.status is distinct from old.status then
    -- el dueño solo pausa/reactiva; los empleos además se pueden cerrar. No puede saltarse la aprobación.
    if not ((old.status in ('active','paused') and new.status in ('active','paused'))
         or (tg_table_name = 'jobs' and old.status in ('pending','active','paused') and new.status = 'closed')) then
      new.status := old.status;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists jobs_guard_t on public.jobs;
create trigger jobs_guard_t before insert or update on public.jobs
  for each row execute function public.listing_guard();
drop trigger if exists services_guard_t on public.services;
create trigger services_guard_t before insert or update on public.services
  for each row execute function public.listing_guard();
drop trigger if exists products_guard_t on public.products;
create trigger products_guard_t before insert or update on public.products
  for each row execute function public.listing_guard();

-- 3.6 Postulaciones
create or replace function public.applications_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare jo uuid; jt text; staff boolean := auth.uid() is null or public.is_staff();
begin
  if public.restoring() then return new; end if;
  if tg_op = 'UPDATE' and not staff then
    new.job_id := old.job_id; new.applicant := old.applicant;   -- nadie cambia a qué empleo ni quién postuló
  end if;
  select owner, title into jo, jt from public.jobs where id = new.job_id;
  if tg_op = 'INSERT' then
    if jo is null or not exists (select 1 from public.jobs where id = new.job_id and status = 'active') then
      raise exception 'Esta oferta ya no está disponible';
    end if;
    if jo = auth.uid() then raise exception 'No puedes postularte a tu propia oferta'; end if;
    new.status := 'applied'; new.viewed_at := null;
    perform public.notify(jo, 'application', pname(new.applicant) || ' se postuló a «' || jt || '»', 'applications');
  else
    if not staff then
      if auth.uid() = old.applicant then                      -- el candidato solo puede retirar
        new.cover_note := old.cover_note; new.viewed_at := old.viewed_at;
        if new.status not in (old.status, 'withdrawn') then raise exception 'Solo puedes retirar tu postulación'; end if;
      elsif auth.uid() = jo then                              -- el empleador solo cambia el estado
        new.cover_note := old.cover_note;
        if old.status = 'withdrawn' then raise exception 'El candidato retiró su postulación'; end if;
        if new.status not in ('applied','viewed','shortlisted','rejected','accepted') then raise exception 'Estado no permitido'; end if;
      else
        raise exception 'No autorizado';
      end if;
    end if;
    if new.status = 'viewed' and new.viewed_at is null then new.viewed_at := now(); end if;
    if new.status is distinct from old.status then
      if new.status = 'shortlisted' then
        perform public.notify(new.applicant, 'shortlist', 'Te preseleccionaron para «' || jt || '»', 'shortlist');
      elsif new.status = 'viewed' then
        perform public.notify(new.applicant, 'application', 'Una empresa vio tu postulación a «' || jt || '»', 'applications');
      elsif new.status = 'accepted' then
        perform public.notify(new.applicant, 'shortlist', 'Te aceptaron en «' || jt || '»', 'shortlist');
      end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists applications_guard_t on public.applications;
create trigger applications_guard_t before insert or update on public.applications
  for each row execute function public.applications_guard();

-- 3.7 Solicitudes de servicio
create or replace function public.requests_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare so uuid; st text; sv text; sa boolean; staff boolean := auth.uid() is null or public.is_staff();
begin
  if public.restoring() then return new; end if;
  if tg_op = 'INSERT' then
    select owner, status, title, available into so, st, sv, sa from public.services where id = new.service_id;
    if so is null or st <> 'active' or not coalesce(sa, true) then raise exception 'Este servicio no está disponible'; end if;
    if so = auth.uid() then raise exception 'No puedes solicitar tu propio servicio'; end if;
    new.provider := so;                                       -- el proveedor siempre es el dueño del servicio
    if not staff then new.client := auth.uid(); new.status := 'open'; end if;
    perform public.notify(so, 'request', pname(new.client) || ' solicitó «' || sv || '»', 'requests');
  else
    if not staff then                                         -- solo cambia el estado; lo demás queda fijo
      new.service_id := old.service_id; new.client := old.client; new.provider := old.provider; new.note := old.note;
    end if;
    if not staff and new.status is distinct from old.status then
      if auth.uid() = new.provider then
        if not ((old.status = 'open' and new.status in ('accepted','declined'))
             or (old.status = 'accepted' and new.status in ('done','cancelled'))) then
          raise exception 'Cambio de estado no permitido';
        end if;
      elsif auth.uid() = new.client then
        if not (old.status in ('open','accepted') and new.status = 'cancelled') then
          raise exception 'Solo puedes cancelar la solicitud';
        end if;
      end if;
      perform public.notify(case when auth.uid() = new.client then new.provider else new.client end,
                            'request', 'Tu solicitud ahora está: ' || new.status, 'requests');
    end if;
  end if;
  return new;
end $$;
drop trigger if exists requests_guard_t on public.service_requests;
create trigger requests_guard_t before insert or update on public.service_requests
  for each row execute function public.requests_guard();

-- 3.8 Reseñas: solo del cliente, solo de solicitudes completadas
create or replace function public.reviews_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  if public.restoring() then return new; end if;
  select * into r from public.service_requests where id = new.request_id;
  if r.id is null or r.client <> auth.uid() or r.status <> 'done' then
    raise exception 'Solo puedes reseñar un servicio que ya recibiste';
  end if;
  new.author := auth.uid(); new.service_id := r.service_id;
  return new;
end $$;
drop trigger if exists reviews_guard_t on public.reviews;
create trigger reviews_guard_t before insert on public.reviews
  for each row execute function public.reviews_guard();

-- 3.9 Citas
create or replace function public.appointments_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare staff boolean := auth.uid() is null or public.is_staff();
begin
  if public.restoring() then return new; end if;
  if tg_op = 'INSERT' then
    if not staff then new.organizer := auth.uid(); new.status := 'pending'; end if;
    if new.invitee = new.organizer then raise exception 'Cita inválida'; end if;
    if new.starts_at < now() - interval '5 minutes' then raise exception 'La cita debe ser a una hora futura'; end if;
    perform public.notify(new.invitee, 'appointment', pname(new.organizer) || ' te propuso una cita', 'appointments');
  else
    if not staff then
      new.organizer := old.organizer; new.invitee := old.invitee; new.starts_at := old.starts_at;
      new.application_id := old.application_id; new.request_id := old.request_id;
      if auth.uid() = old.invitee then                         -- la persona invitada acepta o rechaza
        new.location := old.location; new.note := old.note;
        if new.status not in (old.status, 'accepted', 'rejected') then
          raise exception 'Solo puedes aceptar o rechazar la cita';
        end if;
      elsif auth.uid() = old.organizer then                    -- quien la propuso puede cancelarla o cerrarla
        if new.status not in (old.status, 'cancelled', 'done') then
          raise exception 'Solo puedes cancelar la cita o marcarla como realizada';
        end if;
      else
        raise exception 'No autorizado';
      end if;
    end if;
    if new.status is distinct from old.status then
      if new.status in ('accepted','rejected') then
        perform public.notify(old.organizer, 'appointment',
          pname(old.invitee) || case new.status when 'accepted' then ' aceptó' else ' rechazó' end || ' tu cita', 'appointments');
      elsif new.status = 'cancelled' then
        perform public.notify(old.invitee, 'appointment', pname(old.organizer) || ' canceló la cita', 'appointments');
      end if;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists appointments_guard_t on public.appointments;
create trigger appointments_guard_t before insert or update on public.appointments
  for each row execute function public.appointments_guard();

-- 3.10 Mensajes: bloqueos, remitente real, solo se marca "leído"
create or replace function public.messages_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if public.restoring() then return new; end if;
  if tg_op = 'INSERT' then
    new.sender_id := auth.uid();
    if new.recipient_id = new.sender_id then raise exception 'No puedes escribirte a ti mismo'; end if;
    if exists (select 1 from public.blocks where blocker = new.sender_id and blocked = new.recipient_id) then
      raise exception 'Bloqueaste a este usuario. Desbloquéalo para escribirle.';
    end if;
    if exists (select 1 from public.blocks where blocker = new.recipient_id and blocked = new.sender_id) then
      raise exception 'No puedes enviar mensajes a este usuario.';
    end if;
    new.read_at := null;
  else
    new.sender_id := old.sender_id; new.recipient_id := old.recipient_id;
    new.body := old.body; new.created_at := old.created_at;
  end if;
  return new;
end $$;
drop trigger if exists messages_guard_t on public.messages;
create trigger messages_guard_t before insert or update on public.messages
  for each row execute function public.messages_guard();

create or replace function public.messages_notify() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if public.restoring() then return new; end if;
  if not exists (select 1 from public.notifications n
                  where n.user_id = new.recipient_id and not n.read and n.kind = 'message'
                    and n.body = 'Nuevo mensaje de ' || pname(new.sender_id)) then
    perform public.notify(new.recipient_id, 'message', 'Nuevo mensaje de ' || pname(new.sender_id), 'messages');
  end if;
  return new;
end $$;
drop trigger if exists messages_notify_t on public.messages;
create trigger messages_notify_t after insert on public.messages
  for each row execute function public.messages_notify();

-- 3.11 Pedidos: estados permitidos, total e inventario
create or replace function public.orders_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare staff boolean := auth.uid() is null or public.is_staff();
begin
  if public.restoring() then return new; end if;
  if tg_op = 'INSERT' then
    new.buyer := auth.uid(); new.status := 'pending'; new.total := 0;
    if new.seller = new.buyer then raise exception 'No puedes comprarte a ti mismo'; end if;
    perform public.notify(new.seller, 'order', 'Nuevo pedido de ' || pname(new.buyer), null);
    return new;
  end if;
  if not staff then new.buyer := old.buyer; new.seller := old.seller; new.currency := old.currency; end if;
  if new.total is distinct from old.total and pg_trigger_depth() = 1 then new.total := old.total; end if;
  if new.status is distinct from old.status then
    if not staff then
      if auth.uid() = old.seller then
        if not ((old.status = 'pending'   and new.status in ('confirmed','cancelled'))
             or (old.status = 'confirmed' and new.status in ('preparing','shipped','cancelled'))
             or (old.status = 'preparing' and new.status in ('shipped','cancelled'))
             or (old.status = 'shipped'   and new.status = 'delivered')) then
          raise exception 'Cambio de estado no permitido';
        end if;
      elsif auth.uid() = old.buyer then
        if not (old.status in ('pending','confirmed') and new.status = 'cancelled') then
          raise exception 'Solo puedes cancelar un pedido pendiente o confirmado';
        end if;
      end if;
    end if;
    if new.status in ('cancelled','refunded') and old.status not in ('cancelled','refunded') then
      update public.products p set stock = p.stock + oi.quantity
        from public.order_items oi where oi.order_id = old.id and oi.product_id = p.id;
    end if;
    perform public.notify(case when auth.uid() = old.seller then old.buyer else old.seller end,
                          'order', 'Tu pedido ahora está: ' || new.status, null);
  end if;
  return new;
end $$;
drop trigger if exists orders_guard_t on public.orders;
create trigger orders_guard_t before insert or update on public.orders
  for each row execute function public.orders_guard();

create or replace function public.order_items_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare o record; p record;
begin
  if public.restoring() then return new; end if;
  select * into o from public.orders where id = new.order_id;
  if o.id is null or o.buyer <> auth.uid() or o.status <> 'pending' then
    raise exception 'Pedido inválido';
  end if;
  select * into p from public.products where id = new.product_id for update;
  if p.id is null or p.status <> 'active' or p.seller <> o.seller then
    raise exception 'Producto no disponible';
  end if;
  if new.quantity > p.stock then raise exception 'Inventario insuficiente (quedan %)', p.stock; end if;
  new.name := p.name; new.unit_price := p.price;
  update public.products set stock = stock - new.quantity where id = p.id;
  update public.orders set total = total + p.price * new.quantity where id = o.id;
  return new;
end $$;
drop trigger if exists order_items_guard_t on public.order_items;
create trigger order_items_guard_t before insert on public.order_items
  for each row execute function public.order_items_guard();

-- 3.12 Separación demo / real: nadie crea ni mueve datos entre los dos "mundos".
--      Un usuario normal siempre escribe en SU mundo (auth.uid() es null en el SQL Editor / service_role).
create or replace function public.realm_guard() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if public.restoring() then return new; end if;
  if auth.uid() is not null and not public.is_staff() then
    if tg_op = 'INSERT' then new.is_demo := public.my_demo(); else new.is_demo := old.is_demo; end if;
  end if;
  return new;
end $$;

-- 3.13 Empresas: nadie se verifica ni se reactiva solo, ni cambia de dueño
create or replace function public.companies_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if public.restoring() or auth.uid() is null or public.is_staff() then return new; end if;
  if tg_op = 'INSERT' then
    new.verified := false; new.status := 'active';
  else
    new.verified := old.verified; new.status := old.status; new.owner := old.owner;
  end if;
  return new;
end $$;
drop trigger if exists companies_guard_t on public.companies;
create trigger companies_guard_t before insert or update on public.companies
  for each row execute function public.companies_guard();

-- 3.14 Conectar updated_at automático y la guardia demo/real
do $$
declare t text;
begin
  foreach t in array array['profiles','companies','jobs','applications','services','service_requests',
    'appointments','products','orders','posts','transactions','notification_prefs','app_settings']
  loop
    execute format('drop trigger if exists trg_touch on public.%I', t);
    execute format('create trigger trg_touch before update on public.%I for each row execute function public.touch_updated_at()', t);
  end loop;

  foreach t in array array['profiles','companies','jobs','applications','services','service_requests','messages',
    'appointments','products','orders','order_items','posts','post_comments','post_likes','transactions',
    'reviews','reports','verifications','notifications']
  loop
    execute format('drop trigger if exists trg_realm on public.%I', t);
    execute format('create trigger trg_realm before insert or update on public.%I for each row execute function public.realm_guard()', t);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 4. VISTAS
-- ---------------------------------------------------------------------
create or replace view public.job_cards with (security_invoker = true) as
select j.id, j.title, j.body, j.owner, p.full_name as owner_name, p.verified as owner_verified,
       j.province, j.municipality, j.status, j.created_at,
       j.company_id, c.name as company_name, j.category, j.employment_type,
       j.salary_min, j.salary_max, j.currency, j.remote, j.expires_at, j.is_demo
  from public.jobs j
  join public.profiles p on p.id = j.owner
  left join public.companies c on c.id = j.company_id;

create or replace view public.service_cards with (security_invoker = true) as
select s.id, s.kind, s.title, s.body, s.category, s.subcategory, s.owner,
       p.full_name as owner_name, p.verified as owner_verified,
       s.province, s.municipality, s.price, s.available, s.gallery, s.status, s.created_at,
       coalesce((select round(avg(r.rating)::numeric, 1) from public.reviews r where r.service_id = s.id), 0) as rating,
       (select count(*) from public.reviews r where r.service_id = s.id)::int as reviews,
       s.is_demo
  from public.services s join public.profiles p on p.id = s.owner;

-- ---------------------------------------------------------------------
-- 5. RPC
-- ---------------------------------------------------------------------

-- Estado propio (bloqueo / verificación) — la app lo consulta cada pocos segundos
create or replace function public.my_status() returns jsonb
language plpgsql stable security definer set search_path = public, auth as $$
declare e text := public.jwt_email(); d jsonb; b boolean;
begin
  select data into d from public.docs where col = 'users' and id = e and not del;
  select u.banned_until is not null and u.banned_until > now() into b from auth.users u where u.id = auth.uid();
  return jsonb_build_object(
    'blk', coalesce((d->>'blk')::boolean, false) or coalesce(b, false)
           or coalesce((select blocked from public.profiles where id = auth.uid()), false),
    'vf',  coalesce((d->>'vf')::boolean, false)
           or coalesce((select verified from public.profiles where id = auth.uid()), false));
end $$;

-- Resumen del panel (Hub)
create or replace function public.my_summary() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'cands', (select count(*) from public.applications a join public.jobs j on j.id = a.job_id
               where j.owner = auth.uid() and a.status in ('applied','viewed')),
    'posts', (select count(*) from public.jobs where owner = auth.uid() and status = 'active')
           + (select count(*) from public.services where owner = auth.uid() and status = 'active')
           + (select count(*) from public.products where seller = auth.uid() and status = 'active'),
    'dates', (select count(*) from public.appointments where invitee = auth.uid() and status = 'pending'),
    'reqs_in',  (select count(*) from public.service_requests where provider = auth.uid() and status = 'open'),
    'apps',     (select count(*) from public.applications where applicant = auth.uid()),
    'reqs_out', (select count(*) from public.service_requests where client = auth.uid()))
$$;

-- Panel de administración: estadísticas
create or replace function public.adm_stats() returns jsonb
language plpgsql stable security definer set search_path = public, auth as $$
declare r jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
  select jsonb_build_object(
    'users',       (select count(*) from auth.users),
    'users_7d',    (select count(*) from auth.users where created_at > now() - interval '7 days'),
    'active_24h',  (select count(*) from auth.users where last_sign_in_at > now() - interval '24 hours'),
    'verified',    (select count(*) from public.docs where col = 'users' and not del and data->>'vf' = 'true'),
    'blocked',     (select count(*) from auth.users u
                     left join public.docs d on d.col = 'users' and d.id = lower(u.email) and not d.del
                    where (u.banned_until is not null and u.banned_until > now()) or d.data->>'blk' = 'true'),
    'kyc_pending', (select count(*) from public.docs where col = 'kyc' and not del and data->>'st' = 'pend'),
    'reports_open',(select count(*) from public.docs where col = 'reps' and not del and data->>'st' = 'Abierto')
                 + (select count(*) from public.reports where status = 'open'),
    'pays_pending',(select count(*) from public.docs where col = 'pays' and not del and data->>'st' = 'Pendiente'),
    'series', (select coalesce(jsonb_agg(jsonb_build_object('d', to_char(g.d,'YYYY-MM-DD'),
                 'login', (select count(*) from public.activity_log a where a.action = 'login'  and a.created_at::date = g.d),
                 'reg',   (select count(*) from public.activity_log a where a.action = 'signup' and a.created_at::date = g.d))
                 order by g.d), '[]'::jsonb)
               from (select generate_series(current_date - 13, current_date, interval '1 day')::date d) g)
  ) into r;
  return r;
end $$;

-- Panel de administración: lista de usuarios
create or replace function public.adm_users(p_q text default null, p_flt text default 'all',
                                            p_lim int default 25, p_off int default 0)
returns jsonb language plpgsql stable security definer set search_path = public, auth as $$
declare q text := nullif(regexp_replace(coalesce(p_q,''), '[%_\\]', '', 'g'), ''); r jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
  with b as (
    select lower(u.email) email, u.created_at, u.last_sign_in_at,
           (u.banned_until is not null and u.banned_until > now()) banned,
           (coalesce(u.raw_app_meta_data->>'role','') = 'admin'
             or exists (select 1 from public.user_roles x where x.user_id = u.id and x.role = 'admin')) adm,
           d.data dd
      from auth.users u
      left join public.docs d on d.col = 'users' and d.id = lower(u.email) and not d.del
  ), f as (
    select email, created_at, last_sign_in_at, banned, adm,
           coalesce((dd->>'vf')::boolean, false)  vf,
           coalesce((dd->>'blk')::boolean, false) blk,
           coalesce(nullif(trim(coalesce(dd#>>'{profile,nm}','') || ' ' || coalesce(dd#>>'{profile,ap}','')), ''),
                    dd#>>'{profile,cn}', '') name,
           coalesce(dd->>'role','se') role,
           coalesce(dd#>>'{plan,id}','free') plan
      from b
  ), g as (
    select * from f
     where (q is null or email ilike '%'||q||'%' or name ilike '%'||q||'%')
       and case coalesce(p_flt,'all')
             when 'ver' then vf
             when 'nov' then not vf
             when 'ban' then (blk or banned)
             when 'new' then created_at > now() - interval '7 days'
             else true end
  )
  select jsonb_build_object(
           'total', (select count(*) from g),
           'rows', coalesce((select jsonb_agg(to_jsonb(x)) from (
                      select * from g order by coalesce(last_sign_in_at, created_at) desc
                      limit greatest(p_lim,1) offset greatest(p_off,0)) x), '[]'::jsonb))
    into r;
  return r;
end $$;

-- Verificar / banear (el baneo bloquea el inicio de sesión de verdad)
create or replace function public.adm_user_set(p_email text, p_patch jsonb, p_reason text default null)
returns jsonb language plpgsql security definer set search_path = public, auth as $$
declare e text := lower(trim(p_email)); uid uuid; patch jsonb := '{}'::jsonb;
begin
  if not public.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
  select id into uid from auth.users where lower(email) = e;
  if uid is null then raise exception 'Usuario no encontrado'; end if;
  if p_patch ? 'vf'  then patch := patch || jsonb_build_object('vf',  (p_patch->>'vf')::boolean);  end if;
  if p_patch ? 'blk' then patch := patch || jsonb_build_object('blk', (p_patch->>'blk')::boolean); end if;
  if (patch->>'blk')::boolean is true and (
       exists (select 1 from public.user_roles where user_id = uid and role = 'admin')
       or exists (select 1 from auth.users where id = uid and raw_app_meta_data->>'role' = 'admin')) then
    raise exception 'No se puede banear a un administrador';
  end if;

  insert into public.docs(col, id, data, members) values ('users', e, patch, null)
  on conflict (col, id) do update set data = coalesce(public.docs.data,'{}'::jsonb) || excluded.data, del = false;

  if patch ? 'blk' then
    update auth.users set banned_until = case when (patch->>'blk')::boolean then 'infinity'::timestamptz else null end where id = uid;
    update public.profiles set blocked = (patch->>'blk')::boolean where id = uid;
  end if;
  if patch ? 'vf' then
    update public.profiles set verified = (patch->>'vf')::boolean where id = uid;
  end if;

  insert into public.activity_log(actor, actor_email, action, summary)
  values (auth.uid(), public.jwt_email(),
          case when patch ? 'blk' then (case when (patch->>'blk')::boolean then 'user_ban' else 'user_unban' end) else 'user_verify' end,
          e || coalesce(' · ' || nullif(p_reason,''), ''));
  return jsonb_build_object('ok', true);
end $$;

-- Acciones de moderación del Hub (todas quedan en audit_log)
create or replace function public.admin_action(act text, target text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid; v record;
begin
  if not public.is_staff() then raise exception 'forbidden' using errcode = '42501'; end if;
  case act
    when 'approve_job'     then update public.jobs     set status = 'active'  where id = target::uuid;
    when 'approve_service' then update public.services set status = 'active'  where id = target::uuid;
    when 'approve_product' then update public.products set status = 'active'  where id = target::uuid;
    when 'remove_job'      then update public.jobs     set status = 'removed' where id = target::uuid;
    when 'remove_service'  then update public.services set status = 'removed' where id = target::uuid;
    when 'remove_product'  then update public.products set status = 'removed' where id = target::uuid;
    when 'resolve_report'  then update public.reports  set status = 'resolved' where id = target::uuid;
    when 'dismiss_report'  then update public.reports  set status = 'dismissed' where id = target::uuid;
    when 'verify'          then update public.profiles set verified = true  where id = target::uuid;
    when 'unverify'        then update public.profiles set verified = false where id = target::uuid;
    when 'ban' then
      if not public.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
      uid := target::uuid;
      if exists (select 1 from public.user_roles where user_id = uid and role = 'admin') then
        raise exception 'No se puede banear a un administrador'; end if;
      update public.profiles set blocked = true where id = uid;
      update auth.users set banned_until = 'infinity' where id = uid;
    when 'unban' then
      if not public.is_admin() then raise exception 'forbidden' using errcode = '42501'; end if;
      uid := target::uuid;
      update public.profiles set blocked = false where id = uid;
      update auth.users set banned_until = null where id = uid;
    when 'approve_verification' then
      select * into v from public.verifications where id = target::uuid;
      update public.verifications set status = 'approved', reviewed_by = auth.uid(), reviewed_at = now() where id = v.id;
      update public.profiles set verified = true where id = v.user_id;
      perform public.notify(v.user_id, 'shortlist', '✔ Tu cuenta fue verificada en BEC', null);
    when 'reject_verification' then
      select * into v from public.verifications where id = target::uuid;
      update public.verifications set status = 'rejected', reviewed_by = auth.uid(), reviewed_at = now() where id = v.id;
      perform public.notify(v.user_id, 'shortlist', 'Tu verificación fue rechazada. Puedes volver a intentarlo.', null);
    else raise exception 'Acción desconocida: %', act;
  end case;
  insert into public.audit_log(actor, action, target) values (auth.uid(), act, target);
end $$;

revoke all on function public.adm_stats(), public.adm_users(text,text,int,int),
  public.adm_user_set(text,jsonb,text), public.admin_action(text,text) from public, anon;
grant execute on function public.my_status(), public.my_summary(), public.adm_stats(),
  public.adm_users(text,text,int,int), public.adm_user_set(text,jsonb,text),
  public.admin_action(text,text), public.is_staff(), public.is_admin() to authenticated;

-- ---------------------------------------------------------------------
-- 6. POLÍTICAS RLS
-- ---------------------------------------------------------------------
create or replace function public._p(t text, n text, c text, u text default null, w text default null)
returns void language plpgsql as $$
begin
  execute format('drop policy if exists %I on %s', n, t);
  execute format('create policy %I on %s for %s to authenticated %s %s', n, t, c,
                 case when u is null then '' else 'using (' || u || ')' end,
                 case when w is null then '' else 'with check (' || w || ')' end);
end $$;

-- docs
select public._p('public.docs','docs_sel','select',
  $$ col in ('users','jobs','svc','mk','posts') or public.is_admin() or members @> array[public.jwt_email()] $$);
select public._p('public.docs','docs_ins','insert', null,
  $$ public.is_admin()
     or (col = 'users' and id = public.jwt_email())
     or (col in ('jobs','mk') and lower(data->>'o') = public.jwt_email())
     or (col in ('svc','posts') and lower(data->>'u') = public.jwt_email())
     or (col not in ('users','jobs','svc','mk','posts') and members @> array[public.jwt_email()]) $$);
select public._p('public.docs','docs_upd','update',
  $$ col in ('users','jobs','svc','mk','posts') or public.is_admin() or members @> array[public.jwt_email()] $$,
  $$ col in ('users','jobs','svc','mk','posts') or public.is_admin() or members @> array[public.jwt_email()] $$);
select public._p('public.docs','docs_del','delete', $$ public.is_admin() $$);

-- activity_log (solo lectura para admin; las filas las crean los triggers)
select public._p('public.activity_log','act_sel','select', $$ public.is_admin() $$);

-- profiles
select public._p('public.profiles','pr_sel','select', $$ true $$);
select public._p('public.profiles','pr_ins','insert', null, $$ id = auth.uid() $$);
select public._p('public.profiles','pr_upd','update', $$ id = auth.uid() or public.is_staff() $$, $$ id = auth.uid() or public.is_staff() $$);

select public._p('public.notification_prefs','np_sel','select', $$ user_id = auth.uid() $$);
select public._p('public.notification_prefs','np_ins','insert', null, $$ user_id = auth.uid() $$);
select public._p('public.notification_prefs','np_upd','update', $$ user_id = auth.uid() $$, $$ user_id = auth.uid() $$);

-- jobs / services / products
select public._p('public.jobs','jobs_sel','select',
  $$ (status = 'active' and not public.blocked_with(owner)) or owner = auth.uid() or public.is_staff() $$);
select public._p('public.jobs','jobs_ins','insert', null,
  $$ owner = auth.uid() and public.not_blocked()
     and (company_id is null or exists (select 1 from public.companies c where c.id = company_id and c.owner = auth.uid())) $$);
select public._p('public.jobs','jobs_upd','update', $$ owner = auth.uid() or public.is_staff() $$, $$ owner = auth.uid() or public.is_staff() $$);
select public._p('public.jobs','jobs_del','delete', $$ owner = auth.uid() or public.is_staff() $$);

select public._p('public.services','sv_sel','select',
  $$ (status = 'active' and not public.blocked_with(owner)) or owner = auth.uid() or public.is_staff() $$);
select public._p('public.services','sv_ins','insert', null, $$ owner = auth.uid() and public.not_blocked() $$);
select public._p('public.services','sv_upd','update', $$ owner = auth.uid() or public.is_staff() $$, $$ owner = auth.uid() or public.is_staff() $$);
select public._p('public.services','sv_del','delete', $$ owner = auth.uid() or public.is_staff() $$);

select public._p('public.products','pd_sel','select', $$ status = 'active' or seller = auth.uid() or public.is_staff() $$);
select public._p('public.products','pd_ins','insert', null, $$ seller = auth.uid() and public.not_blocked() $$);
select public._p('public.products','pd_upd','update', $$ seller = auth.uid() or public.is_staff() $$, $$ seller = auth.uid() or public.is_staff() $$);
select public._p('public.products','pd_del','delete', $$ seller = auth.uid() or public.is_staff() $$);

-- applications
select public._p('public.applications','ap_sel','select',
  $$ applicant = auth.uid() or public.is_staff()
     or exists (select 1 from public.jobs j where j.id = job_id and j.owner = auth.uid()) $$);
select public._p('public.applications','ap_ins','insert', null, $$ applicant = auth.uid() and public.not_blocked() $$);
select public._p('public.applications','ap_upd','update',
  $$ applicant = auth.uid() or public.is_staff()
     or exists (select 1 from public.jobs j where j.id = job_id and j.owner = auth.uid()) $$,
  $$ applicant = auth.uid() or public.is_staff()
     or exists (select 1 from public.jobs j where j.id = job_id and j.owner = auth.uid()) $$);

-- service_requests / reviews / appointments
select public._p('public.service_requests','rq_sel','select', $$ client = auth.uid() or provider = auth.uid() or public.is_staff() $$);
select public._p('public.service_requests','rq_ins','insert', null, $$ client = auth.uid() and public.not_blocked() $$);
select public._p('public.service_requests','rq_upd','update',
  $$ client = auth.uid() or provider = auth.uid() or public.is_staff() $$,
  $$ client = auth.uid() or provider = auth.uid() or public.is_staff() $$);

select public._p('public.reviews','rv_sel','select', $$ true $$);
select public._p('public.reviews','rv_ins','insert', null, $$ author = auth.uid() $$);

select public._p('public.appointments','ci_sel','select', $$ organizer = auth.uid() or invitee = auth.uid() or public.is_staff() $$);
select public._p('public.appointments','ci_ins','insert', null, $$ organizer = auth.uid() $$);
select public._p('public.appointments','ci_upd','update',
  $$ invitee = auth.uid() or organizer = auth.uid() or public.is_staff() $$,
  $$ invitee = auth.uid() or organizer = auth.uid() or public.is_staff() $$);

-- messages / notifications / blocks
select public._p('public.messages','ms_sel','select', $$ sender_id = auth.uid() or recipient_id = auth.uid() $$);
select public._p('public.messages','ms_ins','insert', null, $$ sender_id = auth.uid() and public.not_blocked() $$);
select public._p('public.messages','ms_upd','update', $$ recipient_id = auth.uid() $$, $$ recipient_id = auth.uid() $$);

select public._p('public.notifications','nt_sel','select', $$ user_id = auth.uid() $$);
select public._p('public.notifications','nt_upd','update', $$ user_id = auth.uid() $$, $$ user_id = auth.uid() $$);
select public._p('public.notifications','nt_del','delete', $$ user_id = auth.uid() $$);

select public._p('public.blocks','bl_sel','select', $$ blocker = auth.uid() $$);
select public._p('public.blocks','bl_ins','insert', null, $$ blocker = auth.uid() $$);
select public._p('public.blocks','bl_del','delete', $$ blocker = auth.uid() $$);

-- reports / verifications / audit
select public._p('public.reports','rp_sel','select', $$ reporter = auth.uid() or public.is_staff() $$);
select public._p('public.reports','rp_ins','insert', null, $$ reporter = auth.uid() $$);
select public._p('public.reports','rp_upd','update', $$ public.is_staff() $$, $$ public.is_staff() $$);

select public._p('public.verifications','vf_sel','select', $$ user_id = auth.uid() or public.is_staff() $$);
select public._p('public.verifications','vf_ins','insert', null, $$ user_id = auth.uid() $$);

select public._p('public.audit_log','au_sel','select', $$ public.is_staff() $$);

-- orders / order_items
select public._p('public.orders','or_sel','select', $$ buyer = auth.uid() or seller = auth.uid() or public.is_staff() $$);
select public._p('public.orders','or_ins','insert', null, $$ buyer = auth.uid() and public.not_blocked() $$);
select public._p('public.orders','or_upd','update',
  $$ buyer = auth.uid() or seller = auth.uid() or public.is_staff() $$,
  $$ buyer = auth.uid() or seller = auth.uid() or public.is_staff() $$);

select public._p('public.order_items','oi_sel','select',
  $$ exists (select 1 from public.orders o where o.id = order_id and (o.buyer = auth.uid() or o.seller = auth.uid())) or public.is_staff() $$);
select public._p('public.order_items','oi_ins','insert', null,
  $$ exists (select 1 from public.orders o where o.id = order_id and o.buyer = auth.uid()) $$);

-- ---- Políticas de las tablas nuevas y borrados propios ----
select public._p('public.companies','co_sel','select', $$ status = 'active' or owner = auth.uid() or public.is_staff() $$);
select public._p('public.companies','co_ins','insert', null, $$ owner = auth.uid() and public.not_blocked() $$);
select public._p('public.companies','co_upd','update', $$ owner = auth.uid() or public.is_staff() $$, $$ owner = auth.uid() or public.is_staff() $$);
select public._p('public.companies','co_del','delete', $$ owner = auth.uid() or public.is_admin() $$);

select public._p('public.applications','ap_del','delete', $$ applicant = auth.uid() or public.is_admin() $$);
select public._p('public.reviews','rv_del','delete', $$ author = auth.uid() or public.is_staff() $$);

-- posts, comentarios y likes
select public._p('public.posts','po_sel','select',
  $$ (status = 'active' and not public.blocked_with(author)) or author = auth.uid() or public.is_staff() $$);
select public._p('public.posts','po_ins','insert', null, $$ author = auth.uid() and status = 'active' and public.not_blocked() $$);
select public._p('public.posts','po_upd','update', $$ author = auth.uid() or public.is_staff() $$, $$ author = auth.uid() or public.is_staff() $$);
select public._p('public.posts','po_del','delete', $$ author = auth.uid() or public.is_staff() $$);

select public._p('public.post_comments','pc_sel','select',
  $$ exists (select 1 from public.posts p where p.id = post_id and (p.status = 'active' or p.author = auth.uid() or public.is_staff())) $$);
select public._p('public.post_comments','pc_ins','insert', null,
  $$ author = auth.uid() and public.not_blocked()
     and exists (select 1 from public.posts p where p.id = post_id and p.status = 'active') $$);
select public._p('public.post_comments','pc_del','delete', $$ author = auth.uid() or public.is_staff() $$);

select public._p('public.post_likes','pl_sel','select', $$ true $$);
select public._p('public.post_likes','pl_ins','insert', null, $$ user_id = auth.uid() and public.not_blocked() $$);
select public._p('public.post_likes','pl_del','delete', $$ user_id = auth.uid() $$);

-- transacciones: solo lectura para las partes (se escriben desde el servidor); ajustes: solo admin
select public._p('public.transactions','tx_sel','select', $$ payer = auth.uid() or payee = auth.uid() or public.is_admin() $$);
select public._p('public.app_settings','as_sel','select', $$ public.is_admin() $$);

drop function public._p(text,text,text,text,text);

-- ---- Aislamiento demo / real: política RESTRICTIVA (se suma a las demás con AND) ----
do $$
declare t text;
begin
  foreach t in array array['profiles','companies','jobs','applications','services','service_requests','messages',
    'appointments','products','orders','order_items','posts','post_comments','post_likes','transactions',
    'reviews','reports','verifications','notifications']
  loop
    execute format('drop policy if exists realm on public.%I', t);
    execute format($p$create policy realm on public.%I as restrictive for all to authenticated
                      using (public.in_my_realm(is_demo)) with check (public.in_my_realm(is_demo))$p$, t);
  end loop;
end $$;

-- ---- Permisos mínimos (defensa en profundidad): anon no toca nada; authenticated solo lo necesario.
--      Las políticas RLS de arriba deciden QUÉ FILAS; esto decide QUÉ TABLAS.
revoke all on all tables in schema public from anon;
revoke all on all tables in schema public from authenticated;
grant usage on schema public to authenticated;
grant select, insert, update, delete on
  public.docs, public.profiles, public.notification_prefs, public.companies, public.jobs,
  public.services, public.products, public.applications, public.service_requests, public.reviews,
  public.appointments, public.messages, public.notifications, public.blocks, public.reports,
  public.verifications, public.orders, public.order_items, public.posts, public.post_comments,
  public.post_likes
  to authenticated;
grant select on public.activity_log, public.audit_log, public.transactions, public.app_settings to authenticated;
grant select on public.job_cards, public.service_cards to authenticated;

-- ---------------------------------------------------------------------
-- 7. ALMACENAMIENTO + REALTIME
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
  ('media',    'media',    true,  52428800, null),                         -- fotos, videos, audios, PDF de la app
  ('gallery',  'gallery',  true,  10485760,                                -- galería de servicios y productos (Hub)
     array['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm']),
  ('kyc',      'kyc',      false, 8388608,  null),                         -- cédula / documentos de empresa (privado)
  ('id-docs',  'id-docs',  false, 5242880,                                 -- documento de identidad (privado)
     array['application/pdf','image/jpeg','image/png','image/webp']),
  ('resumes',  'resumes',  false, 5242880,                                 -- currículum (privado)
     array['application/pdf','image/jpeg','image/png','image/webp',
           'application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document'])
on conflict (id) do update
  set public = excluded.public,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = coalesce(excluded.allowed_mime_types, storage.buckets.allowed_mime_types);

-- ¿Es el archivo dentro de la carpeta del usuario actual?  (la 1ª carpeta de cada ruta es su id)
create or replace function public.own_folder(p_name text) returns boolean
language sql stable set search_path = '' as $$
  select (storage.foldername(p_name))[1] = auth.uid()::text
$$;

-- ¿Puede la empresa ver este currículum? (el candidato se postuló a un empleo suyo y no se retiró)
create or replace function public.can_view_resume(p_name text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.applications a
      join public.jobs j on j.id = a.job_id
     where j.owner = auth.uid()
       and a.applicant::text = (storage.foldername(p_name))[1]
       and a.status <> 'withdrawn')
$$;
revoke all on function public.own_folder(text), public.can_view_resume(text) from public, anon;
grant execute on function public.own_folder(text), public.can_view_resume(text) to authenticated;

do $$
declare p text;
begin
  foreach p in array array['st_media_ins','st_media_sel','st_media_upd','st_media_del',
    'st_gallery_ins','st_gallery_sel','st_gallery_upd','st_gallery_del',
    'st_kyc_ins','st_kyc_sel','st_iddocs_ins','st_iddocs_sel','st_iddocs_del',
    'st_resume_ins','st_resume_sel','st_resume_upd','st_resume_del']
  loop
    execute format('drop policy if exists %I on storage.objects', p);
  end loop;
end $$;

-- media y gallery: públicos para ver; solo el dueño sube, cambia o borra dentro de su carpeta
create policy st_media_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'media' and public.own_folder(name));
create policy st_media_sel on storage.objects for select using (bucket_id = 'media');
create policy st_media_upd on storage.objects for update to authenticated
  using (bucket_id = 'media' and public.own_folder(name));
create policy st_media_del on storage.objects for delete to authenticated
  using (bucket_id = 'media' and (public.own_folder(name) or public.is_staff()));

create policy st_gallery_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'gallery' and public.own_folder(name));
create policy st_gallery_sel on storage.objects for select using (bucket_id = 'gallery');
create policy st_gallery_upd on storage.objects for update to authenticated
  using (bucket_id = 'gallery' and public.own_folder(name));
create policy st_gallery_del on storage.objects for delete to authenticated
  using (bucket_id = 'gallery' and (public.own_folder(name) or public.is_staff()));

-- kyc (privado: solo el dueño y el equipo)
create policy st_kyc_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'kyc' and public.own_folder(name));
create policy st_kyc_sel on storage.objects for select to authenticated
  using (bucket_id = 'kyc' and (public.own_folder(name) or public.is_staff()));

-- id-docs (privado y sensible: solo el dueño y el equipo)
create policy st_iddocs_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'id-docs' and public.own_folder(name));
create policy st_iddocs_sel on storage.objects for select to authenticated
  using (bucket_id = 'id-docs' and (public.own_folder(name) or public.is_staff()));
create policy st_iddocs_del on storage.objects for delete to authenticated
  using (bucket_id = 'id-docs' and (public.own_folder(name) or public.is_admin()));

-- resumes (privado: el dueño, el equipo y las empresas con una postulación suya)
create policy st_resume_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'resumes' and public.own_folder(name));
create policy st_resume_sel on storage.objects for select to authenticated
  using (bucket_id = 'resumes' and (public.own_folder(name) or public.is_staff() or public.can_view_resume(name)));
create policy st_resume_upd on storage.objects for update to authenticated
  using (bucket_id = 'resumes' and public.own_folder(name));
create policy st_resume_del on storage.objects for delete to authenticated
  using (bucket_id = 'resumes' and public.own_folder(name));

-- Realtime (chat, avisos, sincronización y registro de accesos en vivo)
do $$
declare t text;
begin
  foreach t in array array['docs','activity_log','messages','notifications'] loop
    begin
      execute format('alter publication supabase_realtime add table public.%I', t);
    exception when duplicate_object then null;
    end;
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 8. ÍNDICES DE BÚSQUEDA
-- ---------------------------------------------------------------------
create index if not exists idx_profiles_kind_prov   on public.profiles (kind, province, municipality);
create index if not exists idx_profiles_verified    on public.profiles (verified) where verified;

create index if not exists idx_companies_owner      on public.companies (owner);
create unique index if not exists uq_companies_rnc  on public.companies (rnc) where rnc is not null and not is_demo;

create index if not exists idx_jobs_owner           on public.jobs (owner, created_at desc);
create index if not exists idx_jobs_company         on public.jobs (company_id);
create index if not exists idx_jobs_place           on public.jobs (province, municipality) where status = 'active';
create index if not exists idx_jobs_category        on public.jobs (category) where status = 'active';
create index if not exists idx_jobs_search          on public.jobs using gin (search);
create index if not exists idx_jobs_demo            on public.jobs (is_demo) where is_demo;

create index if not exists idx_apps_job             on public.applications (job_id, status);
create index if not exists idx_apps_applicant       on public.applications (applicant, created_at desc);

create index if not exists idx_services_feed        on public.services (status, available, created_at desc);
create index if not exists idx_services_owner       on public.services (owner, created_at desc);
create index if not exists idx_services_place       on public.services (province, municipality) where status = 'active';
create index if not exists idx_services_category    on public.services (category, subcategory) where status = 'active';
create index if not exists idx_services_search      on public.services using gin (search);
create index if not exists idx_services_demo        on public.services (is_demo) where is_demo;

create index if not exists idx_requests_provider    on public.service_requests (provider, created_at desc);
create index if not exists idx_requests_client      on public.service_requests (client, created_at desc);
create index if not exists idx_requests_service     on public.service_requests (service_id);

create index if not exists idx_messages_inbox       on public.messages (recipient_id, created_at desc);
create index if not exists idx_messages_unread      on public.messages (recipient_id) where read_at is null;

create index if not exists idx_appt_organizer       on public.appointments (organizer, starts_at desc);
create index if not exists idx_appt_invitee         on public.appointments (invitee, starts_at desc);
create index if not exists idx_appt_application     on public.appointments (application_id);

create index if not exists idx_products_seller      on public.products (seller);
create index if not exists idx_products_category    on public.products (category) where status = 'active';
create index if not exists idx_products_search      on public.products using gin (search);

create index if not exists idx_orders_buyer         on public.orders (buyer, created_at desc);
create index if not exists idx_orders_seller        on public.orders (seller, status, created_at desc);
create index if not exists idx_order_items_order    on public.order_items (order_id);
create index if not exists idx_order_items_product  on public.order_items (product_id);

create index if not exists idx_posts_feed           on public.posts (status, created_at desc);
create index if not exists idx_posts_author         on public.posts (author, created_at desc);
create index if not exists idx_posts_demo           on public.posts (is_demo) where is_demo;
create index if not exists idx_comments_post        on public.post_comments (post_id, created_at);
create index if not exists idx_likes_user           on public.post_likes (user_id);

create index if not exists idx_tx_payer             on public.transactions (payer, created_at desc);
create index if not exists idx_tx_payee             on public.transactions (payee, created_at desc);
create index if not exists idx_tx_order             on public.transactions (order_id);
create index if not exists idx_tx_request           on public.transactions (service_request_id);
create index if not exists idx_tx_job               on public.transactions (job_id);
create index if not exists idx_tx_status            on public.transactions (status) where status = 'pending';

create index if not exists idx_reviews_service      on public.reviews (service_id);
create index if not exists idx_reviews_author       on public.reviews (author);
create index if not exists idx_reports_open         on public.reports (created_at desc) where status = 'open';
create index if not exists idx_blocks_blocked       on public.blocks (blocked);
create index if not exists idx_verif_pending        on public.verifications (created_at desc) where status = 'pending';
create index if not exists idx_verif_user           on public.verifications (user_id);
create index if not exists idx_notif_unread         on public.notifications (user_id) where not read;
create index if not exists idx_audit_created        on public.audit_log (created_at desc);

-- Búsqueda por nombre/título parcial (trigramas). Se busca el esquema donde quedó instalada pg_trgm.
do $$
declare s text;
begin
  select n.nspname into s from pg_extension e join pg_namespace n on n.oid = e.extnamespace where e.extname = 'pg_trgm';
  if s is null then raise notice 'pg_trgm no está instalada: se omiten los índices de texto parcial.'; return; end if;
  execute format('create index if not exists idx_profiles_name_trgm  on public.profiles  using gin (full_name %I.gin_trgm_ops)', s);
  execute format('create index if not exists idx_companies_name_trgm on public.companies using gin (name %I.gin_trgm_ops)', s);
  execute format('create index if not exists idx_jobs_title_trgm     on public.jobs      using gin (title %I.gin_trgm_ops)', s);
  execute format('create index if not exists idx_services_title_trgm on public.services  using gin (title %I.gin_trgm_ops)', s);
end $$;

-- ---------------------------------------------------------------------
-- 9. SISTEMA DE COPIAS DE SEGURIDAD
--    Capa 1 (automática de Supabase): Dashboard → Database → Backups.
--            Planes de pago = copias diarias; Pro/Team pueden activar PITR (recuperación al minuto).
--    Capa 2 (esta sección): copias lógicas dentro de la propia base de datos, por tabla,
--            con retención configurable. Sirve para recuperar filas borradas por error
--            sin restaurar toda la base. Incluye la tabla "docs" (todo lo que sincroniza la app).
--    Capa 3 (manual y recomendada): descarga semanal fuera de Supabase (ver comentarios al final).
--    Los archivos de Storage NO van en las copias de la base de datos: respáldalos aparte (capa 3).
-- ---------------------------------------------------------------------
create schema if not exists backup;
revoke all on schema backup from public, anon, authenticated;

create table if not exists backup.runs (
  id        bigint generated always as identity primary key,
  taken_at  timestamptz not null default now(),
  kind      text not null default 'scheduled' check (kind in ('scheduled','manual','pre_purge')),
  tables    int  not null default 0,
  row_count bigint not null default 0,
  note      text
);

-- Una sola tabla de instantáneas en JSON: simple, sin crear una copia de cada tabla
create table if not exists backup.snapshots (
  run_id     bigint not null references backup.runs(id) on delete cascade,
  table_name text   not null,
  row_count  bigint not null,
  data       jsonb  not null,
  primary key (run_id, table_name)
);
create index if not exists idx_snapshots_table on backup.snapshots (table_name, run_id desc);

-- Tomar una copia de las tablas de negocio (sin audit_log ni activity_log para no crecer sin parar)
create or replace function backup.take_snapshot(p_kind text default 'manual', p_note text default null, p_only_real boolean default false)
returns bigint language plpgsql security definer set search_path = '' as $$
declare
  v_run bigint; t text; v_rows bigint; v_total bigint := 0; v_n int := 0; v_data jsonb; v_has_demo boolean;
begin
  insert into backup.runs (kind, note) values (p_kind, p_note) returning id into v_run;

  foreach t in array array['docs','profiles','companies','jobs','applications','services','service_requests',
    'messages','appointments','products','orders','order_items','posts','post_comments','post_likes',
    'transactions','reviews','reports','blocks','verifications','notifications','notification_prefs','app_settings']
  loop
    select exists (select 1 from information_schema.columns
                    where table_schema = 'public' and table_name = t and column_name = 'is_demo') into v_has_demo;
    if p_only_real and v_has_demo then
      execute format('select coalesce(jsonb_agg(to_jsonb(x)), ''[]''::jsonb), count(*) from public.%I x where not x.is_demo', t)
        into v_data, v_rows;
    else
      execute format('select coalesce(jsonb_agg(to_jsonb(x)), ''[]''::jsonb), count(*) from public.%I x', t)
        into v_data, v_rows;
    end if;
    insert into backup.snapshots (run_id, table_name, row_count, data) values (v_run, t, v_rows, v_data);
    v_total := v_total + v_rows; v_n := v_n + 1;
  end loop;

  update backup.runs set tables = v_n, row_count = v_total where id = v_run;
  return v_run;
end $$;

-- Borrar copias antiguas según app_settings.backup_retention_days
create or replace function backup.prune(p_days int default null)
returns int language plpgsql security definer set search_path = '' as $$
declare d int; n int;
begin
  d := coalesce(p_days, (select (value #>> '{}')::int from public.app_settings where key = 'backup_retention_days'), 30);
  delete from backup.runs where taken_at < now() - make_interval(days => d);
  get diagnostics n = row_count;
  return n;
end $$;

-- Restaurar UNA tabla desde una copia, sin borrar filas nuevas: solo recupera las que faltan
-- (así no se pierde lo creado después de la copia). Ejemplo:
--   select backup.restore_missing(12, 'jobs');
-- Orden recomendado si restauras varias: profiles, companies, jobs, services, products, applications, ...
create or replace function backup.restore_missing(p_run bigint, p_table text)
returns bigint language plpgsql security definer set search_path = '' as $$
declare n bigint; cols text;
begin
  if not exists (select 1 from backup.snapshots where run_id = p_run and table_name = p_table) then
    raise exception 'La copia % no contiene la tabla %', p_run, p_table;
  end if;
  select string_agg(quote_ident(column_name), ', ' order by ordinal_position) into cols
    from information_schema.columns
   where table_schema = 'public' and table_name = p_table and is_generated = 'NEVER';   -- sin columnas calculadas (search)

  perform set_config('app.restoring', 'on', true);             -- sin avisos ni reglas de negocio durante la restauración
  execute format(
    'insert into public.%1$I (%4$s) select %4$s from jsonb_populate_recordset(null::public.%1$I, (select data from backup.snapshots where run_id = %2$s and table_name = %3$L)) on conflict do nothing',
    p_table, p_run, p_table, cols);
  get diagnostics n = row_count;
  perform set_config('app.restoring', 'off', true);
  return n;
end $$;

revoke all on all functions in schema backup from public, anon, authenticated;

-- Programación automática con pg_cron (actívalo en Dashboard → Database → Extensions → pg_cron)
-- Ejecuta este bloque UNA VEZ después de activar la extensión:
--
--   select cron.schedule('backup-diario',  '0 7 * * *',  $$select backup.take_snapshot('scheduled','diaria',true)$$);   -- 03:00 hora RD (UTC-4)
--   select cron.schedule('backup-limpieza','30 7 * * 0', $$select backup.prune()$$);                                     -- domingos
--
-- Para ver las copias:         select * from backup.runs order by id desc;
-- Para restaurar una tabla:    select backup.restore_missing(<id de la copia>, 'jobs');
-- Para quitar la programación: select cron.unschedule('backup-diario');

-- ---------------------------------------------------------------------
-- 10. SEPARACIÓN ENTRE DATOS DE DEMOSTRACIÓN Y DATOS REALES
--     Cómo funciona:
--       · Toda tabla de negocio tiene is_demo (false por defecto). Toda cuenta nueva es REAL.
--       · La política RLS "realm" hace que una cuenta real solo vea datos reales,
--         y una cuenta marcada demo solo vea datos de demostración. El equipo ve ambos.
--       · El trigger realm_guard impide escribir en el mundo equivocado.
--       · Las copias diarias usan p_only_real = true: no guardan datos de demostración.
--     Para ver la demo: crea una cuenta de prueba y márcala:
--         select public.set_user_demo('<uuid de esa cuenta>', true);
--     Para lanzar la app de verdad: select public.purge_demo_data(true);
-- ---------------------------------------------------------------------

-- Marcar o desmarcar una cuenta como "de demostración" (solo admin o SQL Editor)
create or replace function public.set_user_demo(p_user uuid, p_demo boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is not null and not public.is_admin() then raise exception 'Solo el administrador'; end if;
  update public.profiles set is_demo = p_demo where id = p_user;
end $$;

-- Borrar TODA la demostración. Hace antes una copia de seguridad "pre_purge" de los datos reales.
create or replace function public.purge_demo_data(p_delete_demo_accounts boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare t text; n bigint; res jsonb := '{}'::jsonb;
begin
  if auth.uid() is not null and not public.is_admin() then raise exception 'Solo el administrador'; end if;

  perform backup.take_snapshot('pre_purge', 'antes de borrar la demostración', true);

  -- orden: primero lo que depende de otras tablas
  foreach t in array array['transactions','order_items','orders','post_likes','post_comments','posts',
    'reviews','appointments','messages','notifications','reports','verifications',
    'service_requests','applications','products','services','jobs','companies']
  loop
    execute format('delete from public.%I where is_demo', t);
    get diagnostics n = row_count;
    res := res || jsonb_build_object(t, n);
  end loop;

  if p_delete_demo_accounts then
    delete from public.activity_log where actor in (select id from public.profiles where is_demo);
    delete from auth.users where id in (select id from public.profiles where is_demo);   -- cascada a profiles
    get diagnostics n = row_count;
    res := res || jsonb_build_object('cuentas_demo', n);
  end if;
  return res;
end $$;

-- Cargar datos de demostración de ejemplo (cuentas SIN contraseña: no se pueden usar para entrar)
create or replace function public.seed_demo_data()
returns void language plpgsql security definer set search_path = '' as $$
declare
  u1 uuid := '00000000-0000-4000-8000-00000000d001';   -- empresa demo
  u2 uuid := '00000000-0000-4000-8000-00000000d002';   -- profesional demo
  u3 uuid := '00000000-0000-4000-8000-00000000d003';   -- candidato demo
  c1 uuid := '00000000-0000-4000-8000-00000000c001';
  j1 uuid := '00000000-0000-4000-8000-0000000a0001';
  s1 uuid := '00000000-0000-4000-8000-0000000b0001';
  p1 uuid := '00000000-0000-4000-8000-0000000e0001';
begin
  if auth.uid() is not null and not public.is_admin() then raise exception 'Solo el administrador'; end if;

  -- el trigger on_auth_user_created crea el perfil y las preferencias de cada cuenta
  insert into auth.users (id, instance_id, aud, role, email, raw_app_meta_data, raw_user_meta_data, created_at, updated_at)
  values
    (u1, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'demo.empresa@demo.invalid',  '{}', '{"full_name":"Ferretería Demo SRL"}', now(), now()),
    (u2, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'demo.pro@demo.invalid',      '{}', '{"full_name":"Carlos Demo (plomero)"}', now(), now()),
    (u3, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'demo.candidato@demo.invalid','{}', '{"full_name":"María Demo"}', now(), now())
  on conflict (id) do nothing;

  update public.profiles set is_demo = true, province = 'Santo Domingo', municipality = 'Santo Domingo Este',
         kind = case id when u1 then 'company' when u2 then 'pro' else 'seeker' end,
         verified = (id <> u3)
   where id in (u1, u2, u3);

  -- las cuentas demo no deben ensuciar el registro de actividad real
  delete from public.activity_log where actor in (u1, u2, u3);

  insert into public.companies (id, owner, name, description, province, verified, is_demo)
  values (c1, u1, 'Ferretería Demo SRL', 'Empresa de demostración.', 'Santo Domingo', true, true)
  on conflict (id) do nothing;

  insert into public.jobs (id, owner, company_id, title, body, category, employment_type, province, municipality, status, is_demo)
  values (j1, u1, c1, 'Vendedor de mostrador (DEMO)', 'Oferta de demostración para probar la app.', 'Ventas', 'full_time',
          'Santo Domingo', 'Santo Domingo Este', 'active', true)
  on conflict (id) do nothing;

  insert into public.services (id, owner, kind, title, category, province, municipality, price, body, status, is_demo)
  values (s1, u2, 'service', 'Plomería a domicilio (DEMO)', 'Hogar', 'Santo Domingo', 'Santo Domingo Este',
          'RD$ 600/hora', 'Servicio de demostración.', 'active', true)
  on conflict (id) do nothing;

  insert into public.products (id, seller, name, description, category, price, stock, status, is_demo)
  values (p1, u1, 'Casco de seguridad (DEMO)', 'Producto de demostración.', 'Herramientas', 450, 25, 'active', true)
  on conflict (id) do nothing;

  insert into public.posts (author, body, is_demo)
  select u2, 'Publicación de demostración: ¡hola comunidad!', true
  where not exists (select 1 from public.posts where author = u2 and is_demo);
end $$;

revoke all on function public.set_user_demo(uuid, boolean)  from public, anon;
revoke all on function public.purge_demo_data(boolean)      from public, anon;
revoke all on function public.seed_demo_data()              from public, anon;
grant execute on function public.set_user_demo(uuid, boolean), public.purge_demo_data(boolean),
                          public.seed_demo_data() to authenticated;   -- la función valida que seas admin

-- DATOS DE DEMOSTRACIÓN (opcional):  select public.seed_demo_data();
-- COPIA EXTERNA (capa 3, recomendada cada semana, desde tu computadora con Supabase CLI):
--   supabase db dump --db-url "postgresql://..." -f respaldo-$(date +%F).sql
--   (y descarga los buckets resumes, id-docs y kyc desde Dashboard → Storage)

-- ---------------------------------------------------------------------
-- 11. PROPIETARIO / ADMINISTRADOR   →   EDITA TU CORREO Y EJECUTA
--    (Después cierra sesión en la app y vuelve a entrar para que el token traiga el rol)
-- ---------------------------------------------------------------------
do $$
declare v_email text := 'TU_CORREO_AQUI@ejemplo.com';   -- <<<<<< CAMBIA ESTO
        uid uuid;
begin
  select id into uid from auth.users where lower(email) = lower(v_email);
  if uid is null then
    raise notice 'No existe un usuario con %: primero crea tu cuenta en BEC y vuelve a ejecutar este bloque.', v_email;
    return;
  end if;
  insert into public.user_roles(user_id, role) values (uid, 'admin')
    on conflict (user_id) do update set role = 'admin';
  update auth.users
     set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"admin"}'::jsonb
   where id = uid;
  raise notice 'Listo: % ahora es administrador de BEC.', v_email;
end $$;
