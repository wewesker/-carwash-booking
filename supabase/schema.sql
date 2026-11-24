-- Запись на автомойку: таблица броней + функции для сайта и администратора.
-- Клиенты не видят чужие данные: таблица закрыта RLS, всё идёт через функции.

create extension if not exists btree_gist with schema extensions;
create extension if not exists pgcrypto with schema extensions;

create table public.bookings (
  id uuid primary key default gen_random_uuid(),
  num int generated always as identity (start with 101),
  created_at timestamptz not null default now(),
  day date not null,
  box smallint not null check (box between 1 and 4),
  start_min smallint not null check (start_min >= 540 and start_min % 30 = 0),
  end_min smallint not null check (end_min <= 1260 and end_min > start_min),
  service text not null check (length(service) between 1 and 60),
  car_class text not null check (length(car_class) between 1 and 30),
  price int not null check (price between 0 and 1000000),
  name text not null check (length(name) between 1 and 60),
  phone text not null check (length(phone) between 10 and 16),
  car text not null default '' check (length(car) <= 60),
  status text not null default 'new' check (status in ('new','arrived','done','cancelled')),
  constraint no_overlap exclude using gist (
    day with =, box with =, int4range(start_min, end_min) with &&
  ) where (status <> 'cancelled')
);
alter table public.bookings enable row level security;
revoke all on public.bookings from anon, authenticated;

create table public.admin_settings (
  id int primary key default 1 check (id = 1),
  pin_hash text not null
);
alter table public.admin_settings enable row level security;
revoke all on public.admin_settings from anon, authenticated;

-- Местное время Семея (UTC+5)
create or replace function public.local_now() returns timestamp
language sql stable set search_path = '' as $$ select (now() at time zone 'UTC') + interval '5 hours' $$;

-- Занятые интервалы на день (без личных данных)
create or replace function public.get_busy(p_day date)
returns table (box smallint, start_min smallint, end_min smallint)
language sql stable security definer set search_path = '' as $$
  select b.box, b.start_min, b.end_min from public.bookings b
  where b.day = p_day and b.status <> 'cancelled'
$$;

-- Создать бронь
create or replace function public.create_booking(
  p_day date, p_box int, p_start int, p_len int, p_service text, p_class text,
  p_price int, p_name text, p_phone text, p_car text)
returns int
language plpgsql security definer set search_path = '' as $$
declare v_num int; v_now timestamp := public.local_now(); v_digits text;
begin
  v_digits := regexp_replace(coalesce(p_phone,''), '\D', '', 'g');
  if length(v_digits) < 10 or length(v_digits) > 12 then raise exception 'bad_phone'; end if;
  if length(trim(coalesce(p_name,''))) = 0 then raise exception 'bad_name'; end if;
  if p_day < v_now::date or p_day > v_now::date + 30 then raise exception 'bad_day'; end if;
  if p_len not in (30,60,90,240) then raise exception 'bad_len'; end if;
  if p_day = v_now::date and p_start < extract(hour from v_now)*60 + extract(minute from v_now) then raise exception 'past'; end if;
  if (select count(*) from public.bookings b where b.phone = v_digits and b.day = p_day and b.status <> 'cancelled') >= 3 then
    raise exception 'too_many';
  end if;
  insert into public.bookings(day, box, start_min, end_min, service, car_class, price, name, phone, car)
  values (p_day, p_box, p_start, p_start + p_len, left(p_service,60), left(p_class,30), p_price,
          left(trim(p_name),60), v_digits, left(trim(coalesce(p_car,'')),60))
  returning num into v_num;
  return v_num;
exception when exclusion_violation then raise exception 'taken';
end $$;

create or replace function public.check_pin(p_pin text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.admin_settings s
    where s.pin_hash = extensions.crypt(p_pin, s.pin_hash))
$$;

-- Записи на день для администратора
create or replace function public.admin_list(p_pin text, p_day date)
returns setof public.bookings
language plpgsql security definer set search_path = '' as $$
begin
  if not public.check_pin(p_pin) then perform pg_sleep(1); raise exception 'bad_pin'; end if;
  return query select * from public.bookings b where b.day = p_day order by b.start_min, b.box;
end $$;

create or replace function public.admin_set_status(p_pin text, p_id uuid, p_status text)
returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.check_pin(p_pin) then perform pg_sleep(1); raise exception 'bad_pin'; end if;
  update public.bookings set status = p_status where id = p_id;
end $$;

revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.get_busy(date) to anon, authenticated;
grant execute on function public.create_booking(date,int,int,int,text,text,int,text,text,text) to anon, authenticated;
grant execute on function public.admin_list(text,date) to anon, authenticated;
grant execute on function public.admin_set_status(text,uuid,text) to anon, authenticated;
