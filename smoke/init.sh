#!/bin/sh
# Seeds the smoke database and creates the least-privilege agent role.
# The role password comes from AGENT_PG_PASSWORD, set by docker-compose.yml.
set -e

psql -v ON_ERROR_STOP=1 -v agent_pw="$AGENT_PG_PASSWORD" --username postgres --dbname appdb <<'SQL'
create table customers (
  id serial primary key,
  name text not null,
  email text not null,
  billing_phone text,
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table orders (
  id serial primary key,
  customer_id int not null references customers(id),
  total_cents int not null,
  status text not null,
  created_at timestamptz not null default now()
);

create table secrets (id serial primary key, value text not null);

insert into customers (name, email, billing_phone, deleted_at) values
  ('Aoife Byrne',   'aoife@example.test',  '+353 1 555 0101', null),
  ('Cathal Doyle',  'cathal@example.test', '+353 1 555 0102', null),
  ('Niamh Walsh',   'niamh@example.test',  '+353 1 555 0103', null),
  ('Oisin Kelly',   'oisin@example.test',  '+353 1 555 0104', null),
  ('Sinead Murphy', 'sinead@example.test', '+353 1 555 0105', null),
  ('Tadhg Ryan',    'tadhg@example.test',  '+353 1 555 0106', null),
  ('Una Hayes',     'una@example.test',    '+353 1 555 0107', null),
  ('Deleted Person','gone@example.test',   '+353 1 555 0199', now());

insert into orders (customer_id, total_cents, status) values
  (1, 1200, 'paid'), (1, 3400, 'paid'), (2, 990, 'open'),
  (3, 15000, 'paid'), (4, 450, 'refunded'), (5, 2200, 'open');

insert into secrets (value) values ('not for agents');

create role astraeus_agent login password :'agent_pw'
  nosuperuser nocreatedb nocreaterole noinherit connection limit 4;
grant connect on database appdb to astraeus_agent;
grant usage on schema public to astraeus_agent;

-- Column-level grants: the role cannot read customers.email or the secrets table at all.
grant select (id, name, billing_phone, created_at, deleted_at) on public.customers to astraeus_agent;
grant select (id, customer_id, total_cents, status, created_at) on public.orders to astraeus_agent;

alter role astraeus_agent set default_transaction_read_only = on;
alter role astraeus_agent set statement_timeout = '5s';
SQL
