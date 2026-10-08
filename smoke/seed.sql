-- Seed for the smoke test and the integration suite. Synthetic data only.
-- Run as a superuser against an empty database named appdb. The agent role is
-- created here WITHOUT a password; the caller sets a throwaway password afterwards
-- (scripts/embedded-pg.mjs does this with a random value, smoke/init.sh from an env var).

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
  created_at timestamptz not null default now(),
  tenant_id int not null
);

-- Same shape as orders, but bounded by a session setting instead of the role (see README).
create table invoices (
  id serial primary key,
  tenant_id int not null,
  amount_cents int not null
);

create table secrets (id serial primary key, value text not null);

-- A second schema, used to prove that cross-schema joins are refused by the guard.
create schema internal;
create table internal.staff_notes (id serial primary key, customer_id int not null, note text not null);

insert into customers (name, email, billing_phone, created_at, deleted_at) values
  ('Aoife Byrne',    'aoife@example.test',  '+353 1 555 0101', '2026-01-05', null),
  ('Cathal Doyle',   'cathal@example.test', '+353 1 555 0102', '2026-02-11', null),
  ('Niamh Walsh',    'niamh@example.test',  '+353 1 555 0103', '2026-03-20', null),
  ('Oisin Kelly',    'oisin@example.test',  '+353 1 555 0104', '2026-04-02', null),
  ('Sinead Murphy',  'sinead@example.test', '+353 1 555 0105', '2026-05-17', null),
  ('Tadhg Ryan',     'tadhg@example.test',  '+353 1 555 0106', '2026-06-30', null),
  ('Una Hayes',      'una@example.test',    '+353 1 555 0107', '2026-07-08', null),
  ('Deleted Person', 'gone@example.test',   '+353 1 555 0199', '2026-08-01', '2026-09-01');

-- Tenant 1 is the agent's tenant. Tenant 2 rows must never be visible to the agent.
insert into orders (customer_id, total_cents, status, created_at, tenant_id) values
  (1, 1200,  'paid',     '2026-09-01', 1),
  (1, 3400,  'paid',     '2026-09-02', 1),
  (2, 990,   'open',     '2026-09-03', 1),
  (3, 15000, 'paid',     '2026-09-04', 1),
  (4, 450,   'refunded', '2026-09-05', 1),
  (5, 2200,  'open',     '2026-09-06', 1),
  (8, 7700,  'paid',     '2026-09-07', 1),
  (1, 99900, 'paid',     '2026-09-08', 2),
  (2, 88800, 'open',     '2026-09-09', 2),
  (6, 77700, 'paid',     '2026-09-10', 2);

insert into invoices (tenant_id, amount_cents) values (1, 100), (1, 200), (2, 900000);

insert into secrets (value) values ('not for agents');
insert into internal.staff_notes (customer_id, note) values (1, 'internal only');

-- Least-privilege agent role (README "Least-privilege role and RLS").
create role astraeus_agent login
  nosuperuser nocreatedb nocreaterole noinherit noreplication nobypassrls connection limit 8;
grant connect on database appdb to astraeus_agent;
grant usage on schema public to astraeus_agent;

-- PUBLIC gets TEMPORARY on every new database, and CREATE on schema public before
-- PostgreSQL 15. Take both away so the agent cannot create any object at all.
revoke temporary on database appdb from public;
revoke create on schema public from public;

-- Column-level grants: no customers.email, nothing at all on secrets.
grant select (id, name, billing_phone, created_at, deleted_at) on public.customers to astraeus_agent;
grant select (id, customer_id, total_cents, status, created_at) on public.orders to astraeus_agent;
grant select (id, amount_cents) on public.invoices to astraeus_agent;

-- The role can read internal.staff_notes, so a refused cross-schema join proves the guard, not a missing grant.
grant usage on schema internal to astraeus_agent;
grant select on internal.staff_notes to astraeus_agent;

alter role astraeus_agent set default_transaction_read_only = on;
alter role astraeus_agent set statement_timeout = '5s';

-- Row-level security bound to the role. The agent cannot change who it is, so it
-- cannot widen this boundary even with a raw connection.
alter table orders enable row level security;
alter table orders force row level security;
create policy agent_tenant_orders on orders for select to astraeus_agent using (tenant_id = 1);

-- Row-level security bound to a session setting. Weaker: anyone holding the role's
-- credentials can run SET app.tenant_id. The integration suite demonstrates this.
alter table invoices enable row level security;
alter table invoices force row level security;
create policy agent_tenant_invoices on invoices for select to astraeus_agent
  using (tenant_id = nullif(current_setting('app.tenant_id', true), '')::int);
alter role astraeus_agent set app.tenant_id = '1';
