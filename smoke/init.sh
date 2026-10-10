#!/bin/sh
# Docker path only (docker-compose.yml). Seeds the smoke database from seed.sql, which
# also creates the least-privilege agent role, then sets that role's throwaway password
# from AGENT_PG_PASSWORD. The embedded path (npm run smoke) uses the same seed.sql.
set -e

psql -v ON_ERROR_STOP=1 --username postgres --dbname appdb -f /docker-entrypoint-initdb.d/seed.sql.in
psql -v ON_ERROR_STOP=1 -v agent_pw="$AGENT_PG_PASSWORD" --username postgres --dbname appdb <<'SQL'
alter role astraeus_agent password :'agent_pw';
SQL
