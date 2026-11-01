#!/bin/sh
set -eu
export RUNTIME_PASSWORD="$(cat /run/secrets/db_runtime_password)"
export MIGRATOR_PASSWORD="$(cat /run/secrets/db_migrator_password)"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv runtime_password RUNTIME_PASSWORD
\getenv migrator_password MIGRATOR_PASSWORD
CREATE ROLE selfguard_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'runtime_password';
CREATE ROLE selfguard_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'migrator_password';
REVOKE ALL ON DATABASE selfguard FROM PUBLIC;
GRANT CONNECT ON DATABASE selfguard TO selfguard_runtime,selfguard_migrator;
GRANT CREATE ON DATABASE selfguard TO selfguard_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO selfguard_migrator;
GRANT USAGE ON SCHEMA public TO selfguard_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE selfguard_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO selfguard_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE selfguard_migrator IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO selfguard_runtime;
SQL
unset RUNTIME_PASSWORD MIGRATOR_PASSWORD
