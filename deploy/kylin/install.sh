#!/bin/bash
set -euo pipefail
umask 077
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo 'This delivery requires Linux x86_64'; exit 1; }
bundle=$(cd -- "$(dirname -- "$0")" && pwd)
base=/opt/self-guard
command -v podman >/dev/null
[ -x /opt/self-guard/bin/podman ] || { echo "Dedicated verified runtime is required"; exit 1; }
export PATH="/opt/self-guard/bin:$PATH"
command -v python3 >/dev/null
command -v flock >/dev/null
install -d -m 700 "$base" "$base/state"
exec 9>"$base/state/install.lock"
flock -n 9 || { echo 'Another installation is in progress'; exit 1; }
python3 "$bundle/scripts/prepare.py" "$bundle"
exec > >(tee -a "$base/state/install.log") 2>&1
if [ -e "$base/installed.json" ]; then
  echo 'This snapshot is already installed; use the dedicated service controls.'
  exit 0
fi
# No private values are evaluated as shell code or passed as command arguments.
image(){ python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["images"][sys.argv[2]])' "$bundle/manifest.json" "$1"; }
app_image=$(image app)
web_image=$(image web)
postgres_image=$(image postgres)
certbot_image=$(image certbot)
waf_image=$(image waf)
for expected in "$app_image" "$web_image" "$postgres_image" "$certbot_image"; do podman inspect "$expected" >/dev/null || { echo "Offline images must be imported before installation"; exit 1; }; done
podman load -i "$bundle/delivery/amd64/image.tar"
for expected in "$app_image" "$web_image" "$postgres_image" "$certbot_image" "$waf_image"; do podman inspect "$expected" >/dev/null; done
# Only the pre-existing default CNI bridge is used; no host network configuration is replaced.
python3 - <<'PY'
import json
p=json.load(open('/etc/cni/net.d/87-podman-bridge.conflist'))
assert p['name']=='podman'
assert p['plugins'][0]['ipam']['subnet']=='10.88.0.0/16', 'Review target private subnet before installation'
PY
create(){
  name=$1; shift
  if podman inspect "$name" >/dev/null 2>&1; then
    [ "$(podman inspect --format '{{ index .Config.Labels "com.selfguard.deployment" }}' "$name")" = kylin-primary-20261103 ] || { echo "Unmanaged container name exists: $name"; exit 1; }
  else
    podman create --name "$name" --label com.selfguard.deployment=kylin-primary-20261103 --log-opt max-size=10485760 "$@"
  fi
}
unit(){
  name=$1; dependencies=${2:-}
  cat > "/etc/systemd/system/$name.service" <<UNIT
[Unit]
Description=Self Guard $name
Wants=network-online.target
After=network-online.target $dependencies
Requires=$dependencies
[Service]
Type=simple
ExecStart=/opt/self-guard/bin/podman start -a $name
ExecStop=/opt/self-guard/bin/podman stop -t 30 $name
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillMode=none
[Install]
WantedBy=multi-user.target
UNIT
}
create selfguard-postgres --net bridge --ip 10.88.0.10 --user 70:70 --read-only --cap-drop ALL --security-opt no-new-privileges --memory 1g --cpus 1 --pids-limit 256 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 --tmpfs /var/run/postgresql:rw,nosuid,nodev,size=16m,uid=70,gid=70,mode=3775 \
  --env-file "$base/secrets/postgres.env" -v "$base/data/postgres:/var/lib/postgresql/data" \
  -v "$base/secrets/db-admin-password:/run/secrets/db_admin_password:ro" \
  -v "$base/secrets/db-runtime-password:/run/secrets/db_runtime_password:ro" \
  -v "$base/secrets/db-migrator-password:/run/secrets/db_migrator_password:ro" \
  -v "$base/current/scripts/01-roles.sh:/docker-entrypoint-initdb.d/01-roles.sh:ro" "$postgres_image"
unit selfguard-postgres
systemctl daemon-reload
systemctl enable --now selfguard-postgres
ready=false
for attempt in $(seq 1 90); do
  if podman exec selfguard-postgres pg_isready -h 127.0.0.1 -U selfguard_bootstrap -d selfguard >/dev/null && [ "$(podman exec selfguard-postgres psql -U selfguard_bootstrap -d selfguard -At -c "SELECT count(*) FROM pg_roles WHERE rolname IN ('selfguard_runtime','selfguard_migrator')")" = 2 ]; then ready=true; break; fi
  sleep 1
done
[ "$ready" = true ] || { echo 'Database startup failed; inspect selfguard-postgres journal'; exit 1; }
if [ ! -e "$base/state/snapshot-restored" ]; then
  # Restore only into the new, dedicated database, never overwrite an existing populated schema.
  tables=$(podman exec selfguard-postgres psql -U selfguard_bootstrap -d selfguard -At -c "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
  [ "$tables" = 0 ] || { echo 'Target database is populated; automatic restore refused'; exit 1; }
  podman exec -i selfguard-postgres sh -c 'PGPASSWORD="$(cat /run/secrets/db_migrator_password)" exec pg_restore -h 127.0.0.1 -U selfguard_migrator -d selfguard --no-owner --no-acl --exit-on-error --single-transaction' < "$bundle/snapshot/selfguard.dump"
  touch "$base/state/snapshot-restored"
fi
podman run --rm --net bridge --read-only --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 --env-file "$base/secrets/migrator.env" "$app_image" /app/bin/migrate
snapshot_sha=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["snapshotSha256"])' "$bundle/manifest.json")
if [ -f "$base/state/snapshot-verified" ]; then
  [ "$(cat "$base/state/snapshot-verified")" = "$snapshot_sha" ] || { echo 'Previously verified snapshot differs'; exit 1; }
else
  python3 "$base/current/scripts/verify-snapshot.py" "$bundle"
  printf '%s\n' "$snapshot_sha" > "$base/state/snapshot-verified"
fi
create selfguard-checker --net bridge --ip 10.88.0.13 --user 10001:10001 --read-only --cap-drop ALL --security-opt no-new-privileges --memory 1g --cpus 1 --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 --tmpfs /state:rw,nosuid,nodev,size=64m,uid=10001,gid=10001 \
  --env-file "$base/secrets/checker.env" -v "$base/secrets/waf-public.key:/run/secrets/waf-public.key:ro" "$waf_image"
unit selfguard-checker
create selfguard-app --net bridge --ip 10.88.0.11 --read-only --cap-drop ALL --security-opt no-new-privileges --memory 1536m --cpus 2 --pids-limit 512 \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,mode=1777 --env-file "$base/secrets/app.env" \
  -v "$base/data/access-evidence:/var/lib/selfguard/access-evidence" \
  -v "$base/data/intelligence:/var/lib/selfguard/intelligence" -v "$base/data/agent-artifacts:/var/lib/selfguard/agent-artifacts" \
  -v "$base/secrets/waf-runtime.pk8.b64:/run/secrets/waf-runtime.pk8.b64:ro" \
  -v "$base/current/delivery:/opt/selfguard-delivery:ro" "$app_image"
unit selfguard-app 'selfguard-postgres.service selfguard-checker.service'
create selfguard-waf --net bridge --ip 10.88.0.14 --read-only --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=32m,mode=1777 --env-file "$base/secrets/waf.env" \
  -v "$base/data/waf:/state" -v "$base/secrets/waf-public.key:/run/secrets/waf-public.key:ro" "$waf_image"
unit selfguard-waf selfguard-app.service
systemctl daemon-reload
systemctl enable --now selfguard-checker selfguard-app selfguard-waf
ready=false
for attempt in $(seq 1 90); do
  if podman exec selfguard-app /app/bin/healthcheck >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
[ "$ready" = true ] || { echo 'Application startup failed; inspect selfguard-app journal'; exit 1; }
# Public 80 serves only ACME until a real trusted certificate is installed.
cat > /etc/systemd/system/selfguard-acme-bootstrap.service <<UNIT
[Unit]
Description=Self Guard temporary ACME listener
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 $base/current/scripts/acme-http.py
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UNIT
systemctl daemon-reload
systemctl start selfguard-acme-bootstrap
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-service=http
  firewall-cmd --permanent --add-service=https
  firewall-cmd --add-service=http
  firewall-cmd --add-service=https
fi
# Refuse issuance against a clock which cannot validate current CA certificates.
chronyc tracking | grep -q 'Leap status.*Normal' || { echo 'System clock is not synchronised; complete time repair and rerun'; exit 1; }
certify(){
  folder=$1; shift
  podman run --rm --net host --cap-drop ALL --security-opt no-new-privileges --memory 256m --cpus 0.5 \
    -v "$base/$folder:/etc/letsencrypt" -v "$base/public/acme:/acme:rw" "$certbot_image" \
    certonly --non-interactive --agree-tos --register-unsafely-without-email --preferred-profile shortlived \
    --webroot --webroot-path /acme --ip-address 20.88.127.75 --cert-name selfguard-ip \
    --config-dir /etc/letsencrypt --work-dir /tmp/work --logs-dir /tmp/logs "$@"
}
if [ -f "$base/secrets/platform-ca.key" ]; then
 /bin/bash "$base/current/scripts/private-ca-renew.sh"
elif [ ! -f "$base/acme/live/selfguard-ip/fullchain.pem" ]; then
  certify acme-staging --staging
  certify acme
fi
if [ -f "$base/secrets/platform-ca.key" ]; then
 /bin/bash "$base/current/scripts/private-ca-renew.sh"
elif [ ! -e "$base/acme/current-selfguard" ]; then
 ln -s live/selfguard-ip "$base/acme/current-selfguard"
fi
certificate_ca=/etc/pki/tls/certs/ca-bundle.crt
[ ! -f "$base/secrets/platform-ca.crt" ] || certificate_ca="$base/secrets/platform-ca.crt"
openssl verify -CAfile "$certificate_ca" -untrusted "$base/acme/current-selfguard/chain.pem" -verify_ip 20.88.127.75 "$base/acme/current-selfguard/cert.pem"
# Validate configuration while port 80 is still held by the challenge listener.
podman run --rm --net none --cap-drop ALL --security-opt no-new-privileges \
  -v "$base/current/scripts/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$base/acme:/etc/letsencrypt:ro" "$web_image" nginx -t
create selfguard-web --net bridge --ip 10.88.0.12 --read-only --cap-drop ALL --security-opt no-new-privileges --memory 256m --cpus 0.5 --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 -p 80:8080 -p 443:8443 \
  -v "$base/current/scripts/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$base/acme:/etc/letsencrypt:ro" \
  -v "$base/public/acme:/acme:ro" "$web_image"
unit selfguard-web selfguard-app.service
systemctl daemon-reload
systemctl stop selfguard-acme-bootstrap
systemctl enable --now selfguard-web
install -d -m 700 "$base/backups/database" "$base/backups/private" "$base/backups/agent-artifacts"
chown 1000:1000 "$base/backups/database" "$base/secrets/pgpass"
chmod 600 "$base/secrets/pgpass"
for task in renew backup; do
  cat > "/etc/systemd/system/selfguard-$task.service" <<UNIT
[Unit]
Description=Self Guard $task
After=selfguard-web.service
[Service]
Type=oneshot
ExecStart=/bin/bash $base/current/scripts/$task.sh
TimeoutStartSec=1800
UNIT
  schedule='*-*-* 00,12:00:00'
  [ "$task" != backup ] || schedule='*-*-* 03:00:00'
  cat > "/etc/systemd/system/selfguard-$task.timer" <<UNIT
[Unit]
Description=Self Guard scheduled $task
[Timer]
OnCalendar=$schedule
Persistent=true
RandomizedDelaySec=300
[Install]
WantedBy=timers.target
UNIT
done
systemctl daemon-reload
systemctl enable --now selfguard-renew.timer selfguard-backup.timer
systemctl start selfguard-backup.service
if [ -f "$base/secrets/platform-ca.crt" ]; then
 curl --cacert "$base/secrets/platform-ca.crt" --fail --silent --show-error https://20.88.127.75/healthz
else
 curl --fail --silent --show-error https://20.88.127.75/healthz
fi
python3 - "$bundle/manifest.json" "$base/installed.json" <<'PY'
import json,sys,os
m=json.load(open(sys.argv[1]))
with os.fdopen(os.open(sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:json.dump({'snapshotSha256':m['snapshotSha256'],'release':m['release'],'url':'https://20.88.127.75','crsRuntimeQualified':False},f)
PY
echo 'Services installed. HTTPS login, Agent downloads and backup restore still require final acceptance.'
