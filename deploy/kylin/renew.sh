#!/bin/bash
set -euo pipefail
base=/opt/self-guard
exec 9>"$base/state/certificate-renew.lock"
flock -n 9 || exit 0
if [ -f "$base/secrets/platform-ca.key" ]; then
 /bin/bash "$base/current/scripts/private-ca-renew.sh"
 /opt/self-guard/bin/podman exec selfguard-web nginx -t
 /opt/self-guard/bin/podman exec selfguard-web nginx -s reload
 exit 0
fi
certbot_image=$(python3 -c 'import json;print(json.load(open("/opt/self-guard/current/manifest.json"))["images"]["certbot"])')
/opt/self-guard/bin/podman run --rm --net host --cap-drop ALL --security-opt no-new-privileges --memory 256m --cpus 0.5 \
  -v "$base/acme:/etc/letsencrypt" -v "$base/public/acme:/acme:rw" "$certbot_image" \
  renew --non-interactive --no-random-sleep-on-renew --config-dir /etc/letsencrypt \
  --work-dir /tmp/work --logs-dir /tmp/logs
/opt/self-guard/bin/podman exec selfguard-web nginx -t
/opt/self-guard/bin/podman exec selfguard-web nginx -s reload
