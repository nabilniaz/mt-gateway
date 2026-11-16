#!/bin/sh
# Create or update the DigitalOcean App Platform app from .do/app.yaml.
#   Prereqs: `doctl auth init`, the repo pushed to GitHub, and DigitalOcean's GitHub app
#   granted access to the repo (Apps -> Create App -> GitHub, once).
# Secrets come from .env.do (git-ignored). It is created with fresh keys on first run; keep it,
# because re-running with different keys would invalidate every issued token.
set -eu
cd "$(dirname "$0")/.."

[ -f .env.do ] || uv run gateway-init-env --path .env.do >/dev/null
spec=$(uv run --with pyyaml --with python-dotenv python - <<'PY'
import sys, yaml
from dotenv import dotenv_values
secrets = dotenv_values(".env.do")
spec = yaml.safe_load(open(".do/app.yaml"))
for service in spec["services"]:
    for env in service.get("envs", []):
        if env.get("type") == "SECRET":
            env["value"] = secrets[env["key"]]
yaml.safe_dump(spec, sys.stdout, sort_keys=False)
PY
)

app_id=$(doctl apps list --format ID,Spec.Name --no-header | awk '$2 == "mt-gateway" {print $1}')
if [ -z "$app_id" ]; then
  echo "$spec" | doctl apps create --spec - --wait --format ID,DefaultIngress,Phase
else
  echo "$spec" | doctl apps update "$app_id" --spec - --wait --format ID,DefaultIngress,Phase
fi
