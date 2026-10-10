#!/bin/zsh
# Starts the disposable server the e2e tests use, on 127.0.0.1:18088. It keeps
# nothing on disk and is removed when stopped (`docker stop bw-e2e`). Sign-in rate
# limits are lifted because a full Swift test run signs in a dozen times.
set -euo pipefail

docker run -d --rm --name bw-e2e -p 127.0.0.1:18088:80 -e SIGNUPS_ALLOWED=true \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  -e LOGIN_RATELIMIT_MAX_BURST=10000 -e LOGIN_RATELIMIT_SECONDS=1 vaultwarden/server:1.37.3
