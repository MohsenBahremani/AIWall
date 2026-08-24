#!/bin/sh
set -e

# Optional plugin sideload for local development: point AIWALL_PRO_PATH at a
# mounted plugin source tree and it is installed into the container's user
# site-packages before startup. Non-editable so a read-only mount still works;
# --user so the unprivileged runtime account can write.
if [ -n "${AIWALL_PRO_PATH:-}" ]; then
    if [ -f "${AIWALL_PRO_PATH}/pyproject.toml" ]; then
        echo "aiwall: installing plugin from ${AIWALL_PRO_PATH}" >&2
        pip install --user --no-cache-dir --no-warn-script-location \
            "${AIWALL_PRO_PATH}"
    else
        echo "aiwall: AIWALL_PRO_PATH=${AIWALL_PRO_PATH} has no pyproject.toml; skipping" >&2
    fi
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${AIWALL_PORT:-8080}"
