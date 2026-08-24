# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
# Source repo-root `.env` into the current shell (safe for demo/dev scripts).
# Does not override variables already set in the environment.
#
# Usage (from another script):
#   # shellcheck source=load_dotenv.sh
#   source "$(dirname "${BASH_SOURCE[0]}")/load_dotenv.sh"

_aiwall_load_dotenv() {
  local root env_file line key value
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  env_file="${AIWALL_ENV_FILE:-${root}/.env}"
  if [[ ! -f "${env_file}" ]]; then
    return 0
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    [[ "${line}" == *"="* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    if [[ "${key}" == export\ * ]]; then
      key="${key#export }"
      key="${key#"${key%%[![:space:]]*}"}"
    fi
    [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ "${value}" =~ ^\".*\"$ || "${value}" =~ ^\'.*\'$ ]]; then
      value="${value:1:${#value}-2}"
    fi
    # Skip keys already present in the environment.
    if [[ -v "${key}" ]]; then
      continue
    fi
    export "${key}=${value}"
  done < "${env_file}"
}

_aiwall_load_dotenv
unset -f _aiwall_load_dotenv
