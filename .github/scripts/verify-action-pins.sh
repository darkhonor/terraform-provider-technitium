#!/usr/bin/env bash
set -euo pipefail

fail=0

while IFS= read -r -d '' file; do
  line_number=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))

    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    if [[ "$line" =~ ^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*([^[:space:]#]+) ]]; then
      ref="${BASH_REMATCH[2]}"
      ref="${ref%\"}"
      ref="${ref#\"}"
      ref="${ref%\'}"
      ref="${ref#\'}"

      case "$ref" in
        ./*|docker://*) continue ;;
      esac

      if [[ ! "$ref" =~ @([0-9a-fA-F]{40})$ ]]; then
        printf '%s:%d: external action is not pinned to a full 40-character SHA: %s\n' \
          "$file" "$line_number" "$ref" >&2
        fail=1
      fi
    fi
  done < "$file"
done < <(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)

if (( fail )); then
  exit 1
fi

printf 'All external GitHub Actions uses references are pinned to full commit SHAs.\n'
