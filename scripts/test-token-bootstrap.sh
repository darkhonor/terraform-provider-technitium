#!/usr/bin/env bash
#
# Disable any inherited xtrace BEFORE secret handling so credentials are
# never written to a debug-trace stream. Restore later modes via the
# explicit `set -euo pipefail` below.
set +x
#
# test-token-bootstrap.sh
#
# Provision Technitium API tokens for acceptance tests without exposing
# admin credentials in any process's argv or environment (issue #35).
#
# Threat model (matches issue #35):
#   * /proc/PID/cmdline (visible to all local users via `ps -ef`).
#   * /proc/PID/environ (same-UID visible via `ps eww` or /proc reads).
#
# Strategy: the admin password is delivered to this script on its own
# stdin (fd 0), NOT via argv and NOT via env. The script reads exactly
# one line from stdin into a local shell variable, then immediately
# closes/replaces fd 0 so the heredocs feeding curl below cannot
# accidentally re-read it. The password value never appears in:
#   * any process's argv  (it is never an argument anywhere)
#   * any process's env   (it is never exported anywhere)
#   * any explicit temp file (no temp files are created by this script)
# It exists only in the script's own memory and in the body bytes sent
# over the curl stdin pipe to the Technitium API.
#
# Caller contract (typically a Makefile recipe):
#
#   printf '%s\n' "$ADMIN_PASSWORD" | ./scripts/test-token-bootstrap.sh \
#       get-token URL TOKEN_NAME [CACERT]
#
#   printf '%s\n' "$ADMIN_PASSWORD" | ./scripts/test-token-bootstrap.sh \
#       wait-ready URL [CACERT]
#
# `printf` is a shell builtin in bash and dash; it does not fork an
# external process, so the password never enters any argv on the caller
# side either.
#
# Subcommands:
#   wait-ready URL [CACERT]            -- poll login endpoint until ready
#   get-token  URL TOKEN_NAME [CACERT] -- create + emit fresh API token
#
# All credentials and tokens are written to stdout only when explicitly
# emitted by get-token. All progress messages go to stderr.

set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
Usage:
  printf '%s\n' "$PASSWORD" | test-token-bootstrap.sh wait-ready URL [CACERT]
  printf '%s\n' "$PASSWORD" | test-token-bootstrap.sh get-token  URL TOKEN_NAME [CACERT]

The admin password MUST be supplied on stdin as a single line terminated
by LF (\n). The trailing newline is required: `read -r` returns non-zero
on EOF without a delimiter, and `set -e` will abort the script. A
trailing CR (CRLF input, e.g. Windows-edited .env.test) is stripped
defensively. The password is never read from argv or env -- this is the
entire point of the script per issue #35.

Optional env (read-only, used only if set):
  DNS_ADMIN_USER       admin username (default: admin). Not sensitive.

wait-ready:
  Polls URL/api/user/login via POST form body up to 60 times (1s each).
  Exits 0 on first success, 1 on timeout. Progress on stderr.

get-token:
  Logs in to URL/api/user/login, then calls URL/api/user/createToken to
  mint a fresh API token labeled TOKEN_NAME. Prints the API token (and
  only the API token) to stdout. Diagnostics on stderr.
USAGE
    exit 2
}

# Read exactly one line of password material from fd 0 and assign it to
# the caller-supplied variable name (via `printf -v`, which is portable
# back to bash 3.2 -- macOS default). The value never appears in argv
# (bash builtin `read` does not fork) and never in env (we never export
# it). A trailing \r from CRLF input is stripped defensively so
# Windows-edited .env.test files still work. After this call, fd 0 is
# intentionally redirected from /dev/null so subsequent heredocs feeding
# curl cannot accidentally pick up trailing stdin content.
read_password_stdin() {
    local _target="$1"
    local _tmp
    if ! IFS= read -r _tmp <&0; then
        echo "ERROR: failed to read password from stdin -- caller must pipe a single LF-terminated line" >&2
        return 1
    fi
    _tmp="${_tmp%$'\r'}"
    printf -v "$_target" '%s' "$_tmp"
    unset _tmp
    exec 0</dev/null
}

# URL-percent-encode a value read from stdin and print to stdout.
# Using stdin (rather than env or argv) keeps the raw value out of every
# inspectable process surface.
url_encode_stdin() {
    python3 -c '
import sys, urllib.parse
print(urllib.parse.quote(sys.stdin.read(), safe=""), end="")
'
}

# POST a form body (read from stdin) to $1 with optional --cacert $2.
# Body lines arrive via `--data @-` so they live on the stdin pipe,
# never in curl's argv.
post_form() {
    local url="$1"
    local cacert="${2:-}"
    local -a args=(--silent --fail --show-error --max-time 5 --data @-)
    if [[ -n "$cacert" ]]; then
        args+=(--cacert "$cacert")
    fi
    curl "${args[@]}" "$url"
}

# Extract the "token" field from a Technitium JSON response on stdin.
# On error, prints ONLY the top-level keys and the type of the "status"
# field, never `errorMessage` / `error` text or the value of any payload
# field -- some API error bodies echo request parameters and could leak
# credential material into CI logs.
extract_token_field() {
    python3 -c '
import json, sys
try:
    payload = json.load(sys.stdin)
except json.JSONDecodeError as e:
    sys.stderr.write(f"ERROR: response was not JSON: {e}\n")
    sys.exit(1)
if not isinstance(payload, dict):
    sys.stderr.write("ERROR: response was not a JSON object\n")
    sys.exit(1)
token = payload.get("token")
if not isinstance(token, str) or not token:
    # Diagnostics that NEVER emit a field VALUE (only type + length +
    # the set of top-level keys). Even a "short" status string can be
    # 32 ASCII chars of credential-shaped data; do not surface it.
    keys = sorted(payload.keys())
    status = payload.get("status")
    status_diag = f"type={type(status).__name__}" + (
        f" len={len(status)}" if isinstance(status, str) else ""
    )
    token_diag = f"type={type(token).__name__}" + (
        f" len={len(token)}" if isinstance(token, str) else ""
    )
    sys.stderr.write(
        f"ERROR: response did not contain a non-empty string \"token\" field; "
        f"status_field={status_diag} token_field={token_diag} keys={keys}\n"
    )
    sys.exit(1)
print(token, end="")
'
}

cmd_wait_ready() {
    [[ $# -lt 1 || $# -gt 2 ]] && usage
    local url="$1"
    local cacert="${2:-}"

    # Read password from stdin (NOT env, NOT argv) into a local shell
    # variable. After this call fd 0 is redirected to /dev/null so
    # later heredocs do not consume stray stdin content.
    local user="${DNS_ADMIN_USER:-admin}"
    local pass
    read_password_stdin pass

    local user_enc pass_enc
    user_enc=$(printf '%s' "$user" | url_encode_stdin)
    pass_enc=$(printf '%s' "$pass" | url_encode_stdin)
    unset pass

    local attempts=60 i
    for i in $(seq 1 "$attempts"); do
        if post_form "${url}/api/user/login" "$cacert" >/dev/null 2>&1 <<EOF
user=${user_enc}&pass=${pass_enc}
EOF
        then
            echo "Endpoint ready after $i attempt(s)" >&2
            return 0
        fi
        sleep 1
    done
    echo "ERROR: endpoint at ${url} never became ready (${attempts} attempts)" >&2
    return 1
}

cmd_get_token() {
    [[ $# -lt 2 || $# -gt 3 ]] && usage
    local url="$1"
    local token_name="$2"
    local cacert="${3:-}"

    # Read password from stdin (NOT env, NOT argv) into a local shell
    # variable. After this call fd 0 is redirected to /dev/null so
    # later heredocs do not consume stray stdin content.
    local user="${DNS_ADMIN_USER:-admin}"
    local pass
    read_password_stdin pass

    local user_enc pass_enc tn_enc
    user_enc=$(printf '%s' "$user" | url_encode_stdin)
    pass_enc=$(printf '%s' "$pass" | url_encode_stdin)
    tn_enc=$(printf '%s' "$token_name" | url_encode_stdin)
    unset pass

    # Step 1: login -> session token
    local login_resp session_token
    if ! login_resp=$(post_form "${url}/api/user/login" "$cacert" <<EOF
user=${user_enc}&pass=${pass_enc}
EOF
    ); then
        echo "ERROR: /api/user/login POST failed against ${url}" >&2
        return 1
    fi
    if ! session_token=$(printf '%s' "$login_resp" | extract_token_field); then
        echo "ERROR: could not extract session token from login response" >&2
        return 1
    fi
    if [[ -z "$session_token" ]]; then
        echo "ERROR: login returned empty session token" >&2
        return 1
    fi

    # Step 2: createToken -> API token
    # Session token is a transient credential. Encode it locally; do
    # not export it.
    local st_enc
    st_enc=$(printf '%s' "$session_token" | url_encode_stdin)
    unset session_token

    local create_resp api_token
    if ! create_resp=$(post_form "${url}/api/user/createToken" "$cacert" <<EOF
user=${user_enc}&pass=${pass_enc}&tokenName=${tn_enc}&token=${st_enc}
EOF
    ); then
        echo "ERROR: /api/user/createToken POST failed against ${url}" >&2
        return 1
    fi
    if ! api_token=$(printf '%s' "$create_resp" | extract_token_field); then
        echo "ERROR: could not extract API token from createToken response" >&2
        return 1
    fi
    if [[ -z "$api_token" ]]; then
        echo "ERROR: createToken returned empty API token" >&2
        return 1
    fi

    printf '%s\n' "$api_token"
}

main() {
    [[ $# -lt 1 ]] && usage
    local cmd="$1"
    shift
    case "$cmd" in
        wait-ready) cmd_wait_ready "$@" ;;
        get-token)  cmd_get_token  "$@" ;;
        -h|--help|help) usage ;;
        *) echo "ERROR: unknown subcommand: $cmd" >&2; usage ;;
    esac
}

main "$@"
