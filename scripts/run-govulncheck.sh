#!/bin/sh
set -eu

output=$(mktemp)
trap 'rm -f "$output"' EXIT

is_infrastructure_failure() {
	grep -Eiq 'dial tcp|network is unreachable|no such host|i/o timeout|tls handshake timeout|connection (refused|reset)|proxyconnect|temporary failure|service unavailable|HTTP (429|5[0-9][0-9])|rate limit' "$output"
}

run_check() {
	govulncheck ./... >"$output" 2>&1
}

if run_check; then
	cat "$output"
	exit 0
fi

cat "$output" >&2
if ! is_infrastructure_failure; then
	exit 1
fi

echo "::warning::govulncheck could not reach its vulnerability service; retrying once." >&2
if run_check; then
	cat "$output"
	exit 0
fi

cat "$output" >&2
if is_infrastructure_failure; then
	echo "::warning::govulncheck remains unavailable after one retry; treating this as non-blocking infrastructure failure." >&2
	exit 0
fi

exit 1
