#!/usr/bin/env bash
set -euo pipefail

readonly upstream_url="https://github.com/ards-project/ard-spec.git"
readonly upstream_commit="5fa2f5aef790b478319f6a3b43adf4661b0ed0e0"
readonly listen="127.0.0.1:18090"
readonly base_url="http://${listen}"

work_dir="$(mktemp -d /tmp/tos-ard-conformance.XXXXXX)"
server_pid=""
cleanup() {
  if [[ -n "${server_pid}" ]]; then
    kill -TERM "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT INT TERM

git clone --quiet --no-checkout "${upstream_url}" "${work_dir}/upstream"
git -C "${work_dir}/upstream" checkout --quiet --detach "${upstream_commit}"
test "$(git -C "${work_dir}/upstream" rev-parse HEAD)" = "${upstream_commit}"

install -m 600 examples/ai-catalog.json "${work_dir}/ai-catalog.json"
GOWORK=off go build -o "${work_dir}/tos-ard-registry" ./cmd/tos-ard-registry
"${work_dir}/tos-ard-registry" \
  -listen "${listen}" \
  -public-url "${base_url}/search" \
  -catalog "${work_dir}/ai-catalog.json" \
  >"${work_dir}/registry.log" 2>&1 &
server_pid="$!"

for _ in $(seq 1 100); do
  if curl --fail --silent --show-error "${base_url}/healthz" >/dev/null; then
    break
  fi
  if ! kill -0 "${server_pid}" 2>/dev/null; then
    cat "${work_dir}/registry.log" >&2
    exit 1
  fi
  sleep 0.05
done
curl --fail --silent --show-error "${base_url}/healthz" >/dev/null

python3 "${work_dir}/upstream/conformance/bin/conformance-test" \
  manifest examples/ai-catalog.json
python3 "${work_dir}/upstream/conformance/bin/conformance-test" \
  registry "${base_url}"
