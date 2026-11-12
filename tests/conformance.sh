#!/usr/bin/env bash
# Five implementations, one answer: the C CLI, the Python binding, the Node/WASM binding and two
# independent pure-language references must produce byte-identical JSON.
set -euo pipefail
cd "$(dirname "$0")/.."
files=("$@")
[ ${#files[@]} -gt 0 ] || files=(fixtures/sample.log)

c=$(build/logforge --json "${files[@]}")
py=$(python3 bindings/python/logforge.py "${files[@]}")
nd=$(node bindings/node/cli.mjs "${files[@]}")
rp=$(python3 bench/ref.py "${files[@]}")
rn=$(node bench/ref.mjs "${files[@]}")

ok=1
for pair in "py:$py" "node-wasm:$nd" "ref-python:$rp" "ref-node:$rn"; do
  name=${pair%%:*}; val=${pair#*:}
  if [ "$val" != "$c" ]; then echo "MISMATCH: $name differs from the C CLI"; diff <(echo "$c" | tr ',' '\n') <(echo "$val" | tr ',' '\n') | head -10; ok=0; fi
done
[ $ok -eq 1 ] || exit 1
echo "conformance OK: C CLI, Python, Node/WASM, ref.py and ref.mjs agree on ${files[*]}"
