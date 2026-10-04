#!/usr/bin/env bash
cd "$(dirname "$0")/.."
pass=0; fail=0

check() {  
  out=$(python3 security-scan.py --path "testinghub/$1" --format json); code=$?
  found=$(echo "$out" | python3 -c "import json,sys; print(sum(f['category']=='$3' for f in json.load(sys.stdin)['findings']))")
  if [ "$code" = "$2" ] && { [ "$3" = "-" ] || [ "$found" -gt 0 ]; }; then
    echo "PASS  $1 (exit $code)"; pass=$((pass+1))
  else
    echo "FAIL  $1 (expected exit $2, got $code; $3 findings: $found)"; fail=$((fail+1))
  fi
}

check clean-app   0 -        # safe code   -> passes
check secrets-test 1 secrets  # leaked key  -> fails on secrets
check iac-tests    1 iac      # open SSH    -> fails on IaC

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]

