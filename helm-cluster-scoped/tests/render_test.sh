#!/usr/bin/env bash
#
# Copyright 2026 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Offline rendering tests for the cpfs.grantOpenShiftAuthRBAC gate (roadmap#70210).
# Requires only helm; no cluster is needed. Run from anywhere:
#   helm-cluster-scoped/tests/render_test.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="$(cd "${HERE}/.." && pwd)"
GOLDEN="${HERE}/testdata/default-gated-documents.yaml"
NS="ibm-common-services"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
pass() { echo "PASS: $*"; }

render() { helm template t "${CHART}" --set "global.operatorNamespace=${NS}" "$@"; }
count_kind() { grep -c "^kind: $1\$" <<<"$2" || true; }

# assert_counts <name> <rendered output> <ClusterRole> <ClusterRoleBinding> <CRD>
assert_counts() {
  local name="$1" out="$2" cr="$3" crb="$4" crd="$5"
  local gcr gcrb gcrd
  gcr=$(count_kind ClusterRole "${out}")
  gcrb=$(count_kind ClusterRoleBinding "${out}")
  gcrd=$(count_kind CustomResourceDefinition "${out}")
  if [[ "${gcr}" != "${gcrb}" ]]; then
    fail "${name}: ClusterRole count (${gcr}) != ClusterRoleBinding count (${gcrb})"
  elif [[ "${gcr}" != "${cr}" || "${gcrb}" != "${crb}" || "${gcrd}" != "${crd}" ]]; then
    fail "${name}: expected ClusterRole=${cr} ClusterRoleBinding=${crb} CRD=${crd}, got ${gcr}/${gcrb}/${gcrd}"
  else
    pass "${name}"
  fi
}

# T1: default render
T1="$(render)" || { fail "T1: helm template failed"; T1=""; }
assert_counts "T1 default" "${T1}" 1 1 2

# T2: explicit true is identical to default
T2="$(render --set cpfs.grantOpenShiftAuthRBAC=true)"
if [[ "${T1}" == "${T2}" ]]; then pass "T2 true identical to default"; else fail "T2: output differs from default"; fi
assert_counts "T2 true" "${T2}" 1 1 2

# T3: false omits both, keeps CRDs
assert_counts "T3 false" "$(render --set cpfs.grantOpenShiftAuthRBAC=false)" 0 0 2

# T4: cpfs map without the key
printf 'cpfs:\n  labels:\n    a: b\n' >"${TMP}/t4.yaml"
assert_counts "T4 key absent" "$(render -f "${TMP}/t4.yaml")" 1 1 2

# T5b: golden comparison of the ClusterRole and ClusterRoleBinding documents
extract_gated() {
  awk '
    BEGIN { RS = "\n---\n"; ORS = "\n---\n" }
    /^# Source: .*\/(10_clusterrole|11_clusterrolebinding)\.yaml/ { print }
  ' <<<"$1"
}
if diff <(extract_gated "${T1}") "${GOLDEN}" >"${TMP}/golden.diff"; then
  pass "T5b golden file"
else
  fail "T5b: gated documents differ from ${GOLDEN}"; cat "${TMP}/golden.diff"
fi

# T6: lint with true and false
for v in true false; do
  if helm lint "${CHART}" --set "global.operatorNamespace=${NS}" --set "cpfs.grantOpenShiftAuthRBAC=${v}" >"${TMP}/lint.out" 2>&1; then
    pass "T6 lint ${v}"
  else
    fail "T6 lint ${v}"; cat "${TMP}/lint.out"
  fi
done

# T7: --set-string "false" is truthy; documents the string pitfall
assert_counts "T7 set-string false" "$(render --set-string cpfs.grantOpenShiftAuthRBAC=false)" 1 1 2

# T8: cpfs null, and cpfs omitted entirely
printf 'cpfs: null\n' >"${TMP}/t8a.yaml"
assert_counts "T8 cpfs null" "$(render -f "${TMP}/t8a.yaml")" 1 1 2
printf 'global:\n  operatorNamespace: %s\n' "${NS}" >"${TMP}/t8b.yaml"
assert_counts "T8 cpfs omitted" "$(render -f "${TMP}/t8b.yaml" --set cpfs=null)" 1 1 2

# T9: values.yaml documents the flag
if grep -q '^  grantOpenShiftAuthRBAC: true$' "${CHART}/values.yaml" &&
   grep -q 'Must be a YAML boolean' "${CHART}/values.yaml"; then
  pass "T9 values.yaml"
else
  fail "T9: values.yaml is missing the flag or its boolean-only comment"
fi

exit "${FAILED}"
