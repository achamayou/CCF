#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

if [[ $# != 1 ]]; then
  echo "Usage: bash $0 <pinned Aeneas checkout>" >&2
  exit 2
fi

aeneas_root=$(realpath "$1")
proof_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manifest="$proof_dir/lakefile.toml"
expected=$(sed -n 's/^rev = "\([0-9a-f]\{40\}\)"$/\1/p' "$manifest")
if [[ -z "$expected" || $(git -C "$aeneas_root" rev-parse HEAD) != "$expected" ]]; then
  echo "Expected the Aeneas revision pinned in $manifest" >&2
  exit 2
fi
charon_expected=$(tail -n 1 "$aeneas_root/charon-pin")
if [[ $(git -C "$aeneas_root/charon" rev-parse HEAD) != "$charon_expected" ]]; then
  echo "Expected Charon at $charon_expected" >&2
  exit 2
fi

export PATH="$HOME/.cargo/bin:$PATH"
generated="$proof_dir/KvRust/Extracted"
mkdir -p "$proof_dir/.lake" "$generated"
llbc="$proof_dir/.lake/ccf_kv.llbc"
(
  cd "$proof_dir/../../src/rust/ccf-kv"
  "$aeneas_root/charon/bin/charon" cargo --preset=aeneas --sysroot=default --dest-file="$llbc"
)
rm -f -- "$generated/TypesExternal_Template.lean" "$generated/FunsExternal_Template.lean"
"$aeneas_root/bin/aeneas" -backend lean -split-files -abort-on-error \
  -dest "$proof_dir" -subdir KvRust/Extracted -namespace CcfKv "$llbc"
if [[ -e "$generated/TypesExternal_Template.lean" || -e "$generated/FunsExternal_Template.lean" ]]; then
  echo "Unexpected opaque Rust dependency; see the generated templates in $generated" >&2
  exit 1
fi

cd "$proof_dir"
lake build --wfail
for module in KvRust.Extracted.Types KvRust.Extracted.Funs \
  KvRust.Assoc KvRust.BranchLog KvRust.History KvRust.Keys KvRust.Publication \
  KvRust.KvIndex KvRust.IndexedHistory KvRust.IndexedImage KvRust.IndexedPublication \
  KvRust.SortedPublication \
  KvRust.Validation KvRust.Lineage KvRust.Apply KvRust.Advance KvRust.Acquire \
  KvRust.OrderEquivalence KvRust.PendingWrites KvRust.PinnedImage KvRust.Point \
  KvRust.Radix KvRust.RadixAddress KvRust.RadixBatch \
  KvRust.RadixLiveness KvRust.RadixSingle KvRust.RadixSingleReclaim \
  KvRust.RetainedCuts KvRust.RetireQueue \
  KvRust.Range KvRust.Scan KvRust.Relation KvRust.Lifecycle \
  KvRust.LifecycleRefinement KvRust.Environment KvRust.ApplyRefinement \
  KvRust.AcquireRefinement KvRust.OperateRefinement KvRust.Simulation; do
  lake env leanchecker "$module"
done
