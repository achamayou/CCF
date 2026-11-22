-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lineage

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private theorem tx_index (s : Spike.engine.Store) (id : U64)
    : WP.spec (Spike.engine.Store.tx_index s id)
        (fun result =>
          match result with
          | .Err e => e = .Disabled ∧ find s.txs.val id = none
          | .Ok i =>
              ∃ t, s.txs.val[i.val]? = some (id, t) ∧ find s.txs.val id = some t) := by
  unfold Spike.engine.Store.tx_index
  apply WP.spec_bind (assoc_index Spike.U64.Insts.Ccf_kv_spikeEngineKey s.txs id (fun _ => rfl))
  intro result h
  cases result <;> simp [h]

/-- Rejected local application preserves the entire store, including attempt state. -/
theorem apply_rejected_keeps_store (s : Spike.engine.Store) (id : U64)
    (rejected
      : ∀ t,
          find s.txs.val id = some t
          → t.phase = .Committing
          → t.pending.val ≠ []
          → WP.spec (Spike.engine.Tx.can_apply t s.history) (fun r => r = false))
    : Spike.engine.Store.execute s (.Apply id) = Result.ok (.Err .Disabled, s) := by
  apply (show WP.spec (Spike.engine.Store.execute s (.Apply id))
      (fun r => r = (.Err .Disabled, s)) → _ from fun h => by
    cases hr : Spike.engine.Store.execute s (.Apply id) using Result.cases with
    | ret r => simpa [hr] using h
    | vis _ _ => simp [hr] at h
    | div => simp [hr] at h)
  unfold Spike.engine.Store.execute Spike.engine.Store.apply
  apply WP.spec_bind (tx_index s id)
  intro index hindex
  cases index with
  | Err why =>
      obtain ⟨rfl, _⟩ := hindex
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | Ok i =>
      obtain ⟨t, hrow, ht⟩ := hindex
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
        alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_usize,
        alloc.vec.Vec.getElem?_Nat_eq, hrow]
      cases hp : t.phase with
      | Active => simp [hp]
      | Finished => simp [hp]
      | Applied _ => simp [hp]
      | Committing =>
          have hcheck' : { t with pending := t.pending, phase := .Committing } = t := by
            rw [← hp]
          by_cases hempty : t.pending.val = []
          · simp [hp, alloc.vec.Vec.is_empty, hempty]
          · simp [hp, alloc.vec.Vec.is_empty, hempty, hcheck']
            apply WP.spec_bind (rejected t ht hp hempty)
            intro _ hr
            simp [hr]

end KvRust
