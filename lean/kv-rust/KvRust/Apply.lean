-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Advance

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- The extracted dispatcher finds the first live attempt with the given ID. -/
theorem tx_index (s : Spike.engine.Store) (id : U64)
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

private abbrev ReportRow := Spike.engine.Address × Option Spike.engine.Bytes

private def reportRow (row : Spike.engine.Address × Spike.engine.Write) : ReportRow :=
  (
    row.1,
    match row.2 with
    | .Put v => some v
    | .Remove => none
  )

private theorem report_one (row : Spike.engine.Address × Spike.engine.Write)
    : Spike.engine.reported_write row = .ok (reportRow row) := by
  obtain ⟨a, w⟩ := row
  cases w <;> simp [Spike.engine.reported_write, reportRow, clone_address, clone_bytes]

private theorem report_writes
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write)
    : WP.spec (Spike.engine.reported_writes pending)
        (fun r => r.val = pending.val.map reportRow) := by
  unfold Spike.engine.reported_writes Spike.engine.reported_writes_loop
  apply loop.spec_decr_nat
    (fun
        (p
          : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write
            × alloc.vec.Vec ReportRow
            × Usize) =>
      pending.val.length - p.2.2.val)
    (fun (p, out, i) =>
      p = pending
      ∧ out.val.length = i.val
      ∧ out.val ++ (pending.val.drop i.val).map reportRow = pending.val.map reportRow)
    _ _ _
  · rintro ⟨p, out, i⟩ ⟨hp, hi, hdata⟩
    dsimp only at hp hi hdata ⊢
    subst p
    unfold Spike.engine.reported_writes_loop.body
    have hlen : (alloc.vec.Vec.len pending).val = pending.val.length := alloc.vec.Vec.len_val _
    have hcap := alloc.vec.Vec.len_ineq pending
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len pending
    · have hb : i.val < pending.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending i hb)
      intro row hrow
      simp only [report_one, bind_ok]
      have hroom : out.val.length < Usize.max := by omega
      apply WP.spec_bind (alloc.vec.Vec.push_spec out (reportRow row) hroom)
      intro next hn
      have hinc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
      apply WP.spec_bind (Usize.add_spec hinc)
      intro j hj
      have hj' : j.val = i.val + 1 := by omega
      have hsplit : pending.val.drop i.val = row :: pending.val.drop j.val := by
        rw [hj', List.drop_eq_getElem_cons hb, ← hrow]
      simp only [WP.spec_ok]
      refine ⟨⟨True.intro, by simp [hn, hi, hj'], ?_⟩, by omega⟩
      simpa [hn, hsplit, List.append_assoc] using hdata
    · have hb : pending.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa [List.drop_eq_nil_of_le hb] using hdata
  · simp

/-- Encode the reported write set in the same way as the model's staged writes. -/
def encodeReport (encode : List U8 → String)
    (rows : alloc.vec.Vec (Spike.engine.Address × Option Spike.engine.Bytes))
    : Pending :=
  rows.val.map
    fun (addr, v) =>
      (encodeAddr encode (byteAddr addr), v.map (encode ∘ alloc.vec.Vec.val))

private theorem report_matches (encode : List U8 → String)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write)
    : WP.spec (Spike.engine.reported_writes pending)
        (fun reported =>
          encodeReport encode reported
          = encodeWrites encode (byteWrites pending.val)) := by
  apply WP.spec_mono (report_writes pending)
  intro r hr
  simp only [encodeReport, hr, encodeWrites, byteWrites, List.map_map, Function.comp_def]
  apply List.map_congr_left
  rintro ⟨a, w⟩ _
  cases w <;> rfl

/-- The operands of an accepted application fit the machine counters and vector operations. -/
structure ApplyCapacity (s : Spike.engine.History) (head : Spike.engine.Frame)
    (t : Spike.engine.Tx)
    : Prop where
  /-- The next version does not overflow. -/
  version : head.version.val < U64.max
  /-- The next application identity does not overflow. -/
  identity : s.next_identity.val < U64.max
  /-- A new frame can be appended. -/
  history : s.frames.val.length < Usize.max
  /-- Capacity for publication. -/
  data : head.data.val.length + t.pending.val.length ≤ Usize.max
  /-- Capacity for revision records. -/
  revisions : head.revisions.val.length + t.pending.val.length ≤ Usize.max
  /-- Capacity for birth records. -/
  births : head.births.val.length + t.pending.val.length ≤ Usize.max

/-- Accepted local application returns the model's next version, term, and full write set. -/
theorem apply_accepted_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (s : Spike.engine.Store) (id : U64)
    (t : Spike.engine.Tx) (model : Store) (prior : List Spike.engine.Frame)
    (head : Spike.engine.Frame) (hTx : find s.txs.val id = some t)
    (hPhase : t.phase = .Committing) (hWrites : t.pending.val ≠ [])
    (hEligible : WP.spec (Spike.engine.Tx.can_apply t s.history) (fun r => r = true))
    (hHead : s.history.frames.val = prior ++ [head])
    (hFrames : model.history = modelFrames s.history (modelFrame encode))
    (hModelHead : model.head = modelFrame encode head)
    (hTerm : model.term = s.history.term.val)
    (hGlobal : model.global = s.history.global.val)
    (hIdentity : model.nextIdentity = s.history.next_identity.val)
    (hCap : ApplyCapacity s.history head t)
    : let writes := encodeWrites encode (byteWrites t.pending.val)
      let expected := advance model writes
      WP.spec (Spike.engine.Store.execute s (.Apply id))
        (fun (result, after) =>
          ∃ version reported index,
            result = .Ok (.Applied version s.history.term reported)
            ∧ version.val = expected.head.version
            ∧ s.history.term.val = expected.term
            ∧ encodeReport encode reported = writes
            ∧ modelFrames after.history (modelFrame encode) = expected.history
            ∧ after.history.global.val = expected.global
            ∧ after.history.term.val = expected.term
            ∧ after.history.next_identity.val = expected.nextIdentity
            ∧ s.txs.val[index]? = some (id, t)
            ∧ after.txs.val
              = s.txs.val.set index (id, {t with phase := .Applied version})) := by
  dsimp only
  unfold Spike.engine.Store.execute Spike.engine.Store.apply
  apply WP.spec_bind (tx_index s id)
  intro r hr
  cases r with
  | Err _ => simp [hTx] at hr
  | Ok i =>
      obtain ⟨tx, hrow, ht⟩ := hr
      rw [hTx] at ht
      cases ht
      have ht' : { t with pending := t.pending, phase := .Committing } = t := by
        rw [← hPhase]
      simp [core.result.Result.Insts.CoreOpsTry.branch, alloc.vec.Vec.index_slice_index,
        alloc.vec.Vec.index_usize, hrow, hPhase, alloc.vec.Vec.is_empty, hWrites, ht']
      apply WP.spec_bind hEligible
      intro can hcan
      subst can
      have hmax : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
      have hn : head.version ≠ core.num.U64.MAX := fun h => by
        have hv := congrArg (fun v : U64 => v.val) h
        have hd := hCap.version
        omega
      have hi : s.history.next_identity ≠ core.num.U64.MAX := fun h => by
        have hv := congrArg (fun v : U64 => v.val) h
        have hd := hCap.identity
        omega
      simp only [ite_true, history_head s.history prior head hHead, bind_ok, hn, hi, ite_false]
      have hone : (1#u64 : U64).val = 1 := rfl
      have hvbound : head.version.val + (1#u64 : U64).val ≤ U64.max := by
        have := hCap.version
        omega
      apply WP.spec_bind (U64.add_spec hvbound)
      intro version hv
      have hv' : version.val = model.head.version + 1 := by
        have he : model.head.version = head.version.val := by
          simp [hModelHead, modelFrame, modelMetadata]
        omega
      apply WP.spec_bind
        (frame_advance_matches_model encode inj head model t.pending version
          s.history.next_identity hModelHead hv' hIdentity.symm hCap.data hCap.revisions
          hCap.births)
      intro next hnext
      apply WP.spec_bind (report_matches encode t.pending)
      intro reported hreported
      apply WP.spec_bind (alloc.vec.Vec.push_spec s.history.frames next hCap.history)
      intro frames hf
      have hibound : s.history.next_identity.val + (1#u64 : U64).val ≤ U64.max := by
        have := hCap.identity
        omega
      apply WP.spec_bind (U64.add_spec hibound)
      intro identity hidentity
      obtain ⟨idx, hget⟩ := List.getElem?_eq_some_iff.mp hrow
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s.txs i idx)
      rintro ⟨row, back⟩ hback
      have hrow' : row = (id, t) := hback.1.trans hget
      subst row
      change WP.spec (Result.ok
        (core.result.Result.Ok (Spike.engine.Output.Applied version s.history.term reported),
          ({history := {s.history with frames, next_identity := identity},
            txs := back (id, {t with phase := .Applied version})} : Spike.engine.Store))) _
      rw [WP.spec_ok]
      refine ⟨version, reported, ?_⟩
      refine ⟨rfl, hv', hTerm.symm, hreported, ?_, hGlobal.symm,
        hTerm.symm, ?_, i.val, hrow, ?_⟩
      · simp only [modelFrames, hf, List.reverse_append, List.reverse_singleton, List.singleton_append,
          List.map_cons]
        unfold modelFrames at hFrames
        rw [← hFrames, hnext]
        rfl
      · simpa [hone, hIdentity, advance] using hidentity
      · rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _

end KvRust
