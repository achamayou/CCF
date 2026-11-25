-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Advance

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

local instance : DecidableEq Spike.engine.Address :=
  fun a b =>
    decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

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

private theorem optional_report_matches (encode : List U8 → String)
    (pending
      : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write) (includeReport : Bool)
    : WP.spec
        (if includeReport then
            Spike.engine.reported_writes pending
          else
            .ok (alloc.vec.Vec.new ReportRow))
        (fun reported =>
          encodeReport encode reported
          = if includeReport then
              encodeWrites encode (byteWrites pending.val)
            else
              []) := by
  cases includeReport
  · simp [encodeReport, alloc.vec.Vec.new]
  · simpa using report_matches encode pending

/-- The operands of an accepted application fit the machine counters and vector operations. -/
structure ApplyCapacity (s : Spike.engine.History) (head : Spike.engine.Frame)
    (t : Spike.engine.Tx)
    : Prop where
  /-- The next version does not overflow. -/
  version : head.version.val < U64.max
  /-- The next application identity does not overflow. -/
  identity : s.next_identity.val < U64.max
  /-- A new frame can be appended. -/
  history : s.activeFrames.length < Usize.max
  archive : s.log.frames.val.length < Usize.max
  /-- Capacity for publication. -/
  data
    : IndexBatchRoom s.index ((indexRows s.index head.data).length + t.pending.val.length)
        t.pending.val.length
  addresses : ∀ row ∈ t.pending.val, IndexKeyRoom row
  dependencies : ∀ d ∈ t.deps.val, DependencyRoom (indexRows s.index head.data) d
  /-- Capacity for revision records. -/
  revisions : head.revisions.val.length + t.pending.val.length ≤ Usize.max
  /-- Capacity for birth records. -/
  births : head.births.val.length + t.pending.val.length ≤ Usize.max

/-- Accepted local application publishes the frame modulo binding order, with or without a write report. -/
theorem apply_accepted_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (s : Spike.engine.Store) (id : U64)
    (includeReport : Bool) (t : Spike.engine.Tx) (model : Store)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hTx : find s.txs.val id = some t) (hPhase : t.phase = .Committing)
    (hWrites : t.pending.val ≠ [])
    (hEligible : WP.spec (Spike.engine.Tx.can_apply t s.history) (fun r => r = true))
    (hHead : s.history.activeFrames = prior ++ [head])
    (hFrames : model.history = modelFrames s.history (modelFrame encode s.history.index))
    (hModelHead : model.head = modelFrame encode s.history.index head)
    (hTerm : model.term = s.history.term.val)
    (hGlobal : model.global = s.history.global.val)
    (hIdentity : model.nextIdentity = s.history.next_identity.val)
    (hCap : ApplyCapacity s.history head t) (valid : BranchValid s.history.log)
    (indexed : HistoryIndexValid s.history)
    : let writes := encodeWrites encode (byteWrites t.pending.val)
      let expected := advance model writes
      WP.spec (Spike.engine.Store.apply s id includeReport)
        (fun (result, after) =>
          ∃ version reported index next,
            result = .Ok (.Applied version s.history.term reported)
            ∧ version.val = expected.head.version
            ∧ s.history.term.val = expected.term
            ∧ encodeReport encode reported = (if includeReport then writes else [])
            ∧ FrameOrderEq (modelFrame encode after.history.index next) expected.head
            ∧ IndexView after.history.index next.data
                (indexRows after.history.index next.data)
            ∧ modelFrames after.history (modelFrame encode after.history.index)
              = modelFrame encode after.history.index next :: model.history
            ∧ after.history.global.val = expected.global
            ∧ after.history.term.val = expected.term
            ∧ after.history.next_identity.val = expected.nextIdentity
            ∧ s.txs.val[index]? = some (id, t)
            ∧ after.txs.val = s.txs.val.set index (id, {t with phase := .Applied version})
            ∧ BranchValid after.history.log
            ∧ HistoryIndexValid after.history
            ∧ HistoryKeeps s.history after.history
            ∧ after.history.log.frames.val = s.history.log.frames.val ++ [next]
            ∧ after.history.log.frames.val.map (modelFrame encode after.history.index)
              = s.history.log.frames.val.map (modelFrame encode s.history.index)
                ++ [modelFrame encode after.history.index next]) := by
  dsimp only
  unfold Spike.engine.Store.apply
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
      simp only [ite_true, history_head s.history prior head hHead valid, bind_ok, hn, hi, ite_false]
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
        (prepare_frame_matches_model encode inj s.history prior head valid hHead indexed
          model t.pending version s.history.next_identity hModelHead hv' hIdentity.symm
          hCap.data hCap.addresses hCap.revisions hCap.births)
      rintro ⟨next, prepared⟩ ⟨arena, same, hnext, view, indexValid, indexKept⟩
      change prepared = {s.history with index := arena} at same
      subst prepared
      apply WP.spec_bind (optional_report_matches encode t.pending includeReport)
      intro reported hreported
      have branchRoom : s.history.log.branch.val.length < Usize.max :=
        (branch_values_length s.history.log valid) ▸ hCap.history
      apply WP.spec_bind
        (branch_append_refines s.history.log next valid hCap.archive branchRoom)
      rintro ⟨frameId, log⟩ ⟨logValid, hf, slot, _, kept, archive⟩
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
          ({s with
            history := {s.history with log, index := arena, next_identity := identity}
            txs := back (id, {t with phase := .Applied version})} : Spike.engine.Store))) _
      rw [WP.spec_ok]
      dsimp only
      refine ⟨
        version,
        reported,
        rfl,
        hv',
        hTerm.symm,
        hreported,
        i.val,
        next,
        hnext,
        view,
        ?_,
        hGlobal.symm,
        hTerm.symm,
        ?_,
        hrow,
        ?_,
        logValid,
        ?_,
        ⟨?_, indexKept⟩,
        archive,
        ?_
      ⟩
      · simp only [modelFrames, Spike.engine.History.activeFrames, hf, List.reverse_append,
          List.reverse_singleton, List.singleton_append,
          List.map_cons]
        have same := congrArg List.reverse (model_frame_retained_active encode indexed indexKept)
        simp only [← List.map_reverse] at same
        unfold modelFrames at hFrames
        rw [same, ← hFrames]
      · simpa [hone, hIdentity, advance] using hidentity
      · rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _
      · exact indexed.append indexKept indexValid next view archive
      · intro j f saved
        have bound : j < frameId.val := by
          rw [slot]
          by_contra hn
          rw [List.getElem?_eq_none (Nat.le_of_not_gt hn)] at saved
          cases saved
        exact (kept j bound).trans saved
      · rw [archive, List.map_append, List.map_singleton]
        congr 1
        apply List.map_congr_left
        intro f hfmem
        obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hfmem
        exact model_frame_retained encode indexKept f (indexed.archived j f hj)

/-- The wire-size preflight reads exactly the write set used by the KV model. -/
theorem pending_writes_match (encode : List U8 → String)
    (s : Spike.engine.Store) (id : U64) (t : Spike.engine.Tx)
    (hTx : find s.txs.val id = some t) (hPhase : t.phase = .Active)
    : WP.spec (Spike.engine.Store.pending_writes s id)
        (fun result =>
          ∃ writes,
            result = .Ok writes
            ∧ encodeReport encode writes
              = encodeWrites encode (byteWrites t.pending.val)) := by
  unfold Spike.engine.Store.pending_writes
  apply WP.spec_bind (tx_index s id)
  intro index hindex
  cases index with
  | Err _ => simp [hTx] at hindex
  | Ok i =>
      obtain ⟨actual, hrow, ht⟩ := hindex
      rw [hTx] at ht
      cases ht
      simp [core.result.Result.Insts.CoreOpsTry.branch, alloc.vec.Vec.index_slice_index,
        alloc.vec.Vec.index_usize, hrow, hPhase]
      apply WP.spec_bind (report_matches encode t.pending)
      intro writes hw
      simp only [WP.spec_ok]
      exact ⟨writes, rfl, hw⟩

/-- A gap or duplicate version is rejected before changing the store. -/
theorem replay_next_rejects_wrong_version
    (s : Spike.engine.Store) (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hHead : s.history.activeFrames = prior ++ [head])
    (hVersion : head.version.val < U64.max)
    (hIdentity : s.history.next_identity.val < U64.max)
    (requested : U64)
    (writes : alloc.vec.Vec (Spike.engine.Address × Option Spike.engine.Bytes))
    (wrong : requested.val ≠ head.version.val + 1)
    (valid : BranchValid s.history.log)
    : WP.spec (Spike.engine.Store.replay_next s requested writes)
        (fun r => r = (.Err .Disabled, s)) := by
  have hmax : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
  have hv : head.version ≠ core.num.U64.MAX := fun he => by
    have he' := congrArg (fun v : U64 => v.val) he
    omega
  have hi : s.history.next_identity ≠ core.num.U64.MAX := fun he => by
    have he' := congrArg (fun v : U64 => v.val) he
    omega
  have hone : (1#u64 : U64).val = 1 := rfl
  have hroom : head.version.val + (1#u64 : U64).val ≤ U64.max := by omega
  have rejection : WP.spec
      (Spike.engine.Store.prepare_replay head.version s.history.next_identity requested writes)
      (fun r => r = .Err .Disabled) := by
    simp only [Spike.engine.Store.prepare_replay, hv, hi, ite_false]
    apply WP.spec_bind (U64.add_spec hroom)
    intro v hval
    have hne : requested ≠ v := fun he => by
      have he' := congrArg (fun x : U64 => x.val) he
      omega
    simp [hne]
  unfold Spike.engine.Store.replay_next Spike.engine.Store.replay_indexed
  simp only [history_head s.history prior head hHead valid, bind_ok]
  apply WP.spec_bind rejection
  intro r hr
  subst r
  simp [core.result.Result.Insts.CoreOpsTry.branch,
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]

def replayRow (row : Spike.engine.Address × Option Spike.engine.Bytes) : IndexWrite :=
  (
    row.1,
    match row.2 with
    | some bytes => .Put bytes
    | none => .Remove
  )

private theorem prepare_replay_matches (previous identity version : U64)
    (hVersion : version.val = previous.val + 1) (hI : identity.val < U64.max)
    (writes : alloc.vec.Vec (Spike.engine.Address × Option Spike.engine.Bytes))
    : WP.spec (Spike.engine.Store.prepare_replay previous identity version writes)
        (fun result =>
          result = .Err .Disabled
          ∨ ∃ pending,
              result = .Ok pending ∧ pending.val = writes.val.map replayRow) := by
  have hmax : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
  have hle : version.val ≤ U64.max := by scalar_tac
  have hv : previous ≠ core.num.U64.MAX := fun he => by
    have he' := congrArg (fun v : U64 => v.val) he
    omega
  have hi : identity ≠ core.num.U64.MAX := fun he => by
    have he' := congrArg (fun v : U64 => v.val) he
    omega
  have hone : (1#u64 : U64).val = 1 := rfl
  have hroom : previous.val + (1#u64 : U64).val ≤ U64.max := by omega
  unfold Spike.engine.Store.prepare_replay
  simp only [hv, hi, ite_false]
  apply WP.spec_bind (U64.add_spec hroom)
  intro v hv'
  have hEq : v = version := by
    apply UScalar.eq_of_val_eq
    omega
  subst v
  simp only [bne_self_eq_false, Bool.false_eq_true, ite_false,
    Spike.engine.Assoc.new, bind_ok]
  unfold Spike.engine.Store.prepare_replay_loop
  ·
    apply loop.spec_decr_nat
      (fun (p : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write × Usize) =>
        writes.val.length - p.2.val)
      (fun (pending, j) =>
        pending.val.length = j.val
        ∧ pending.val ++ (writes.val.drop j.val).map replayRow = writes.val.map replayRow)
      _ _ _
    · rintro ⟨pending, j⟩ ⟨hj, hrows⟩
      dsimp only at hj hrows ⊢
      unfold Spike.engine.Store.prepare_replay_loop.body
      have hlen : (alloc.vec.Vec.len writes).val = writes.val.length :=
        alloc.vec.Vec.len_val writes
      have hcap := alloc.vec.Vec.len_ineq writes
      have hu : (1#usize : Usize).val = 1 := rfl
      by_cases hb : j < alloc.vec.Vec.len writes
      · have hlt : j.val < writes.val.length := by rw [← hlen]; exact hb
        rw [ite_eq_left hb, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec writes j hlt)
        rintro ⟨addr, value⟩ hrow
        apply WP.spec_bind
          (assoc_index Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey pending addr
            (fun k => compare_address k addr))
        intro found _
        cases found with
        | some _ => simp
        | none =>
            have hwrite :
                (match value with
                | none => Result.ok Spike.engine.Write.Remove
                | some bytes => do
                    let b ← Spike.engine.Bytes.Insts.CoreCloneClone.clone bytes
                    Result.ok (Spike.engine.Write.Put b))
                = .ok (replayRow (addr, value)).2 := by
              cases value <;> simp [replayRow, clone_bytes]
            simp only [core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true,
              ite_false, clone_address, bind_ok]
            change WP.spec (do
              let write ←
                match value with
                | none => Result.ok Spike.engine.Write.Remove
                | some bytes => do
                    let b ← Spike.engine.Bytes.Insts.CoreCloneClone.clone bytes
                    Result.ok (Spike.engine.Write.Put b)
              let next ← alloc.vec.Vec.push pending (addr, write)
              let nextj ← j + 1#usize
              Result.ok (ControlFlow.cont (next, nextj))) _
            rw [hwrite, bind_ok]
            have hpush : pending.val.length < Usize.max := by omega
            apply WP.spec_bind (alloc.vec.Vec.push_spec pending _ hpush)
            intro next hn
            have hinc : j.val + (1#usize : Usize).val ≤ Usize.max := by omega
            apply WP.spec_bind (Usize.add_spec hinc)
            intro nextj hnext
            have hnext' : nextj.val = j.val + 1 := by omega
            have hsplit : writes.val.drop j.val = (addr, value) :: writes.val.drop nextj.val := by
              rw [hnext', List.drop_eq_getElem_cons hlt, ← hrow]
            simp only [WP.spec_ok]
            refine ⟨⟨by simp [hn, hj, hnext'], ?_⟩, by omega⟩
            simpa [replayRow, hn, hsplit, List.append_assoc] using hrows
      · have hge : writes.val.length ≤ j.val := by rw [← hlen]; exact Nat.le_of_not_gt hb
        rw [ite_eq_right hb, WP.spec_ok]
        have hp : pending.val = writes.val.map replayRow := by simpa [List.drop_eq_nil_of_le hge] using hrows
        exact Or.inr ⟨pending, rfl, hp⟩
    · simp

/-- Ordinary replay leaves the store unchanged on rejection, or appends the specified frame. -/
theorem replay_next_matches_advance (encode : List U8 → String)
    (inj : Function.Injective encode) (s : Spike.engine.Store) (model : Store)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hHead : s.history.activeFrames = prior ++ [head])
    (hModelHead : model.head = modelFrame encode s.history.index head)
    (hIdentity : model.nextIdentity = s.history.next_identity.val)
    (version : U64) (hVersion : version.val = head.version.val + 1)
    (writes : alloc.vec.Vec (Spike.engine.Address × Option Spike.engine.Bytes))
    (hF : s.history.activeFrames.length < Usize.max)
    (hI : s.history.next_identity.val < U64.max)
    (hD
      : IndexBatchRoom s.history.index
          ((indexRows s.history.index head.data).length + writes.val.length)
          writes.val.length)
    (hKeys : ∀ row ∈ writes.val, IndexKeyRoom (replayRow row))
    (hR : head.revisions.val.length + writes.val.length ≤ Usize.max)
    (hB : head.births.val.length + writes.val.length ≤ Usize.max)
    (valid : BranchValid s.history.log) (indexed : HistoryIndexValid s.history)
    (archiveRoom : s.history.log.frames.val.length < Usize.max)
    : WP.spec (Spike.engine.Store.replay_next s version writes)
        (fun (result, after) =>
          (result = .Err .Disabled ∧ after = s)
          ∨ (result = .Ok ()
              ∧ ∃ next,
                  FrameOrderEq (modelFrame encode after.history.index next)
                    (advance model (encodeReport encode writes)).head
                  ∧ after.history.activeFrames = s.history.activeFrames ++ [next]
                  ∧ after.history.next_identity.val = s.history.next_identity.val + 1
                  ∧ after.history.term = s.history.term
                  ∧ after.history.global = s.history.global
                  ∧ after.txs = s.txs
                  ∧ BranchValid after.history.log
                  ∧ HistoryIndexValid after.history
                  ∧ HistoryKeeps s.history after.history)) := by
  unfold Spike.engine.Store.replay_next Spike.engine.Store.replay_indexed
  simp only [history_head s.history prior head hHead valid, bind_ok]
  apply WP.spec_bind (prepare_replay_matches head.version s.history.next_identity
    version hVersion hI writes)
  rintro r (rfl | ⟨pending, rfl, hp⟩)
  · simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  · simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, Spike.engine.Store.append_replay,
      Bool.false_eq_true, ite_false, Aeneas.Std.bind_assoc]
    have hlength : pending.val.length = writes.val.length := by simp [hp]
    have hWrite : encodeWrites encode (byteWrites pending.val) = encodeReport encode writes := by
      simp only [hp, byteWrites, encodeWrites, encodeReport, List.map_map, Function.comp_def]
      apply List.map_congr_left
      rintro ⟨addr, value⟩ _
      cases value <;> rfl
    have versionEq : version.val = model.head.version + 1 := by
      simpa only [hModelHead, modelFrame, modelMetadata] using hVersion
    have keyRoom : ∀ row ∈ pending.val, IndexKeyRoom row := by
      intro row hm
      rw [hp] at hm
      obtain ⟨entry, present, rfl⟩ := List.mem_map.mp hm
      exact hKeys entry present
    apply WP.spec_bind
      (prepare_frame_matches_model encode inj s.history prior head valid hHead indexed
        model pending version s.history.next_identity hModelHead versionEq hIdentity.symm
        (hlength.symm ▸ hD) keyRoom (hlength.symm ▸ hR) (hlength.symm ▸ hB))
    rintro ⟨next, prepared⟩ ⟨arena, same, modelFrameEq, view, good, preserved⟩
    change prepared = {s.history with index := arena} at same
    subst prepared
    let publish (log : Spike.branch_log.BranchLog Spike.engine.Frame) (identity : U64)
        : Spike.engine.Store :=
      { s with
        history := { s.history with
          log
          index := arena
          next_identity := identity
          reuse_compacted_images := false } }
    change WP.spec (Aeneas.Std.bind
      (do
        let (_, log) ← Spike.branch_log.BranchLog.append s.history.log next
        let identity ← s.history.next_identity + 1#u64
        Result.ok (publish log identity))
      (fun updated => Result.ok (core.result.Result.Ok (), updated))) _
    rw [Aeneas.Std.bind_assoc]
    have branchRoom : s.history.log.branch.val.length < Usize.max :=
      (branch_values_length s.history.log valid) ▸ hF
    apply WP.spec_bind
      (branch_append_refines s.history.log next valid archiveRoom branchRoom)
    rintro ⟨id, log⟩ ⟨logValid, hf, slot, saved, kept, archive⟩
    change WP.spec (Aeneas.Std.bind
      (do
        let identity ← s.history.next_identity + 1#u64
        Result.ok (publish log identity))
      (fun updated => Result.ok (core.result.Result.Ok (), updated))) _
    rw [Aeneas.Std.bind_assoc]
    have one : (1#u64 : U64).val = 1 := rfl
    apply WP.spec_bind
      (U64.add_spec (x := s.history.next_identity) (y := 1#u64) (by omega))
    intro ident hident
    simp only [bind_ok, WP.spec_ok, publish]
    refine Or.inr
      ⟨
        True.intro,
        next,
        hWrite ▸ modelFrameEq,
        hf,
        by omega,
        True.intro,
        True.intro,
        True.intro,
        logValid,
        indexed.append preserved good next view archive,
        ⟨?_, preserved⟩
      ⟩
    intro j f entry
    have inside : j < id.val := by
      rw [slot]
      by_contra no
      rw [List.getElem?_eq_none (Nat.le_of_not_gt no)] at entry
      cases entry
    exact (kept j inside).trans entry

end KvRust
