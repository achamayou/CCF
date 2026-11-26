-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lifecycle
public import KvRust.Simulation

import all Aeneas.Data.BitVec
import all Aeneas.Std.Alloc.Vec

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Metadata-only stub relation: `stub` carries the exact snapshot cut and acquired
`(map, birth, revision)` stamps of `full` while holding no radix root pins. -/
def StubOf (stub full : CcfKv.engine.Tx) : Prop :=
  stub.snapshot = full.snapshot
  ∧ stub.views.val
    = full.views.val.map (fun (m, v) => (m, {v with «local» := .Empty, global := none}))

/-- A metadata-only stub holds zero radix root pins. -/
theorem stub_tx_pins_empty {stub full : CcfKv.engine.Tx} (h : StubOf stub full)
    : txPins stub = [] := by
  unfold txPins
  rw [h.2]
  simp only [List.flatMap_eq_nil_iff, List.mem_map, Prod.forall, Prod.exists]
  rintro a b ⟨_, _, _, hpair⟩
  cases hpair
  simp [viewPins, pinPins]

/-- `tx_needs_frame` evaluates identically on a full `Tx` and any metadata-only
stub `StubOf stub full`, proving that `History.compact` and `History.prune_retained`
make the exact same retention and pruning decisions on the detached stub registry. -/
theorem tx_needs_frame_stub {stub full : CcfKv.engine.Tx} (h : StubOf stub full)
    (frame globalFrame : CcfKv.engine.Frame)
    : CcfKv.engine.tx_needs_frame stub frame globalFrame
      = CcfKv.engine.tx_needs_frame full frame globalFrame := by
  have encInj : Function.Injective (encodeBytes ∘ alloc.vec.Vec.val (α := U8)) :=
    encodeBytes_injective.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have hs1 := tx_needs_frame_spec (encodeBytes ∘ alloc.vec.Vec.val) encInj stub frame globalFrame
  have hs2 := tx_needs_frame_spec (encodeBytes ∘ alloc.vec.Vec.val) encInj full frame globalFrame
  cases h1 : CcfKv.engine.tx_needs_frame stub frame globalFrame using Result.cases with
  | vis _ _ => rw [h1] at hs1; simp at hs1
  | div => rw [h1] at hs1; simp at hs1
  | ret b1 =>
      cases h2 : CcfKv.engine.tx_needs_frame full frame globalFrame
        using Result.cases with
      | vis _ _ => rw [h2] at hs2; simp at hs2
      | div => rw [h2] at hs2; simp at hs2
      | ret b2 =>
          rw [h1, WP.spec_ok] at hs1
          rw [h2, WP.spec_ok] at hs2
          congr 1
          rw [hs1, hs2, h.1, h.2, List.any_map]
          rfl

/-- Creating a `DetachedTx` initializes `lifecycleNewTx` without touching `Store`. -/
theorem detached_new_eq (id : U64)
    : CcfKv.engine.DetachedTx.new id
      = .ok { id, tx := lifecycleNewTx, registered := false } := by
  simp [CcfKv.engine.DetachedTx.new, tx_new_lifecycle]

/-- `DetachedTx.operate` borrows `&Store` immutably and delegates directly to
`Tx.operate`, so every verified read/scan/range/size/clear theorem applies
verbatim under a shared `RwLock::read` guard. -/
theorem detached_operate_eq (d : CcfKv.engine.DetachedTx) (s : CcfKv.engine.Store)
    (m : CcfKv.engine.Bytes) (op : CcfKv.engine.Operation)
    : CcfKv.engine.DetachedTx.operate d s m op
      = (do
          let (out, nextTx) ← CcfKv.engine.Tx.operate d.tx s.history m op
          Result.ok (out, { d with tx := nextTx })) := by
  rfl

/-- `DetachedTx.stage_write` agrees with `Tx.operate ... (.Write k v)` for every
`History`, proving lock-free staged writes are independent of `Store.history`. -/
theorem detached_stage_write_matches_operate (d : CcfKv.engine.DetachedTx)
    (h : CcfKv.engine.History) (m k : CcfKv.engine.Bytes) (v : Option CcfKv.engine.Bytes)
    (hSorted : PendingSorted d.tx.pending.val)
    (hRoom : d.tx.pending.val.length < Usize.max)
    : WP.spec (CcfKv.engine.DetachedTx.stage_write d m k v)
        (fun (res, after) =>
          after.id = d.id
          ∧ after.registered = d.registered
          ∧ match d.tx.phase, find d.tx.views.val m with
            | .Active, some _ =>
                res = .Ok ()
                ∧ CcfKv.engine.Tx.operate d.tx h m (.Write k v)
                  = .ok (.Ok .Unit, after.tx)
            | _, _ => res = .Err .Disabled ∧ after = d) := by
  unfold CcfKv.engine.DetachedTx.stage_write CcfKv.engine.Tx.operate
  cases hp : d.tx.phase with
  | Committing =>
      have hrest : { d with tx := { d.tx with phase := .Committing } } = d := by
        cases d with
        | mk _ tx _ => cases tx; simp_all
      simp [hrest]
  | Applied ver =>
      have hrest : { d with tx := { d.tx with phase := .Applied ver } } = d := by
        cases d with
        | mk _ tx _ => cases tx; simp_all
      simp [hrest]
  | Finished =>
      have hrest : { d with tx := { d.tx with phase := .Finished } } = d := by
        cases d with
        | mk _ tx _ => cases tx; simp_all
      simp [hrest]
  | Active =>
      simp only [bind_ok]
      apply WP.spec_bind
        (assoc_index CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey d.tx.views m
          (fun a => key_same a m))
      intro idx hidx
      cases idx with
      | none =>
          have hmiss : find d.tx.views.val m = none := hidx
          have hrest : { d with tx := { d.tx with phase := .Active } } = d := by
            cases d with
            | mk _ tx _ => cases tx; simp_all
          simp [core.option.Option.is_none, hmiss, hrest]
      | some i =>
          obtain ⟨view, _, hfind⟩ := hidx
          simp only [core.option.Option.is_none, Option.isNone_some, Bool.false_eq_true, ite_false]
          let w : CcfKv.engine.Write := match v with | some val => .Put val | none => .Remove
          have hfrom : CcfKv.engine.Write.from_option v = .ok w := by
            cases v <;> rfl
          rw [hfrom, bind_ok]
          have hstage
              : ∃ nextP,
                  CcfKv.engine.stage_write d.tx.pending { map := m, key := k } w
                  = .ok nextP := by
            have hspec :=
              stage_write_by_key_refines d.tx.pending { map := m, key := k } w hSorted
                hRoom
            cases hres : CcfKv.engine.stage_write d.tx.pending { map := m, key := k } w
              using Result.cases with
            | ret nextP => exact ⟨nextP, rfl⟩
            | vis _ _ => rw [hres] at hspec; simp at hspec
            | div => rw [hres] at hspec; simp at hspec
          obtain ⟨nextP, hnextP⟩ := hstage
          rw [hnextP, bind_ok, WP.spec_ok]
          refine ⟨rfl, rfl, ?_⟩
          simp only [hfind, true_and]
          have hgetRef : CcfKv.engine.Assoc.get_ref CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              d.tx.views m = .ok (some view) := by
            have hspec := assoc_get_ref CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey d.tx.views m
              (fun a => key_same a m)
            cases hres
                  : CcfKv.engine.Assoc.get_ref CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                      d.tx.views m
              using Result.cases with
            | ret o =>
                rw [hres, WP.spec_ok, hfind] at hspec
                rw [hspec]
            | vis _ _ => rw [hres] at hspec; simp at hspec
            | div => rw [hres] at hspec; simp at hspec
          simp [hgetRef, hnextP]

/-- `DetachedTx.finish` matches `lifecycleCommitVersion` identically to `Store.finish`
without borrowing `Store`. -/
theorem detached_finish_matches (d : CcfKv.engine.DetachedTx)
    (outcome : CcfKv.engine.Outcome)
    : WP.spec (CcfKv.engine.DetachedTx.finish d outcome)
        (fun (res, after) =>
          match lifecycleCommitVersion d.tx outcome with
          | none => res = .Err .Disabled ∧ after = d
          | some v =>
              res = .Ok (.Committed outcome v)
              ∧ after = { d with tx := { d.tx with phase := .Finished } }) := by
  unfold CcfKv.engine.DetachedTx.finish lifecycleCommitVersion
  cases hp : d.tx.phase <;> cases outcome <;>
    simp [alloc.vec.Vec.is_empty]
  by_cases hw : d.tx.pending.val = []
  · cases hu : d.tx.unavailable <;> simp [hw]
  · simp [hw]

/-- `Store.end_detached` releases `d.tx`'s pinned roots, erases `d.id`'s metadata stub
from `s.txs`, prunes unneeded retained frames, and retires freed radix nodes while
preserving `IndexLiveness`, `IndexPreservesPins`, and `HistoryIndexValid`. -/
theorem detached_end_refines (s : CcfKv.engine.Store) (d : CcfKv.engine.DetachedTx)
    (otherPins : List U32) (baseFrame : CcfKv.engine.Frame)
    (hbase0 : s.history.activeFrames[0]? = some baseFrame)
    (valid : BranchValid s.history.log)
    (idxValid : HistoryIndexValid s.history)
    (live
      : IndexLiveness s.history.index
          (txPins d.tx ++ (framePins s.history.activeFrames ++ otherPins)))
    (queueRoom
      : 2
            * (s.history.index.values.dirs.val.length
                + s.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.end_detached s d)
        (fun (afterStore, afterTx) =>
          afterStore.history.log = s.history.log
          ∧ afterStore.history.global = s.history.global
          ∧ afterStore.history.term = s.history.term
          ∧ afterStore.history.next_identity = s.history.next_identity
          ∧ afterStore.history.reuse_compacted_images = s.history.reuse_compacted_images
          ∧ afterTx.registered = false
          ∧ afterTx.tx.views.val = []
          ∧ IndexLiveness afterStore.history.index
              (framePins afterStore.history.activeFrames ++ otherPins)
          ∧ IndexPreservesPins s.history.index afterStore.history.index
              (framePins afterStore.history.activeFrames ++ otherPins)
          ∧ HistoryIndexValid afterStore.history
          ∧ (∀ f ∈ afterStore.history.retained.val, f ∈ s.history.retained.val)
          ∧ (d.registered = true
              → afterStore.txs.val = erase s.txs.val d.id
                ∧ ∀ f ∈ s.history.retained.val,
                    f ∈ afterStore.history.retained.val
                    ∨ CcfKv.engine.txs_need_frame afterStore.txs f baseFrame
                      = .ok false)) := by
  unfold CcfKv.engine.Store.end_detached
  let restPins := framePins s.history.activeFrames ++ otherPins
  apply WP.spec_bind
    (release_tx_pins_refines s.history.index d.tx restPins live queueRoom)
  intro ai ⟨haiVals, haiLive⟩
  simp only [CcfKv.engine.Assoc.new, bind_ok]
  have hmid : WP.spec
      (if d.registered then do
        let a2 ← CcfKv.engine.erase_attempt s.txs d.id
        let h1 ← CcfKv.engine.History.prune_retained { s.history with index := ai } a2
        Result.ok (h1, a2, false)
      else Result.ok ({ s.history with index := ai }, s.txs, d.registered))
      (fun (h, txs', reg') =>
        h.log = s.history.log
        ∧ h.index = ai
        ∧ h.global = s.history.global
        ∧ h.term = s.history.term
        ∧ h.next_identity = s.history.next_identity
        ∧ h.reuse_compacted_images = s.history.reuse_compacted_images
        ∧ reg' = false
        ∧ (∀ f ∈ h.retained.val, f ∈ s.history.retained.val)
        ∧ (d.registered = true →
            txs'.val = erase s.txs.val d.id
            ∧ ∀ f ∈ s.history.retained.val,
                f ∈ h.retained.val
                ∨ CcfKv.engine.txs_need_frame txs' f baseFrame = .ok false)) := by
    cases hreg : d.registered with
    | false =>
        simp [WP.spec_ok]
    | true =>
        simp only [↓reduceIte]
        apply WP.spec_bind (erase_attempt_matches s.txs d.id)
        intro txs' htxs'
        apply WP.spec_bind
          (history_prune_retained_refines { s.history with index := ai } txs' baseFrame hbase0 valid)
        rintro h ⟨hlog, hidx, hgl, htm, hid, hre, hsub, hdone⟩
        rw [WP.spec_ok]
        exact ⟨hlog, hidx, hgl, htm, hid, hre, rfl, hsub, fun _ => ⟨htxs', hdone⟩⟩
  apply WP.spec_bind hmid
  rintro ⟨h, txs', reg'⟩ ⟨hlog, hidx, hgl, htm, hid, hre, hreg', hretSub, hregSpec⟩
  have haiQueue : 2 * (ai.values.dirs.val.length + ai.values.rows.val.length) + 1 ≤ Usize.max := by
    rw [haiVals]; exact queueRoom
  have hretSpec : WP.spec
      (CcfKv.kv_index.AddressIndex.retire_budget h.index CcfKv.engine.RETIRE_BUDGET)
      (fun (_, ai1) =>
        IndexLiveness ai1 restPins
        ∧ IndexPreservesPins ai ai1 restPins
        ∧ ai1.values.dirs.val.length = ai.values.dirs.val.length
        ∧ ai1.values.rows.val.length = ai.values.rows.val.length) := by
    rw [hidx]
    exact index_retire_budget_refines ai restPins CcfKv.engine.RETIRE_BUDGET haiLive haiQueue
  apply WP.spec_bind hretSpec
  rintro ⟨_, ai1⟩ ⟨hai1Live, hai1Pres, _, _⟩
  change WP.spec (Result.ok _) _
  rw [WP.spec_ok]
  have hactEq : ({ h with index := ai1 } : CcfKv.engine.History).activeFrames = s.history.activeFrames := by
    unfold CcfKv.engine.History.activeFrames; rw [hlog]
  have hkeptAi : IndexPreservesPins s.history.index ai restPins := by
    intro root _ bindings hview
    refine ⟨⟨by rw [haiVals]; exact hview.lookup, by rw [haiVals]; exact hview.values,
      hview.sorted⟩, ?_⟩
    simp [singleBindings, haiVals]
  have hpres : IndexPreservesPins s.history.index ai1 restPins := hkeptAi.trans hai1Pres
  refine ⟨
    hlog,
    hgl,
    htm,
    hid,
    hre,
    hreg',
    rfl,
    by simpa only [hactEq] using hai1Live,
    by simpa only [hactEq] using hpres,
    idxValid.of_preserves_pins hai1Live.valid (by simpa only [hactEq] using hpres)
      (fun f' hf' => Or.inr ⟨f', hactEq ▸ hf', rfl⟩)
      (fun rf hrf => idxValid.retainedEmpty rf (hretSub rf hrf)),
    hretSub,
    hregSpec
  ⟩

/-- Reserving a placeholder frame retains `head.data`, appends `{head with version := head.version + 1}`,
and preserves `BranchValid`, `HistoryIndexValid`, `IndexLiveness`, and `IndexKeeps`. -/
theorem reserve_placeholder_refines (s : CcfKv.engine.Store) (extraPins : List U32)
    (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (hframes : s.history.activeFrames = prior ++ [head])
    (hver : head.version.val < U64.max)
    (valid : BranchValid s.history.log)
    (idxValid : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (framePins s.history.activeFrames ++ extraPins))
    (refRoom
      : (framePins s.history.activeFrames ++ extraPins).length
          + 17 * s.history.index.values.dirs.val.length
          + 1
        ≤ U32.max)
    (ringRoom
      : s.history.log.len.val = s.history.log.slots.val.length
        → 2 * s.history.log.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.reserve_placeholder_ccf s)
        (fun (res, after) =>
          ∃ v next,
            res = .Ok v
            ∧ v.val = head.version.val + 1
            ∧ next = { head with version := v }
            ∧ after.history.activeFrames = s.history.activeFrames ++ [next]
            ∧ after.history.retained = s.history.retained
            ∧ after.history.global = s.history.global
            ∧ after.history.term = s.history.term
            ∧ after.history.next_identity = s.history.next_identity
            ∧ after.txs = s.txs
            ∧ BranchValid after.history.log
            ∧ HistoryIndexValid after.history
            ∧ IndexLiveness after.history.index
                (framePins after.history.activeFrames ++ extraPins)
            ∧ IndexKeeps s.history.index after.history.index) := by
  unfold CcfKv.engine.Store.reserve_placeholder_ccf
  rw [history_head s.history prior head hframes valid, bind_ok]
  have hmax : core.num.U64.MAX.val = U64.max := by rw [U64.max_eq]; rfl
  have hne : head.version ≠ core.num.U64.MAX := fun h => by
    have := congrArg UScalar.val h; omega
  rw [ite_eq_right hne]
  have hone : (1#u64 : U64).val = 1 := rfl
  apply WP.spec_bind (U64.add_spec (x := head.version) (y := 1#u64) (by omega))
  intro v hv
  have hvVal : v.val = head.version.val + 1 := by omega
  rw [clone_assoc, bind_ok, clone_assoc, bind_ok]
  let pins0 := framePins s.history.activeFrames ++ extraPins
  have hheadMem : head ∈ s.history.activeFrames := by simp [hframes]
  have hrootRef : head.data ≠ 0#u32 →
      SingleLinkLive s.history.index.values.dirs.val s.history.index.values.rows.val head.data
      ∧ radixReferences s.history.index.values.dirs.val pins0 head.data > 0 := by
    intro hnz
    have hmem : head.data ∈ pins0 :=
      List.mem_append_left extraPins (List.mem_filterMap.mpr ⟨head, hheadMem, by simp [hnz]⟩)
    refine ⟨live.pinsLive head.data hmem, ?_⟩
    rw [radixReferences_eq]
    exact List.count_pos_iff.mpr (List.mem_append_left _ hmem)
  have hroomRef : head.data ≠ 0#u32 →
      radixReferences s.history.index.values.dirs.val pins0 head.data < U32.max := by
    intro _
    have h1 := owners_count_le_bound s.history.index.values.dirs.val pins0 head.data
    have h2 : pins0.length + 17 * s.history.index.values.dirs.val.length + 1 ≤ U32.max := refRoom
    rw [radixReferences_eq]
    omega
  apply WP.spec_bind
    (index_retain_root_refines s.history.index pins0 head.data live hrootRef hroomRef)
  intro ai ⟨hvals, haiLive⟩
  let next : CcfKv.engine.Frame := { head with version := v }
  apply WP.spec_bind (branch_append_refines s.history.log next valid ringRoom)
  rintro bl ⟨hblValid, hblVals⟩
  rw [WP.spec_ok]
  have hactAfter : branchValues bl = s.history.activeFrames ++ [next] := hblVals
  have hpinsPerm : (if head.data = 0#u32 then pins0 else head.data :: pins0).Perm
      (framePins (branchValues bl) ++ extraPins) := by
    rw [hactAfter]
    have hfp := (framePins_append s.history.activeFrames next).append_right extraPins
    have hnd : next.data = head.data := rfl
    rw [hnd] at hfp
    by_cases hz : head.data = 0#u32
    · simp only [hz, ↓reduceIte, pins0] at hfp ⊢
      exact hfp.symm
    · simp only [hz, ↓reduceIte, pins0] at hfp ⊢
      exact hfp.symm
  have hk : IndexKeeps s.history.index ai := by unfold IndexKeeps; rw [hvals]; exact .refl _
  refine ⟨v, next, rfl, hvVal, rfl, hactAfter, rfl, rfl, rfl, rfl, rfl, hblValid,
    ⟨haiLive.valid, ?_, idxValid.retainedEmpty⟩, haiLive.perm hpinsPerm, hk⟩
  intro f hf
  change f ∈ branchValues bl at hf
  rw [hactAfter] at hf
  have hview0 : IndexView s.history.index f.data (indexRows s.history.index f.data) := by
    rcases List.mem_append.mp hf with hold | hnew
    · exact idxValid.active f hold
    · rw [List.mem_singleton.mp hnew]
      exact idxValid.active head hheadMem
  have hview1 := index_keeps_view hk f.data (indexRows s.history.index f.data) hview0
  rwa [index_rows_eq hview1]

private theorem get_bytes_loop0_refines (buf : Array U8 256#usize)
    (lenBytes : Array U8 8#usize)
    : WP.spec (CcfKv.kv_index.AddressIndex.get_bytes_loop0 buf lenBytes 0#usize)
        (fun out => out.val.take 8 = lenBytes.val) := by
  unfold CcfKv.kv_index.AddressIndex.get_bytes_loop0
  apply loop.spec_decr_nat
    (fun st : Array U8 256#usize × Usize => 8 - st.2.val)
    (fun st =>
      st.2.val ≤ 8
      ∧ ∀ j, j < st.2.val → st.1.val[j]? = lenBytes.val[j]?) _ _ _
  · rintro ⟨b, i⟩ ⟨hiLe, hmatch⟩
    dsimp only at hiLe hmatch ⊢
    unfold CcfKv.kv_index.AddressIndex.get_bytes_loop0.body
    by_cases hlt : i < 8#usize
    · have hiLt : i.val < 8 := hlt
      rw [ite_eq_left hlt]
      have hlen8 : lenBytes.length = 8 := lenBytes.property
      have hlen256 : b.length = 256 := b.property
      have hlen8v : lenBytes.val.length = 8 := lenBytes.property
      have hlen256v : b.val.length = 256 := b.property
      apply WP.spec_bind (Array.index_usize_spec lenBytes i (by omega))
      intro byte hbyte
      apply WP.spec_bind (Array.update_spec b i byte (by omega))
      intro b1 hb1
      have hb1Val : b1.val = b.val.set i.val byte := by
        rw [hb1]; exact Array.set_val_eq _ _ _
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by scalar_tac))
      intro i1 hi1
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, ?_⟩, by omega⟩
      intro j hj
      rw [hb1Val]
      by_cases hji : j = i.val
      · subst hji
        rw [List.getElem?_set_self (by omega), List.getElem?_eq_getElem (by omega), hbyte]
      · rw [List.getElem?_set_ne (by omega)]
        exact hmatch j (by omega)
    · have hi8 : i.val = 8 := by have : ¬ i.val < 8 := hlt; omega
      rw [ite_eq_right hlt, WP.spec_ok]
      apply List.ext_getElem?
      intro j
      by_cases hj : j < 8
      · rw [List.getElem?_take_of_lt hj]
        exact hmatch j (by omega)
      · have hlen8 : lenBytes.val.length = 8 := lenBytes.property
        rw [List.getElem?_eq_none (by simp; omega), List.getElem?_eq_none (by omega)]
  · refine ⟨by change (0#usize : Usize).val ≤ 8; decide, ?_⟩
    intro j hj
    have h0 : (0#usize : Usize).val = 0 := rfl
    change j < (0#usize : Usize).val at hj
    omega

private theorem get_bytes_loop1_refines (map : Slice U8) (buf : Array U8 256#usize)
    (hfit : map.val.length ≤ 248)
    : WP.spec (CcfKv.kv_index.AddressIndex.get_bytes_loop1 map buf 0#usize)
        (fun out =>
          out.val.take 8 = buf.val.take 8
          ∧ (out.val.drop 8).take map.val.length = map.val) := by
  unfold CcfKv.kv_index.AddressIndex.get_bytes_loop1
  apply loop.spec_decr_nat
    (fun st : Array U8 256#usize × Usize => map.val.length - st.2.val)
    (fun st =>
      st.2.val ≤ map.val.length
      ∧ st.1.val.take 8 = buf.val.take 8
      ∧ ∀ j, j < st.2.val → st.1.val[8 + j]? = map.val[j]?) _ _ _
  · rintro ⟨b, m⟩ ⟨hmLe, hpre, hmatch⟩
    dsimp only at hmLe hpre hmatch ⊢
    unfold CcfKv.kv_index.AddressIndex.get_bytes_loop1.body
    have hmlen : (Slice.len map).val = map.val.length := Slice.len_val _
    have hblen : b.length = 256 := b.property
    have hblenv : b.val.length = 256 := b.property
    by_cases hlt : m < Slice.len map
    · have hmLt : m.val < map.val.length := by rwa [← hmlen]
      rw [ite_eq_left hlt]
      apply WP.spec_bind (Slice.index_usize_spec map m hmLt)
      intro byte hbyte
      have h8 : (8#usize : Usize).val = 8 := rfl
      apply WP.spec_bind (Usize.add_spec (x := 8#usize) (y := m) (by scalar_tac))
      intro idx hidx
      apply WP.spec_bind (Array.update_spec b idx byte (by omega))
      intro b1 hb1
      have hb1Val : b1.val = b.val.set idx.val byte := by
        rw [hb1]; exact Array.set_val_eq _ _ _
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := m) (y := 1#usize) (by scalar_tac))
      intro m1 hm1
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, ?_, ?_⟩, by omega⟩
      · apply List.ext_getElem?
        intro j
        by_cases hj : j < 8
        · rw [List.getElem?_take_of_lt hj, List.getElem?_take_of_lt hj, hb1Val,
            List.getElem?_set_ne (by omega)]
          have := congrArg (fun l => l[j]?) hpre
          simpa [List.getElem?_take_of_lt hj] using this
        · rw [List.getElem?_eq_none (by simp; omega), List.getElem?_eq_none (by simp; omega)]
      · intro j hj
        rw [hb1Val]
        by_cases hjm : j = m.val
        · have heq : idx.val = 8 + j := by omega
          rw [← heq, List.getElem?_set_self (by omega), hjm, List.getElem?_eq_getElem hmLt, hbyte]
        · rw [List.getElem?_set_ne (by omega)]
          exact hmatch j (by omega)
    · have hmEq : m.val = map.val.length := by
        have : ¬ m.val < map.val.length := by rwa [← hmlen]
        omega
      rw [ite_eq_right hlt, WP.spec_ok]
      refine ⟨hpre, ?_⟩
      apply List.ext_getElem?
      intro j
      by_cases hj : j < map.val.length
      · rw [List.getElem?_take_of_lt hj, List.getElem?_drop]
        exact hmatch j (by omega)
      · rw [List.getElem?_eq_none (by simp; omega), List.getElem?_eq_none (by omega)]
  · refine ⟨Nat.zero_le _, rfl, ?_⟩
    intro j hj
    have h0 : (0#usize : Usize).val = 0 := rfl
    change j < (0#usize : Usize).val at hj
    omega

private theorem get_bytes_loop2_refines (key : Slice U8) (buf : Array U8 256#usize)
    (base : Usize) (hfit : base.val + key.val.length ≤ 256)
    : WP.spec (CcfKv.kv_index.AddressIndex.get_bytes_loop2 key buf base 0#usize)
        (fun out =>
          out.val.take base.val = buf.val.take base.val
          ∧ (out.val.drop base.val).take key.val.length = key.val) := by
  unfold CcfKv.kv_index.AddressIndex.get_bytes_loop2
  apply loop.spec_decr_nat
    (fun st : Array U8 256#usize × Usize => key.val.length - st.2.val)
    (fun st =>
      st.2.val ≤ key.val.length
      ∧ st.1.val.take base.val = buf.val.take base.val
      ∧ ∀ j, j < st.2.val → st.1.val[base.val + j]? = key.val[j]?) _ _ _
  · rintro ⟨b, k⟩ ⟨hkLe, hpre, hmatch⟩
    dsimp only at hkLe hpre hmatch ⊢
    unfold CcfKv.kv_index.AddressIndex.get_bytes_loop2.body
    have hklen : (Slice.len key).val = key.val.length := Slice.len_val _
    have hblen : b.length = 256 := b.property
    have hblenv : b.val.length = 256 := b.property
    by_cases hlt : k < Slice.len key
    · have hkLt : k.val < key.val.length := by rwa [← hklen]
      rw [ite_eq_left hlt]
      apply WP.spec_bind (Slice.index_usize_spec key k hkLt)
      intro byte hbyte
      apply WP.spec_bind (Usize.add_spec (x := base) (y := k) (by scalar_tac))
      intro idx hidx
      apply WP.spec_bind (Array.update_spec b idx byte (by omega))
      intro b1 hb1
      have hb1Val : b1.val = b.val.set idx.val byte := by
        rw [hb1]; exact Array.set_val_eq _ _ _
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_bind (Usize.add_spec (x := k) (y := 1#usize) (by scalar_tac))
      intro k1 hk1
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨by omega, ?_, ?_⟩, by omega⟩
      · apply List.ext_getElem?
        intro j
        by_cases hj : j < base.val
        · rw [List.getElem?_take_of_lt hj, List.getElem?_take_of_lt hj, hb1Val,
            List.getElem?_set_ne (by omega)]
          have := congrArg (fun l => l[j]?) hpre
          simpa [List.getElem?_take_of_lt hj] using this
        · rw [List.getElem?_eq_none (by simp; omega), List.getElem?_eq_none (by simp; omega)]
      · intro j hj
        rw [hb1Val]
        by_cases hjk : j = k.val
        · have heq : idx.val = base.val + j := by omega
          rw [← heq, List.getElem?_set_self (by omega), hjk, List.getElem?_eq_getElem hkLt, hbyte]
        · rw [List.getElem?_set_ne (by omega)]
          exact hmatch j (by omega)
    · have hkEq : k.val = key.val.length := by
        have : ¬ k.val < key.val.length := by rwa [← hklen]
        omega
      rw [ite_eq_right hlt, WP.spec_ok]
      refine ⟨hpre, ?_⟩
      apply List.ext_getElem?
      intro j
      by_cases hj : j < key.val.length
      · rw [List.getElem?_take_of_lt hj, List.getElem?_drop]
        exact hmatch j (by omega)
      · rw [List.getElem?_eq_none (by simp; omega), List.getElem?_eq_none (by omega)]
  · refine ⟨Nat.zero_le _, rfl, ?_⟩
    intro j hj
    have h0 : (0#usize : Usize).val = 0 := rfl
    change j < (0#usize : Usize).val at hj
    omega

local instance detachedAddressEq : DecidableEq CcfKv.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-- The stack-buffered slice lookup `AddressIndex.get_bytes` returns the exact
same result as `AddressIndex.get` / `Kv.Model.find` on both the 256-byte fast
path and the fallback path. -/
theorem index_get_bytes_refines {V : Type} (index : CcfKv.kv_index.AddressIndex V)
    (root : CcfKv.radix.RadixRoot) (rows : List (CcfKv.engine.Address × V))
    (view : IndexView index root rows) (address : CcfKv.engine.Address)
    (capacity : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec
        (CcfKv.kv_index.AddressIndex.get_bytes index root
          (alloc.vec.Vec.deref address.map) (alloc.vec.Vec.deref address.key))
        (· = Kv.Model.find rows address) := by
  obtain ⟨links, related, projection⟩ := view.witness
  let mapS : Slice U8 := alloc.vec.Vec.deref address.map
  let keyS : Slice U8 := alloc.vec.Vec.deref address.key
  have hml : mapS.val = address.map.val := by simp [mapS, alloc.vec.Vec.deref]
  have hkl : keyS.val = address.key.val := by simp [keyS, alloc.vec.Vec.deref]
  have hfallback :
      WP.spec (do
        let packed ← CcfKv.radix.address_key mapS keyS
        let s := alloc.vec.Vec.deref packed
        let o ← CcfKv.radix.SingleRadix.get index root s
        match o with
        | none => Result.ok none
        | some binding => Result.ok (some binding.value))
        (· = Kv.Model.find rows address) := by
    apply WP.spec_bind (native_address_key mapS keyS (by simpa [hml, hkl] using capacity))
    intro packed hpacked
    apply WP.spec_bind
      (single_get_refines index root (alloc.vec.Vec.deref packed) links related)
    intro found he
    have lookup :
        found = (Kv.Model.find rows address).map
          (fun v => ({ address, value := v } : CcfKv.kv_index.Binding V)) := by
      rw [projection, show (alloc.vec.Vec.deref packed).val = packedAddress address from by
        simpa [alloc.vec.Vec.deref, packedAddress, hml, hkl] using hpacked] at he
      exact he.trans
        (find_projected_with_key rows address packedAddress
          (fun a v => ({ address := a, value := v } : CcfKv.kv_index.Binding V))
          packed_address_injective)
    rw [lookup]
    cases Kv.Model.find rows address <;> simp
  unfold CcfKv.kv_index.AddressIndex.get_bytes
  have hmlen : (Slice.len mapS).val = mapS.val.length := Slice.len_val _
  have hklen : (Slice.len keyS).val = keyS.val.length := Slice.len_val _
  by_cases h1 : Slice.len mapS ≤ 248#usize
  · rw [ite_eq_left h1]
    have hm248 : mapS.val.length ≤ 248 := by rwa [← hmlen]
    have h248 : (248#usize : Usize).val = 248 := rfl
    apply WP.spec_bind (Usize.sub_spec (x := 248#usize) (y := Slice.len mapS) (by omega))
    intro rem hrem
    by_cases h2 : Slice.len keyS ≤ rem
    · rw [ite_eq_left h2]
      have hkFit : keyS.val.length ≤ 248 - mapS.val.length := by
        have : keyS.val.length ≤ rem.val := by rwa [← hklen]
        omega
      let size := UScalar.cast .U64 (Slice.len mapS)
      have sizeVal : size.val = mapS.val.length := by
        unfold size
        rw [UScalar.cast_val_mod_pow_greater_numBits_eq .U64 (Slice.len mapS)
          (by
            simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U64_numBits_eq]
            rcases System.Platform.numBits_eq with h | h <;> simp [h])]
        exact Slice.len_val _
      simp only [lift, bind_ok]
      let lenBytes := core.num.U64.to_le_bytes size
      have hlenBytes : lenBytes.val = addressPrefix mapS.val.length := by
        have bytes := core.num.U64.to_le_bytes.step_spec size
        simp only [lift, WP.spec_ok] at bytes
        have bitEq : size.bv = BitVec.ofNat 64 mapS.val.length := by
          apply BitVec.eq_of_toNat_eq
          change size.val = mapS.val.length % 2 ^ 64
          have small : mapS.val.length < 2 ^ 64 := by omega
          rw [Nat.mod_eq_of_lt small, sizeVal]
        change lenBytes.val = _
        rw [show lenBytes = core.num.U64.to_le_bytes size from rfl, bytes]
        change size.bv.toLEBytes.map (@UScalar.mk .U8) = _
        rw [bitEq]
        rfl
      apply WP.spec_bind (get_bytes_loop0_refines (Array.repeat 256#usize 0#u8) lenBytes)
      intro buf1 hbuf1
      apply WP.spec_bind (get_bytes_loop1_refines mapS buf1 hm248)
      intro buf2 ⟨hbuf2Pre, hbuf2Map⟩
      have h8 : (8#usize : Usize).val = 8 := rfl
      apply WP.spec_bind (Usize.add_spec (x := 8#usize) (y := Slice.len mapS) (by scalar_tac))
      intro base hbase
      apply WP.spec_bind (get_bytes_loop2_refines keyS buf2 base (by omega))
      intro buf3 ⟨hbuf3Pre, hbuf3Key⟩
      apply WP.spec_bind (Usize.add_spec (x := base) (y := Slice.len keyS) (by scalar_tac))
      intro total htotal
      have hsliceSpec : WP.spec
          (core.array.Array.index
            (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeToUsizeSlice U8))
            buf3 { «end» := total })
          (fun s => s.val = packedAddress address) := by
        rw [Array.index_SliceIndexRangeToUsizeSlice]
        have hbuf3Len : buf3.val.length = 256 := buf3.property
        have hle256 : total.val ≤ buf3.to_slice.length := by
          have : buf3.to_slice.length = buf3.val.length := by simp [Array.val_to_slice]
          omega
        apply WP.spec_mono
          (core.slice.index.SliceIndexRangeToUsizeSlice.index.step_spec
            { «end» := total } buf3.to_slice hle256)
        intro s ⟨hsVal, _⟩
        rw [hsVal, Array.val_to_slice, List.slice, List.drop_zero, Nat.sub_zero]
        have htotalVal : total.val = 8 + mapS.val.length + keyS.val.length := by omega
        have hbaseVal : base.val = 8 + mapS.val.length := by omega
        have hpart1 : buf3.val.take 8 = addressPrefix mapS.val.length := by
          have h1 : buf3.val.take 8 = (buf3.val.take base.val).take 8 := by
            rw [List.take_take, Nat.min_eq_left (by omega)]
          rw [h1, hbuf3Pre, List.take_take, Nat.min_eq_left (by omega), hbuf2Pre, hbuf1, hlenBytes]
        have hpart2 : (buf3.val.drop 8).take mapS.val.length = mapS.val := by
          have h1 : (buf3.val.take base.val).drop 8 = (buf3.val.drop 8).take mapS.val.length := by
            rw [List.drop_take]; congr 1; omega
          rw [← h1, hbuf3Pre, List.drop_take, show base.val - 8 = mapS.val.length by omega,
            hbuf2Map]
        have hsplit : buf3.val.take total.val =
            buf3.val.take 8 ++ (buf3.val.drop 8).take mapS.val.length
              ++ (buf3.val.drop base.val).take keyS.val.length := by
          have htake1 : buf3.val.take total.val =
              buf3.val.take base.val ++ (buf3.val.drop base.val).take keyS.val.length := by
            rw [← List.take_add, show base.val + keyS.val.length = total.val by omega]
          have htake2 : buf3.val.take base.val =
              buf3.val.take 8 ++ (buf3.val.drop 8).take mapS.val.length := by
            rw [← List.take_add, show 8 + mapS.val.length = base.val by omega]
          rw [htake1, htake2]
        rw [hpart1, hpart2, hbuf3Key] at hsplit
        simpa only [packedAddress, addressBytes, hml, hkl] using hsplit
      apply WP.spec_bind hsliceSpec
      intro s hs
      apply WP.spec_bind (single_get_refines index root s links related)
      intro found he
      have lookup :
          found = (Kv.Model.find rows address).map
            (fun v => ({ address, value := v } : CcfKv.kv_index.Binding V)) := by
        rw [projection, hs] at he
        exact he.trans
          (find_projected_with_key rows address packedAddress
            (fun a v => ({ address := a, value := v } : CcfKv.kv_index.Binding V))
            packed_address_injective)
      rw [lookup]
      cases Kv.Model.find rows address <;> simp
    · rw [ite_eq_right h2]
      exact hfallback
  · rw [ite_eq_right h1]
    exact hfallback

/-- `Store.readonly_pins` selects the exact same `(local, global)` pinned images as
`pin_maps` without retaining roots, and reports the exact nonzero root IDs `(r0, r1)`
that external hazard slots must keep alive. -/
theorem readonly_pins_matches (reuse : Bool) (snapVer globalVer : U64)
    (localData globalData : CcfKv.radix.RadixRoot)
    : WP.spec
        (CcfKv.engine.Store.readonly_pins reuse snapVer globalVer localData globalData)
        (fun (loc, glob, r0, r1) =>
          [r0, r1].filter (· != 0#u32)
            = pinPins loc
              ++ (match glob with
                  | none => []
                  | some g => pinPins g)
          ∧ (∀ r ∈ [r0, r1].filter (· != 0#u32), r = localData ∨ r = globalData)
          ∧ (reuse = true ∧ snapVer.val < globalVer.val
              → loc = .Root globalData ∧ glob = none)
          ∧ (¬(reuse = true ∧ snapVer.val < globalVer.val) ∧ snapVer = globalVer
              → loc = .Root localData ∧ glob = none)
          ∧ (¬(reuse = true ∧ snapVer.val < globalVer.val) ∧ snapVer ≠ globalVer
              → loc = .Root localData ∧ glob = some (.Root globalData))) := by
  unfold CcfKv.engine.Store.readonly_pins
  cases reuse with
  | false =>
      simp only [Bool.false_eq_true, ↓reduceIte, false_and, not_false_eq_true, true_and]
      by_cases heq : snapVer = globalVer
      · rw [ite_eq_left heq, WP.spec_ok]
        by_cases hz : localData = 0#u32 <;> simp [pinPins, hz, heq]
      · rw [ite_eq_right heq, WP.spec_ok]
        by_cases hl : localData = 0#u32 <;> by_cases hg : globalData = 0#u32 <;>
          simp [pinPins, hl, hg, heq]
  | true =>
      simp only [↓reduceIte, true_and]
      by_cases hlt : snapVer < globalVer
      · have hltVal : snapVer.val < globalVer.val := hlt
        have hne : snapVer ≠ globalVer := fun h => by subst h; omega
        rw [ite_eq_left hlt, WP.spec_ok]
        by_cases hg : globalData = 0#u32 <;> simp [pinPins, hg, hltVal, hne]
      · have hgeVal : ¬(snapVer.val < globalVer.val) := hlt
        rw [ite_eq_right hlt]
        by_cases heq : snapVer = globalVer
        · rw [ite_eq_left heq, WP.spec_ok]
          by_cases hl : localData = 0#u32 <;> simp [pinPins, hl, heq]
        · rw [ite_eq_right heq, WP.spec_ok]
          by_cases hl : localData = 0#u32 <;> by_cases hg : globalData = 0#u32 <;>
            simp [pinPins, hl, hg, hgeVal, heq]

/-- `Store.snapshot_and_acquire_readonly` borrows `&Store` immutably, captures the
head snapshot if unset, evaluates the exact same cut-resolution and availability
checks as `Acquire`, and returns `(snap.version, snap.term, out, r0, r1)` where
`[r0, r1].filter (· != 0)` equals the exact `viewPins` of any newly acquired view. -/
theorem snapshot_and_acquire_readonly_refines (s : CcfKv.engine.Store)
    (d : CcfKv.engine.DetachedTx) (map : CcfKv.engine.Bytes)
    (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (baseFrame : CcfKv.engine.Frame)
    (hframes : s.history.activeFrames = prior ++ [head])
    (hbase0 : s.history.activeFrames[0]? = some baseFrame)
    (hbaseLeGlobal : baseFrame.version.val ≤ s.history.global.val)
    (hrec : s.recovery_views.val = [])
    (hactive : d.tx.phase = .Active)
    (hunreg : d.registered = false)
    (hmissing : find d.tx.views.val map = none)
    (hviewRoom : d.tx.views.val.length < Usize.max)
    (valid : BranchValid s.history.log)
    : WP.spec (CcfKv.engine.Store.snapshot_and_acquire_readonly s d map)
        (fun (res, after) =>
          let snap :=
            d.tx.snapshot.getD { version := head.version, term := s.history.term }
          after.id = d.id
          ∧ after.registered = false
          ∧ after.tx.snapshot = some snap
          ∧ after.tx.phase = .Active
          ∧ match res with
            | .Err _ => False
            | .Ok (sv, st, out, r0, r1) =>
                sv = snap.version
                ∧ st = snap.term
                ∧ match out with
                  | .Unavailable =>
                      r0 = 0#u32
                      ∧ r1 = 0#u32
                      ∧ after.tx.unavailable = true
                      ∧ after.tx.views = d.tx.views
                  | .Acquired locRev globRev =>
                      ∃ v,
                        after.tx.views.val = (map, v) :: erase d.tx.views.val map
                        ∧ [r0, r1].filter (· != 0#u32) = viewPins v
                        ∧ v.revision.version = locRev
                        ∧ (∀ r ∈ viewPins v,
                            ∃ f ∈ s.history.activeFrames ++ s.history.retained.val,
                              f.data = r)
                        ∧ (v.birth = none
                            → locRev = 0#u64 ∧ globRev = 0#u64 ∧ viewPins v = [])
                  | _ => False) := by
  unfold CcfKv.engine.Store.snapshot_and_acquire_readonly
  rw [hactive, hunreg]
  simp only [↓reduceIte, Bool.false_eq_true, bind_ok]
  let snap : CcfKv.engine.Snapshot :=
    d.tx.snapshot.getD { version := head.version, term := s.history.term }
  have hsnapStep : WP.spec
      (if core.option.Option.is_none d.tx.snapshot then do
          let f ← CcfKv.engine.History.head s.history
          Result.ok (s, some ({ version := f.version, term := s.history.term } : CcfKv.engine.Snapshot))
        else Result.ok (s, d.tx.snapshot))
      (fun (s1, o) => s1 = s ∧ o = some snap) := by
    cases hs : d.tx.snapshot with
    | none =>
        simp only [core.option.Option.is_none, Option.isNone_none, ↓reduceIte, snap, hs, Option.getD_none]
        rw [history_head s.history prior head hframes valid, bind_ok, WP.spec_ok]
        exact ⟨rfl, rfl⟩
    | some sn =>
        simp [core.option.Option.is_none, snap, hs]
  apply WP.spec_bind hsnapStep
  rintro ⟨s1, o⟩ ⟨hs1, ho⟩
  subst s1; subst ho
  apply WP.spec_bind
    (assoc_index CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey d.tx.views map
      (fun a => key_same a map))
  intro idx hidx
  have hidxNone : idx = none := by
    cases idx with
    | none => rfl
    | some i =>
        obtain ⟨_, _, hfind⟩ := hidx
        rw [hmissing] at hfind
        cases hfind
  subst hidxNone
  simp only [core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  apply WP.spec_bind (history_resolve_cut s.history snap.version baseFrame hbase0 valid)
  intro cutRef hcutRef
  cases cutRef with
  | none =>
      rw [WP.spec_ok]
      exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
  | some localRef =>
      have hrecNone : CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.RecoveryView.Insts.CoreCloneClone
          s.recovery_views map = .ok none := by
        have hgs := assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.RecoveryView.Insts.CoreCloneClone
          s.recovery_views map (fun a => key_same a map)
          (fun rv => by
            cases rv
            simp [CcfKv.engine.RecoveryView.Insts.CoreCloneClone.clone, clone_assoc, lift])
        cases hres
              : CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone
                  CcfKv.engine.RecoveryView.Insts.CoreCloneClone s.recovery_views map
          using Result.cases with
        | vis _ _ => rw [hres] at hgs; simp at hgs
        | div => rw [hres] at hgs; simp at hgs
        | ret o =>
            rw [hres, WP.spec_ok, hrec] at hgs
            simpa [find] using hgs
      dsimp only
      rw [hrecNone, bind_ok]
      have hreadSpec : ∃ localFrame,
          WP.spec (CcfKv.engine.History.read_cut s.history localRef) (· = localFrame)
          ∧ localFrame ∈ s.history.activeFrames ++ s.history.retained.val := by
        cases localRef with
        | Active off =>
            by_cases hlt : snap.version.val < baseFrame.version.val
            · simp [hlt] at hcutRef
            · simp only [hlt, ↓reduceIte] at hcutRef
              obtain ⟨idx', hidxEq, hidxVal⟩ := hcutRef
              cases hidxEq
              have hoffLt : off.val < s.history.activeFrames.length := by
                have hpos : 0 < s.history.activeFrames.length := by
                  rw [hframes, List.length_append]; simp
                omega
              let f := s.history.activeFrames[off.val]
              have hf : s.history.activeFrames[off.val]? = some f := List.getElem?_eq_getElem hoffLt
              refine ⟨f, history_read_cut_active s.history off f valid hf, ?_⟩
              exact List.mem_append_left _ (List.mem_of_getElem? hf)
        | Retained ridx =>
            by_cases hlt : snap.version.val < baseFrame.version.val
            · simp only [hlt, ↓reduceIte] at hcutRef
              obtain ⟨f, hf, _⟩ := hcutRef
              refine ⟨f, history_read_cut_retained s.history ridx f hf, ?_⟩
              exact List.mem_append_right _ (List.mem_of_getElem? hf)
            · simp only [hlt, ↓reduceIte] at hcutRef
              obtain ⟨_, hcontra, _⟩ := hcutRef
              cases hcontra
      obtain ⟨localFrame, hreadLocal, hlocalMem⟩ := hreadSpec
      apply WP.spec_bind hreadLocal
      intro lf hlf; rw [hlf]
      apply WP.spec_bind
        (assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
          localFrame.births map (fun a => key_same a map)
          (fun st => by simp [CcfKv.engine.Stamp.Insts.CoreCloneClone.clone]))
      intro birth hbirth
      cases birth with
      | none =>
          simp only [core.option.Option.is_none]
          have hzero : CcfKv.engine.Stamp.zero = .ok { version := 0#u64, identity := 0#u64 } := rfl
          rw [hzero, bind_ok]
          let vEmpty : CcfKv.engine.View :=
            { birth := none, revision := { version := 0#u64, identity := 0#u64 },
              «local» := .Empty, global := none }
          apply WP.spec_bind
            (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone
              CcfKv.engine.View.Insts.CoreCloneClone d.tx.views map vEmpty
              (fun a => key_same a map) clone_bytes clone_view hviewRoom)
          intro views1 hviews1
          rw [WP.spec_ok]
          refine ⟨
            rfl,
            rfl,
            rfl,
            rfl,
            rfl,
            rfl,
            vEmpty,
            by simpa [Kv.Model.set] using hviews1,
            ?_,
            rfl,
            ?_,
            ?_
          ⟩
          · simp [vEmpty, viewPins, pinPins]
          · intro r hr; simp [vEmpty, viewPins, pinPins] at hr
          · intro _; simp [vEmpty, viewPins, pinPins]
      | some bStamp =>
          simp only [core.option.Option.is_none]
          have hrelSpec : WP.spec (CcfKv.engine.History.relative_cut s.history s.history.global)
              (fun i => i.val = s.history.global.val - baseFrame.version.val) := by
            unfold CcfKv.engine.History.relative_cut
            apply WP.spec_bind (branch_active_at s.history.log valid 0#usize baseFrame hbase0)
            intro bf hbf; rw [hbf]
            by_cases hlt : s.history.global < baseFrame.version
            · have : s.history.global.val < baseFrame.version.val := hlt
              omega
            · rw [ite_eq_right hlt]
              apply WP.spec_mono (U64.sub_spec (x := s.history.global) (y := baseFrame.version) (by omega))
              intro diff hd; omega
          apply WP.spec_bind hrelSpec
          intro relOff hrelOff
          apply WP.spec_bind (branch_cut_refines s.history.log valid relOff)
          intro globOff hglobOff
          have hglobLt : globOff.val < s.history.activeFrames.length := by
            have hpos : 0 < s.history.activeFrames.length := by
              rw [hframes, List.length_append]; simp
            rw [CcfKv.engine.History.activeFrames, branch_values_length _ valid] at hpos ⊢
            omega
          let globalFrame := s.history.activeFrames[globOff.val]
          have hglobGet : s.history.activeFrames[globOff.val]? = some globalFrame :=
            List.getElem?_eq_getElem hglobLt
          have hglobMem : globalFrame ∈ s.history.activeFrames ++ s.history.retained.val :=
            List.mem_append_left _ (List.mem_of_getElem? hglobGet)
          apply WP.spec_bind
            (branch_active_at s.history.log valid globOff globalFrame hglobGet)
          intro gf hgf; rw [hgf]
          have hrevSpec (f : CcfKv.engine.Frame) : ∃ rev,
              CcfKv.engine.Frame.revision f map = .ok rev := by
            unfold CcfKv.engine.Frame.revision
            have hgs := assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
              f.revisions map (fun a => key_same a map)
              (fun st => by simp [CcfKv.engine.Stamp.Insts.CoreCloneClone.clone])
            cases hres
                  : CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                      CcfKv.engine.Bytes.Insts.CoreCloneClone
                      CcfKv.engine.Stamp.Insts.CoreCloneClone f.revisions map
              using Result.cases with
            | vis _ _ => rw [hres] at hgs; simp at hgs
            | div => rw [hres] at hgs; simp at hgs
            | ret o =>
                cases o with
                | none =>
                    exact ⟨
                      { version := 0#u64, identity := 0#u64 },
                      by simp [CcfKv.engine.Stamp.zero]
                    ⟩
                | some st => exact ⟨st, by simp⟩
          obtain ⟨locRev, hlocRev⟩ := hrevSpec localFrame
          obtain ⟨globRev, hglobRev⟩ := hrevSpec globalFrame
          rw [hlocRev, bind_ok, hglobRev, bind_ok]
          by_cases hltRev : locRev.version < globRev.version
          · rw [ite_eq_left hltRev, WP.spec_ok]
            exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
          · rw [ite_eq_right hltRev]
            apply WP.spec_bind
              (readonly_pins_matches s.history.reuse_compacted_images snap.version
                s.history.global localFrame.data globalFrame.data)
            rintro ⟨locImg, globImg, r0, r1⟩ ⟨hpins, hfrom, _, _, _⟩
            let vNew : CcfKv.engine.View :=
              { birth := some bStamp, revision := locRev, «local» := locImg, global := globImg }
            apply WP.spec_bind
              (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.View.Insts.CoreCloneClone
                d.tx.views map vNew (fun a => key_same a map) clone_bytes clone_view hviewRoom)
            intro views1 hviews1
            rw [WP.spec_ok]
            refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, vNew, by simpa [Kv.Model.set] using hviews1, hpins, rfl, ?_, ?_⟩
            · intro r hr
              have hr' : r ∈ List.filter (fun x => x != 0#u32) [r0, r1] := by
                rw [hpins]; exact hr
              rcases hfrom r hr' with rfl | rfl
              · exact ⟨localFrame, hlocalMem, rfl⟩
              · exact ⟨globalFrame, hglobMem, rfl⟩
            · intro hnone; cases hnone

/-- Promoting a hazard-pinned `DetachedTx` retains every view root in `d.tx.views`,
registers a metadata-only stub in `s.txs` with identical `tx_needs_frame` behavior
and zero radix pins, and preserves `IndexLiveness`, `IndexKeeps`, and `HistoryIndexValid`. -/
theorem promote_detached_tx_refines (s : CcfKv.engine.Store) (d : CcfKv.engine.DetachedTx)
    (basePins : List U32)
    (hunreg : d.registered = false)
    (hmissing : find s.txs.val d.id = none)
    (htxsRoom : s.txs.val.length < Usize.max)
    (hviewsUnique : (d.tx.views.val.map Prod.fst).Nodup)
    (idxValid : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index basePins)
    (hrootsLive
      : ∀ r ∈ txPins d.tx,
          SingleLinkLive s.history.index.values.dirs.val s.history.index.values.rows.val r
          ∧ radixReferences s.history.index.values.dirs.val basePins r > 0)
    (refRoom
      : basePins.length
          + (txPins d.tx).length
          + 17 * s.history.index.values.dirs.val.length
          + 1
        ≤ U32.max)
    : WP.spec (CcfKv.engine.Store.promote_detached_tx s d)
        (fun (res, afterStore, afterTx) =>
          res = .Ok ()
          ∧ afterTx = { d with registered := true }
          ∧ afterStore.history.log = s.history.log
          ∧ afterStore.history.retained = s.history.retained
          ∧ afterStore.history.global = s.history.global
          ∧ afterStore.history.term = s.history.term
          ∧ afterStore.history.next_identity = s.history.next_identity
          ∧ afterStore.history.reuse_compacted_images = s.history.reuse_compacted_images
          ∧ IndexLiveness afterStore.history.index (txPins d.tx ++ basePins)
          ∧ IndexKeeps s.history.index afterStore.history.index
          ∧ HistoryIndexValid afterStore.history
          ∧ ∃ stub,
              afterStore.txs.val = (d.id, stub) :: erase s.txs.val d.id
              ∧ txPins stub = []
              ∧ ∀ frame globalFrame,
                  CcfKv.engine.tx_needs_frame stub frame globalFrame
                  = CcfKv.engine.tx_needs_frame d.tx frame globalFrame) := by
  unfold CcfKv.engine.Store.promote_detached_tx
  rw [hunreg, ite_eq_right (by decide : ¬false = true)]
  apply WP.spec_bind
    (assoc_index CcfKv.U64.Insts.Ccf_kvEngineKey s.txs d.id (fun _ => rfl))
  intro idx hidx
  have hidxNone : idx = none := by
    cases idx with
    | none => rfl
    | some _ =>
        obtain ⟨_, _, hfind⟩ := hidx
        rw [hmissing] at hfind
        cases hfind
  subst hidxNone
  simp only [core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  rw [tx_new_lifecycle, bind_ok]
  let n := d.tx.views.val.length
  let prePins (k : Nat) : List U32 :=
    (d.tx.views.val.take k).flatMap fun (_, v) => viewPins v
  let strip (row : CcfKv.engine.Bytes × CcfKv.engine.View) : CcfKv.engine.Bytes × CcfKv.engine.View :=
    (row.1, { row.2 with «local» := .Empty, global := none })
  have hloop : WP.spec
      (CcfKv.engine.Store.promote_detached_tx_loop s.history d.tx.views lifecycleNewTx.views 0#usize)
      (fun (h, v, stubViews) =>
        h.log = s.history.log
        ∧ h.retained = s.history.retained
        ∧ h.global = s.history.global
        ∧ h.term = s.history.term
        ∧ h.next_identity = s.history.next_identity
        ∧ h.reuse_compacted_images = s.history.reuse_compacted_images
        ∧ h.index.values = s.history.index.values
        ∧ v = d.tx.views
        ∧ IndexLiveness h.index (txPins d.tx ++ basePins)
        ∧ stubViews.val.Perm (d.tx.views.val.map strip)) := by
    unfold CcfKv.engine.Store.promote_detached_tx_loop
    apply loop.spec_decr_nat (fun (_, _, _, i) => n - i.val)
      (fun (curH, curV, curStub, i) =>
        i.val ≤ n
        ∧ curH.log = s.history.log
        ∧ curH.retained = s.history.retained
        ∧ curH.global = s.history.global
        ∧ curH.term = s.history.term
        ∧ curH.next_identity = s.history.next_identity
        ∧ curH.reuse_compacted_images = s.history.reuse_compacted_images
        ∧ curH.index.values = s.history.index.values
        ∧ curV = d.tx.views
        ∧ IndexLiveness curH.index (prePins i.val ++ basePins)
        ∧ curStub.val.Perm ((d.tx.views.val.take i.val).map strip))
      _ _ _
    · rintro ⟨curH, curV, curStub, i⟩
        ⟨hi, hlog, hret, hgl, htm, hid, hre, hvals, hcurV, hliveCur, hpermCur⟩
      dsimp only at hi hlog hret hgl htm hid hre hvals hcurV hliveCur hpermCur ⊢
      subst curV
      unfold CcfKv.engine.Store.promote_detached_tx_loop.body
      have hlen : (alloc.vec.Vec.len d.tx.views).val = n := alloc.vec.Vec.len_val _
      have hcap := alloc.vec.Vec.len_ineq d.tx.views
      have hone : (1#usize : Usize).val = 1 := rfl
      by_cases hlt : i < alloc.vec.Vec.len d.tx.views
      · have hilt : i.val < n := by rwa [← hlen]
        rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_usize_spec d.tx.views i hilt)
        rintro ⟨m, view⟩ hrow
        have htakeStep : d.tx.views.val.take (i.val + 1) = d.tx.views.val.take i.val ++ [(m, view)] := by
          rw [List.take_add_one, List.getElem?_eq_getElem hilt, ← hrow]
          simp
        have hpreLen : (prePins i.val).length + (viewPins view).length ≤ (txPins d.tx).length := by
          have h1 : (d.tx.views.val.take (i.val + 1)).flatMap (fun p => viewPins p.2)
              = prePins i.val ++ viewPins view := by
            rw [htakeStep, List.flatMap_append]; simp [prePins]
          have h3 : (txPins d.tx).length =
              ((d.tx.views.val.take (i.val + 1)).flatMap (fun p => viewPins p.2)).length
              + ((d.tx.views.val.drop (i.val + 1)).flatMap (fun p => viewPins p.2)).length := by
            unfold txPins
            conv_lhs => rw [← List.take_append_drop (i.val + 1) d.tx.views.val]
            rw [List.flatMap_append, List.length_append]
          rw [h1, List.length_append] at h3
          omega
        have hviewMemTx : (m, view) ∈ d.tx.views.val := by
          rw [hrow]; exact List.getElem_mem hilt
        have hretainPin : ∀ (hIn : CcfKv.engine.History) (pinsIn : List U32) (p : CcfKv.engine.PinnedImage),
            hIn.index.values = s.history.index.values →
            IndexLiveness hIn.index (pinsIn ++ basePins) →
            (∀ r ∈ pinPins p, r ∈ txPins d.tx) →
            pinsIn.length + (pinPins p).length ≤ (txPins d.tx).length →
            WP.spec
              (match p with
                | .Empty => Result.ok hIn
                | .Root root => do
                    let ai ← CcfKv.kv_index.AddressIndex.retain_root hIn.index root
                    Result.ok { hIn with index := ai }
                | .Recovered _ => Result.ok hIn)
              (fun hOut =>
                hOut.log = hIn.log
                ∧ hOut.retained = hIn.retained
                ∧ hOut.global = hIn.global
                ∧ hOut.term = hIn.term
                ∧ hOut.next_identity = hIn.next_identity
                ∧ hOut.reuse_compacted_images = hIn.reuse_compacted_images
                ∧ hOut.index.values = s.history.index.values
                ∧ IndexLiveness hOut.index ((pinPins p ++ pinsIn) ++ basePins)) := by
          intro hIn pinsIn p hInVals hInLive hpSub hpLen
          cases p with
          | Empty =>
              simp [pinPins, hInVals, hInLive]
          | Recovered _ =>
              simp [pinPins, hInVals, hInLive]
          | Root root =>
              have hrootLive : root ≠ 0#u32 →
                  SingleLinkLive hIn.index.values.dirs.val hIn.index.values.rows.val root
                  ∧ radixReferences hIn.index.values.dirs.val (pinsIn ++ basePins) root > 0 := by
                intro hnz
                have hmem : root ∈ txPins d.tx := hpSub root (by simp [pinPins, hnz])
                obtain ⟨hsll, hpos⟩ := hrootsLive root hmem
                rw [hInVals]
                refine ⟨hsll, ?_⟩
                rw [radixReferences_eq] at hpos ⊢
                have hcnt : (basePins ++ arenaEdges s.history.index.values.dirs.val).count root
                    ≤ ((pinsIn ++ basePins) ++ arenaEdges s.history.index.values.dirs.val).count root := by
                  simp only [List.count_append]
                  omega
                omega
              have hrootRoom : root ≠ 0#u32 →
                  radixReferences hIn.index.values.dirs.val (pinsIn ++ basePins) root < U32.max := by
                intro _
                have h1 := owners_count_le_bound hIn.index.values.dirs.val (pinsIn ++ basePins) root
                rw [hInVals] at h1 ⊢
                rw [radixReferences_eq]
                have hlen1 : (pinsIn ++ basePins).length = pinsIn.length + basePins.length :=
                  List.length_append
                have h2 : pinsIn.length ≤ (txPins d.tx).length := by omega
                have h3 : basePins.length + (txPins d.tx).length
                    + 17 * s.history.index.values.dirs.val.length + 1 ≤ U32.max := refRoom
                omega
              apply WP.spec_bind
                (index_retain_root_refines hIn.index (pinsIn ++ basePins) root hInLive
                  hrootLive hrootRoom)
              intro ai ⟨haiVals, haiLive⟩
              rw [WP.spec_ok]
              refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, haiVals.trans hInVals, ?_⟩
              by_cases hz : root = 0#u32
              · simpa [pinPins, hz] using haiLive
              · simpa [pinPins, hz, List.cons_append] using haiLive
        have hlocSub : ∀ r ∈ pinPins view.local, r ∈ txPins d.tx := by
          intro r hr
          exact List.mem_flatMap.mpr ⟨(m, view), hviewMemTx, by
            dsimp only; unfold viewPins; exact List.mem_append_left _ hr⟩
        have hlocLen : (prePins i.val).length + (pinPins view.local).length ≤ (txPins d.tx).length := by
          have : (pinPins view.local).length ≤ (viewPins view).length := by
            unfold viewPins; rw [List.length_append]; omega
          omega
        apply WP.spec_bind
          (hretainPin curH (prePins i.val) view.local hvals hliveCur hlocSub hlocLen)
        rintro h1 ⟨hlog1, hret1, hgl1, htm1, hid1, hre1, hvals1, hlive1⟩
        have hglobStep : WP.spec
            (match view.global with
              | none => Result.ok h1
              | some pi =>
                  match pi with
                  | .Empty => Result.ok h1
                  | .Root root => do
                      let ai ← CcfKv.kv_index.AddressIndex.retain_root h1.index root
                      Result.ok { h1 with index := ai }
                  | .Recovered _ => Result.ok h1)
            (fun h2 =>
              h2.log = h1.log
              ∧ h2.retained = h1.retained
              ∧ h2.global = h1.global
              ∧ h2.term = h1.term
              ∧ h2.next_identity = h1.next_identity
              ∧ h2.reuse_compacted_images = h1.reuse_compacted_images
              ∧ h2.index.values = s.history.index.values
              ∧ IndexLiveness h2.index (prePins (i.val + 1) ++ basePins)) := by
          cases hg : view.global with
          | none =>
              rw [WP.spec_ok]
              refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, hvals1, ?_⟩
              have hperm : ((pinPins view.local ++ prePins i.val) ++ basePins).Perm
                  (prePins (i.val + 1) ++ basePins) := by
                have hvp : viewPins view = pinPins view.local := by simp [viewPins, hg]
                have hpreNext : prePins (i.val + 1) = prePins i.val ++ pinPins view.local := by
                  unfold prePins; rw [htakeStep, List.flatMap_append]; simp [hvp]
                rw [hpreNext]
                exact List.perm_append_comm.append_right basePins
              exact hlive1.perm hperm
          | some gpin =>
              have hgsub : ∀ r ∈ pinPins gpin, r ∈ txPins d.tx := by
                intro r hr
                exact List.mem_flatMap.mpr ⟨(m, view), hviewMemTx, by
                  dsimp only; unfold viewPins; rw [hg]; exact List.mem_append_right _ hr⟩
              have hglen : (pinPins view.local ++ prePins i.val).length + (pinPins gpin).length
                  ≤ (txPins d.tx).length := by
                have hvp : (viewPins view).length = (pinPins view.local).length + (pinPins gpin).length := by
                  unfold viewPins; rw [hg, List.length_append]
                rw [List.length_append]; omega
              apply WP.spec_mono
                (hretainPin h1 (pinPins view.local ++ prePins i.val) gpin hvals1 hlive1
                  hgsub hglen)
              rintro h2 ⟨hl2, hr2, hgl2, htm2, hid2, hre2, hvals2, hlive2⟩
              refine ⟨hl2, hr2, hgl2, htm2, hid2, hre2, hvals2, ?_⟩
              have hperm : ((pinPins gpin ++ (pinPins view.local ++ prePins i.val)) ++ basePins).Perm
                  (prePins (i.val + 1) ++ basePins) := by
                have hvp : viewPins view = pinPins view.local ++ pinPins gpin := by simp [viewPins, hg]
                have hpreNext : prePins (i.val + 1) = prePins i.val ++ (pinPins view.local ++ pinPins gpin) := by
                  unfold prePins; rw [htakeStep, List.flatMap_append]; simp [hvp]
                rw [hpreNext]
                have p1 : (pinPins gpin ++ (pinPins view.local ++ prePins i.val)).Perm
                    (prePins i.val ++ (pinPins view.local ++ pinPins gpin)) := by
                  have a1 : (pinPins gpin ++ (pinPins view.local ++ prePins i.val)).Perm
                      ((pinPins gpin ++ pinPins view.local) ++ prePins i.val) := by
                    rw [List.append_assoc]
                  have a2 : ((pinPins gpin ++ pinPins view.local) ++ prePins i.val).Perm
                      (prePins i.val ++ (pinPins gpin ++ pinPins view.local)) := List.perm_append_comm
                  have a3 : (prePins i.val ++ (pinPins gpin ++ pinPins view.local)).Perm
                      (prePins i.val ++ (pinPins view.local ++ pinPins gpin)) :=
                    List.perm_append_comm.append_left _
                  exact a1.trans (a2.trans a3)
                exact p1.append_right basePins
              exact hlive2.perm hperm
        apply WP.spec_bind hglobStep
        rintro h2 ⟨hlog2, hret2, hgl2, htm2, hid2, hre2, hvals2, hlive2⟩
        rw [clone_bytes, bind_ok]
        have hstubRoom : curStub.val.length < Usize.max := by
          have : curStub.val.length = i.val := by
            rw [hpermCur.length_eq, List.length_map, List.length_take, Nat.min_eq_left hi]
          omega
        apply WP.spec_bind
          (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.View.Insts.CoreCloneClone
            curStub m { view with «local» := .Empty, global := none }
            (fun a => key_same a m) clone_bytes clone_view hstubRoom)
        intro stubNext hstubNext
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
        intro iNext hiNext
        have hiNextVal : iNext.val = i.val + 1 := by omega
        rw [WP.spec_ok]
        dsimp only
        have hnotMemTake : m ∉ (d.tx.views.val.take i.val).map Prod.fst := by
          intro hmem
          have htakeMap : (d.tx.views.val.take (i.val + 1)).map Prod.fst
              = (d.tx.views.val.take i.val).map Prod.fst ++ [m] := by
            rw [htakeStep, List.map_append]; rfl
          have hsubNodup : ((d.tx.views.val.take (i.val + 1)).map Prod.fst).Nodup := by
            have hprefix : (d.tx.views.val.take (i.val + 1)).map Prod.fst
                <+: d.tx.views.val.map Prod.fst :=
              (List.take_prefix _ _).map _
            exact hviewsUnique.sublist hprefix.sublist
          rw [htakeMap, List.nodup_append] at hsubNodup
          exact hsubNodup.2.2 m hmem m List.mem_cons_self rfl
        have heraseId : erase curStub.val m = curStub.val := by
          unfold erase
          apply List.filter_eq_self.mpr
          intro row hrowMem
          have hmemMap : row ∈ (d.tx.views.val.take i.val).map strip := hpermCur.subset hrowMem
          obtain ⟨orig, horigMem, rfl⟩ := List.mem_map.mp hmemMap
          have hne : orig.1 ≠ m := fun heq =>
            hnotMemTake (List.mem_map.mpr ⟨orig, horigMem, heq⟩)
          simp [strip, hne]
        have hpermNext : stubNext.val.Perm ((d.tx.views.val.take (i.val + 1)).map strip) := by
          rw [hstubNext, Kv.Model.set, heraseId, htakeStep, List.map_append, List.map_singleton]
          exact ((hpermCur.cons (strip (m, view))).trans (List.perm_append_singleton _ _).symm)
        refine ⟨
          ⟨
            by omega,
            hlog2.trans (hlog1.trans hlog),
            hret2.trans (hret1.trans hret),
            hgl2.trans (hgl1.trans hgl),
            htm2.trans (htm1.trans htm),
            hid2.trans (hid1.trans hid),
            hre2.trans (hre1.trans hre),
            hvals2,
            rfl,
            by rwa [hiNextVal],
            by rwa [hiNextVal]
          ⟩,
          by omega
        ⟩
      · have hge : n ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt hlt
        have hiEq : i.val = n := Nat.le_antisymm hi hge
        rw [ite_eq_right hlt, WP.spec_ok]
        have htakeAll : d.tx.views.val.take i.val = d.tx.views.val := by
          rw [hiEq]; exact List.take_length
        refine ⟨hlog, hret, hgl, htm, hid, hre, hvals, rfl, ?_, ?_⟩
        · simpa [prePins, txPins, htakeAll] using hliveCur
        · simpa [htakeAll] using hpermCur
    · refine ⟨Nat.zero_le _, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, ?_, ?_⟩
      · simpa [prePins] using live
      · simp [lifecycleNewTx]
  apply WP.spec_bind hloop
  rintro ⟨h, v, stubViews⟩ ⟨hlog, hret, hgl, htm, hid, hre, hvals, hvEq, hliveH, hpermStub⟩
  let stub : CcfKv.engine.Tx := { lifecycleNewTx with snapshot := d.tx.snapshot, views := stubViews }
  apply WP.spec_bind
    (assoc_set CcfKv.U64.Insts.Ccf_kvEngineKey core.clone.CloneU64
      CcfKv.engine.Tx.Insts.CoreCloneClone s.txs d.id stub (fun _ => rfl) (fun _ => rfl)
      clone_tx htxsRoom)
  intro txs1 htxs1
  rw [WP.spec_ok]
  have hk : IndexKeeps s.history.index h.index := by unfold IndexKeeps; rw [hvals]; exact .refl _
  have hactEq : h.activeFrames = s.history.activeFrames := by
    unfold CcfKv.engine.History.activeFrames; rw [hlog]
  have hidxValidAfter : HistoryIndexValid h := by
    refine ⟨hliveH.valid, ?_, by rw [hret]; exact idxValid.retainedEmpty⟩
    intro f hf
    rw [hactEq] at hf
    have hview0 := idxValid.active f hf
    have hview1 := index_keeps_view hk f.data (indexRows s.history.index f.data) hview0
    rw [index_rows_eq hview1]
    exact hview1
  have hstubPins : txPins stub = [] := by
    unfold txPins
    rw [List.flatMap_eq_nil_iff]
    intro row hrow
    obtain ⟨orig, _, rfl⟩ := List.mem_map.mp (hpermStub.subset hrow)
    simp [strip, viewPins, pinPins]
  have hneedsEq : ∀ frame globalFrame,
      CcfKv.engine.tx_needs_frame stub frame globalFrame
      = CcfKv.engine.tx_needs_frame d.tx frame globalFrame := by
    intro frame globalFrame
    have encInj : Function.Injective (encodeBytes ∘ alloc.vec.Vec.val (α := U8)) :=
      encodeBytes_injective.comp (fun _ _ => alloc.vec.Vec.ext _ _)
    have hs1 := tx_needs_frame_spec (encodeBytes ∘ alloc.vec.Vec.val) encInj stub frame globalFrame
    have hs2 := tx_needs_frame_spec (encodeBytes ∘ alloc.vec.Vec.val) encInj d.tx frame globalFrame
    cases h1 : CcfKv.engine.tx_needs_frame stub frame globalFrame using Result.cases with
    | vis _ _ => rw [h1] at hs1; simp at hs1
    | div => rw [h1] at hs1; simp at hs1
    | ret b1 =>
        cases h2 : CcfKv.engine.tx_needs_frame d.tx frame globalFrame
          using Result.cases with
        | vis _ _ => rw [h2] at hs2; simp at hs2
        | div => rw [h2] at hs2; simp at hs2
        | ret b2 =>
            rw [h1, WP.spec_ok] at hs1
            rw [h2, WP.spec_ok] at hs2
            congr 1
            rw [hs1, hs2]
            have hsnapEq : stub.snapshot = d.tx.snapshot := rfl
            rw [hsnapEq]
            congr 1
            have hanyPerm : ∀ (p : CcfKv.engine.Bytes × CcfKv.engine.View → Bool),
                stub.views.val.any p = (d.tx.views.val.map strip).any p := by
              intro p
              apply Bool.eq_iff_iff.mpr
              simp only [List.any_eq_true]
              exact ⟨fun ⟨x, hx, hp⟩ => ⟨x, hpermStub.subset hx, hp⟩,
                fun ⟨x, hx, hp⟩ => ⟨x, hpermStub.symm.subset hx, hp⟩⟩
            rw [hanyPerm, List.any_map]
            rfl
  refine ⟨
    rfl,
    by rw [hvEq],
    hlog,
    hret,
    hgl,
    htm,
    hid,
    hre,
    hliveH,
    hk,
    hidxValidAfter,
    stub,
    htxs1,
    hstubPins,
    hneedsEq
  ⟩

end KvRust
