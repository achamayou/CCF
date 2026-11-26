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
  ∧ stub.views.val = full.views.val.map (fun (m, v) => (m, {v with «local» := .Empty, global := none}))

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
      cases h2 : CcfKv.engine.tx_needs_frame full frame globalFrame using Result.cases with
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
        cases d with | mk _ tx _ => cases tx; simp_all
      simp [hrest]
  | Applied ver =>
      have hrest : { d with tx := { d.tx with phase := .Applied ver } } = d := by
        cases d with | mk _ tx _ => cases tx; simp_all
      simp [hrest]
  | Finished =>
      have hrest : { d with tx := { d.tx with phase := .Finished } } = d := by
        cases d with | mk _ tx _ => cases tx; simp_all
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
            cases d with | mk _ tx _ => cases tx; simp_all
          simp [core.option.Option.is_none, hmiss, hrest]
      | some i =>
          obtain ⟨view, _, hfind⟩ := hidx
          simp only [core.option.Option.is_none, Option.isNone_some, Bool.false_eq_true, ite_false]
          let w : CcfKv.engine.Write := match v with | some val => .Put val | none => .Remove
          have hfrom : CcfKv.engine.Write.from_option v = .ok w := by
            cases v <;> rfl
          rw [hfrom, bind_ok]
          have hstage : ∃ nextP,
              CcfKv.engine.stage_write d.tx.pending { map := m, key := k } w = .ok nextP := by
            have hspec := stage_write_by_key_refines d.tx.pending { map := m, key := k } w hSorted hRoom
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
            cases hres : CcfKv.engine.Assoc.get_ref CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              d.tx.views m using Result.cases with
            | ret o =>
                rw [hres, WP.spec_ok, hfind] at hspec
                rw [hspec]
            | vis _ _ => rw [hres] at hspec; simp at hspec
            | div => rw [hres] at hspec; simp at hspec
          simp [hgetRef, hnextP]

/-- `DetachedTx.finish` matches `lifecycleCommitVersion` identically to `Store.finish`
without borrowing `Store`. -/
theorem detached_finish_matches (d : CcfKv.engine.DetachedTx) (outcome : CcfKv.engine.Outcome)
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
    (live : IndexLiveness s.history.index (txPins d.tx ++ (framePins s.history.activeFrames ++ otherPins)))
    (queueRoom
      : 2 * (s.history.index.values.dirs.val.length + s.history.index.values.rows.val.length) + 1
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
          ∧ (d.registered = true →
              afterStore.txs.val = erase s.txs.val d.id
              ∧ ∀ f ∈ s.history.retained.val,
                  f ∈ afterStore.history.retained.val
                  ∨ CcfKv.engine.txs_need_frame afterStore.txs f baseFrame = .ok false)) := by
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
  refine ⟨hlog, hgl, htm, hid, hre, hreg', rfl,
    by simpa only [hactEq] using hai1Live,
    by simpa only [hactEq] using hpres,
    idxValid.of_preserves_pins hai1Live.valid (by simpa only [hactEq] using hpres)
      (fun f' hf' => Or.inr ⟨f', hactEq ▸ hf', rfl⟩)
      (fun rf hrf => idxValid.retainedEmpty rf (hretSub rf hrf)),
    hretSub, hregSpec⟩

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
          + 17 * s.history.index.values.dirs.val.length + 1
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

end KvRust
