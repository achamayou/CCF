-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Detached

import all Aeneas.Data.List.List
import all Aeneas.Std.Core.Core

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

local instance : DecidableEq CcfKv.engine.Bytes :=
  fun a b =>
    decidable_of_iff (a.val = b.val) ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

local instance : DecidableEq CcfKv.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-- `same_opt_cell` checks exact byte-level equality of two optional committed cells. -/
theorem same_opt_cell_refines (a b : Option CcfKv.engine.Cell)
    : CcfKv.engine.same_opt_cell a b = .ok (decide (a.map byteCell = b.map byteCell)) := by
  unfold CcfKv.engine.same_opt_cell
  cases a with
  | none =>
      cases b <;> simp
  | some ca =>
      cases b with
      | none => simp
      | some cb =>
          simp only [Option.map_some, Option.some.injEq]
          by_cases hv : ca.version = cb.version
          · rw [ite_eq_left hv]
            simp only [bytes_same, byteCell, hv]
            by_cases hveq : ca.value.val = cb.value.val
            · simp [hveq]
            · have hneq : ({ value := ca.value.val, version := cb.version.val } : Cell (List U8))
                  ≠ { value := cb.value.val, version := cb.version.val } := by
                intro h; injection h with hv'; exact hveq hv'
              simp [hveq, hneq]
          · rw [ite_eq_right hv]
            have hne : ca.version.val ≠ cb.version.val := fun h => hv (UScalar.eq_of_val_eq h)
            have hneq : byteCell ca ≠ byteCell cb := fun h => by
              unfold byteCell at h
              injection h with _ hveq
              exact hne hveq
            simp [hneq]

/-- Pure survival mask step: keep write `i` active iff it was active and `prev` and `cur`
agree on the committed cell at `pending[i].1`. -/
def updateActiveMask (prevDb curDb : DB (List U8) (List U8) (List U8))
    (pending : List IndexWrite) (mask : List Bool) : List Bool :=
  (List.range pending.length).map fun i =>
    mask.getD i false
      && match pending[i]? with
         | none => false
         | some (a, _) => decide (find prevDb (byteAddr a) = find curDb (byteAddr a))

/-- Pure sublist of `pending` selected by a boolean mask of matching length. -/
def filterByMask (pending : List IndexWrite) (mask : List Bool) : List IndexWrite :=
  (List.range pending.length).filterMap fun i =>
    if mask.getD i false then pending[i]? else none

private theorem filterByMask_length_le (pending : List IndexWrite) (mask : List Bool)
    : (filterByMask pending mask).length ≤ pending.length := by
  unfold filterByMask
  calc ((List.range pending.length).filterMap _).length
      ≤ (List.range pending.length).length := List.length_filterMap_le _ _
    _ = pending.length := List.length_range

private theorem filterByMask_subset (pending : List IndexWrite) (mask : List Bool)
    : ∀ row ∈ filterByMask pending mask, row ∈ pending := by
  intro row hmem
  unfold filterByMask at hmem
  obtain ⟨i, _, hi⟩ := List.mem_filterMap.mp hmem
  split at hi
  · exact List.mem_of_getElem? hi
  · cases hi

/-- `filter_overwritten_writes` clears `active[i]` iff the committed cell at
`pending[i].1` changed between `prev` and `current`. -/
theorem filter_overwritten_writes_refines (index : CellIndex)
    (prev current : CcfKv.radix.RadixRoot) (prevRows curRows : CellRows)
    (hprevView : IndexView index prev prevRows) (hcurView : IndexView index current curRows)
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (active : alloc.vec.Vec Bool)
    (hlen : active.val.length = pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    : WP.spec (CcfKv.engine.filter_overwritten_writes index prev current pending active)
        (fun after =>
          after.val.length = pending.val.length
          ∧ after.val = updateActiveMask (indexedCellData prevRows) (indexedCellData curRows)
              pending.val active.val) := by
  let n := pending.val.length
  let target := updateActiveMask (indexedCellData prevRows) (indexedCellData curRows)
    pending.val active.val
  have htargetLen : target.length = n := by
    simp [target, updateActiveMask, n]
  have htargetAt : ∀ k, k < n →
      target[k]? = some (active.val.getD k false
        && match pending.val[k]? with
           | none => false
           | some (a, _) =>
               decide (find (indexedCellData prevRows) (byteAddr a)
                 = find (indexedCellData curRows) (byteAddr a))) := by
    intro k hk
    have hk' : k < pending.val.length := hk
    change ((List.range pending.val.length).map _)[k]? = _
    rw [List.getElem?_map, List.getElem?_range hk']
    rfl
  unfold CcfKv.engine.filter_overwritten_writes CcfKv.engine.filter_overwritten_writes_loop
  apply loop.spec_decr_nat (fun (_, _, wi) => n - wi.val)
    (fun (p, act, wi) =>
      p = pending
      ∧ wi.val ≤ n
      ∧ act.val.length = n
      ∧ (∀ k, k < wi.val → act.val[k]? = target[k]?)
      ∧ (∀ k, wi.val ≤ k → act.val[k]? = active.val[k]?))
    _ _ _
  · rintro ⟨p, act, wi⟩ ⟨hp, hwi, hactLen, hpre, hsuf⟩
    dsimp only at hp hwi hactLen hpre hsuf ⊢
    rw [hp]
    unfold CcfKv.engine.filter_overwritten_writes_loop.body
    have hplen : (alloc.vec.Vec.len pending).val = n := alloc.vec.Vec.len_val _
    have hpcap := alloc.vec.Vec.len_ineq pending
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases hlt : wi < alloc.vec.Vec.len pending
    · have hwilt : wi.val < n := by rwa [← hplen]
      have hactLt : wi.val < act.val.length := by omega
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec act wi hactLt)
      intro b hb
      have hbEq : b = active.val.getD wi.val false := by
        have h1 : act.val[wi.val]? = some b := by rw [List.getElem?_eq_getElem hactLt, ← hb]
        rw [hsuf wi.val (Nat.le_refl _)] at h1
        have h2 : active.val[wi.val]? = some (active.val[wi.val]'(by omega)) :=
          List.getElem?_eq_getElem (by omega)
        have h3 : active.val.getD wi.val false = active.val[wi.val]'(by omega) := by
          simp [List.getD, h2]
        rw [h3]
        exact Option.some.inj (h1.symm.trans h2)
      have hstep : WP.spec
          (if b then do
            let (addr, _) ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice
              (CcfKv.engine.Address × CcfKv.engine.Write)) pending wi
            let before ← CcfKv.kv_index.AddressIndex.get index prev addr
            let after ← CcfKv.kv_index.AddressIndex.get index current addr
            let b1 ← CcfKv.engine.same_opt_cell before after
            if b1 then Result.ok act
            else
              let (_, index_mut_back) ← alloc.vec.Vec.index_mut
                (core.slice.index.SliceIndexUsizeSlice Bool) act wi
              Result.ok (index_mut_back false)
          else Result.ok act)
          (fun act1 =>
            act1.val.length = n
            ∧ act1.val[wi.val]? = target[wi.val]?
            ∧ ∀ k, k ≠ wi.val → act1.val[k]? = act.val[k]?) := by
        cases hbVal : b with
        | false =>
            rw [ite_eq_right (by decide : ¬false = true), WP.spec_ok]
            refine ⟨hactLen, ?_, fun _ _ => rfl⟩
            rw [htargetAt wi.val hwilt, ← hbEq, hbVal]
            have h1 : act.val[wi.val]? = some false := by
              rw [List.getElem?_eq_getElem hactLt, ← hb, hbVal]
            simpa using h1
        | true =>
            rw [ite_eq_left (by decide : true = true), alloc.vec.Vec.index_slice_index]
            apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending wi hwilt)
            rintro ⟨addr, w⟩ hrow
            have hrowMem : (addr, w) ∈ pending.val := by
              rw [hrow]; exact List.getElem_mem hwilt
            have hrowGet : pending.val[wi.val]? = some (addr, w) := by
              rw [List.getElem?_eq_getElem hwilt, ← hrow]
            have hkeyRoom : 8 + addr.map.val.length + addr.key.val.length ≤ Usize.max := by
              have hr := addresses (addr, w) hrowMem
              dsimp only [IndexKeyRoom] at hr
              omega
            apply WP.spec_bind (index_data_lookup index prev prevRows hprevView addr hkeyRoom)
            intro before hbefore
            apply WP.spec_bind (index_data_lookup index current curRows hcurView addr hkeyRoom)
            intro after hafter
            rw [same_opt_cell_refines before after, hbefore, hafter, bind_ok]
            by_cases hsame : find (indexedCellData prevRows) (byteAddr addr)
                = find (indexedCellData curRows) (byteAddr addr)
            · rw [decide_eq_true hsame, ite_eq_left rfl, WP.spec_ok]
              refine ⟨hactLen, ?_, fun _ _ => rfl⟩
              rw [htargetAt wi.val hwilt, ← hbEq, hbVal, hrowGet]
              have h1 : act.val[wi.val]? = some true := by
                rw [List.getElem?_eq_getElem hactLt, ← hb, hbVal]
              rw [h1]
              simp [hsame]
            · rw [decide_eq_false hsame, ite_eq_right (by decide : ¬false = true)]
              rw [alloc.vec.Vec.index_mut_slice_index]
              apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec act wi hactLt)
              rintro ⟨_, back⟩ ⟨_, hback⟩
              change WP.spec (Result.ok (back false)) _
              rw [WP.spec_ok]
              have hvVal : (back false).val = act.val.set wi.val false := by
                rw [hback]; exact alloc.vec.Vec.set_val_eq _ _ _
              refine ⟨by rw [hvVal, List.length_set, hactLen], ?_, ?_⟩
              · rw [hvVal, List.getElem?_set_self hactLt, htargetAt wi.val hwilt,
                  ← hbEq, hbVal, hrowGet]
                simp [hsame]
              · intro k hne
                rw [hvVal, List.getElem?_set_ne (Ne.symm hne)]
      apply WP.spec_bind hstep
      rintro act1 ⟨hact1Len, hact1At, hact1Other⟩
      apply WP.spec_bind (Usize.add_spec (x := wi) (y := 1#usize) (by omega))
      intro wi1 hwi1
      have hwi1Val : wi1.val = wi.val + 1 := by omega
      rw [WP.spec_ok]
      dsimp only
      refine ⟨⟨rfl, by omega, hact1Len, ?_, ?_⟩, by omega⟩
      · intro k hk
        by_cases hkeq : k = wi.val
        · subst hkeq; exact hact1At
        · rw [hact1Other k hkeq]
          exact hpre k (by omega)
      · intro k hk
        have hne : k ≠ wi.val := by omega
        rw [hact1Other k hne]
        exact hsuf k (by omega)
    · have hge : n ≤ wi.val := by rw [← hplen]; exact Nat.le_of_not_gt hlt
      have hwiEq : wi.val = n := Nat.le_antisymm hwi hge
      rw [ite_eq_right hlt, WP.spec_ok]
      refine ⟨hactLen, ?_⟩
      apply List.ext_getElem?
      intro k
      by_cases hk : k < n
      · exact hpre k (by omega)
      · have hle1 : act.val.length ≤ k := by rw [hactLen]; exact Nat.le_of_not_gt hk
        have hle2 : target.length ≤ k := by rw [htargetLen]; exact Nat.le_of_not_gt hk
        rw [List.getElem?_eq_none hle1, List.getElem?_eq_none hle2]
  · refine ⟨rfl, Nat.zero_le _, hlen, ?_, fun _ _ => rfl⟩
    intro k hk
    change k < 0 at hk
    omega

/-- `collect_active_writes` builds the exact masked sublist `filterByMask pending active`. -/
theorem collect_active_writes_refines
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (active : alloc.vec.Vec Bool)
    (hlen : active.val.length = pending.val.length)
    : WP.spec (CcfKv.engine.collect_active_writes pending active)
        (fun out => out.val = filterByMask pending.val active.val) := by
  let n := pending.val.length
  let pre (k : Nat) : List IndexWrite :=
    (List.range k).filterMap fun i => if active.val.getD i false then pending.val[i]? else none
  unfold CcfKv.engine.collect_active_writes CcfKv.engine.Assoc.new
    CcfKv.engine.collect_active_writes_loop
  rw [bind_ok]
  apply loop.spec_decr_nat (fun (_, _, wi) => n - wi.val)
    (fun (p, filt, wi) =>
      p = pending
      ∧ wi.val ≤ n
      ∧ filt.val = pre wi.val)
    _ _ _
  · rintro ⟨p, filt, wi⟩ ⟨hp, hwi, hfilt⟩
    dsimp only at hp hwi hfilt ⊢
    rw [hp]
    unfold CcfKv.engine.collect_active_writes_loop.body
    have hplen : (alloc.vec.Vec.len pending).val = n := alloc.vec.Vec.len_val _
    have hpcap := alloc.vec.Vec.len_ineq pending
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases hlt : wi < alloc.vec.Vec.len pending
    · have hwilt : wi.val < n := by rwa [← hplen]
      have hactLt : wi.val < active.val.length := by omega
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec active wi hactLt)
      intro b hb
      have hbEq : b = active.val.getD wi.val false := by
        have h1 : active.val[wi.val]? = some b := by rw [List.getElem?_eq_getElem hactLt, ← hb]
        simp [List.getD, h1]
      have hfiltLen : filt.val.length ≤ wi.val := by
        rw [hfilt]
        calc (pre wi.val).length ≤ (List.range wi.val).length := List.length_filterMap_le _ _
          _ = wi.val := List.length_range
      have hstep : WP.spec
          (if b then do
            let p ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice
              (CcfKv.engine.Address × CcfKv.engine.Write)) pending wi
            let p1 ← (BuiltinClone (CcfKv.engine.Address × CcfKv.engine.Write)).clone p
            let v ← alloc.vec.Vec.push filt p1
            Result.ok v
          else Result.ok filt)
          (fun filt1 => filt1.val = pre (wi.val + 1)) := by
        cases hbVal : b with
        | false =>
            rw [ite_eq_right (by decide : ¬false = true), WP.spec_ok]
            unfold pre
            rw [List.range_succ, List.filterMap_append, List.filterMap_cons, List.filterMap_nil,
              ← hbEq, hbVal]
            simpa [pre] using hfilt
        | true =>
            rw [ite_eq_left (by decide : true = true), alloc.vec.Vec.index_slice_index]
            apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending wi hwilt)
            intro row hrow
            have hclone : (BuiltinClone (CcfKv.engine.Address × CcfKv.engine.Write)).clone row
                = Result.ok row := rfl
            rw [hclone, bind_ok]
            apply WP.spec_bind (alloc.vec.Vec.push_spec filt row (by omega))
            intro filt1 hfilt1
            rw [WP.spec_ok]
            unfold pre
            rw [List.range_succ, List.filterMap_append, List.filterMap_cons, List.filterMap_nil,
              ← hbEq, hbVal, List.getElem?_eq_getElem hwilt, ← hrow]
            simpa [pre, hfilt] using hfilt1
      apply WP.spec_bind hstep
      intro filt1 hfilt1
      apply WP.spec_bind (Usize.add_spec (x := wi) (y := 1#usize) (by omega))
      intro wi1 hwi1
      have hwi1Val : wi1.val = wi.val + 1 := by omega
      rw [WP.spec_ok]
      dsimp only
      exact ⟨⟨rfl, by omega, by rwa [hwi1Val]⟩, by omega⟩
    · have hge : n ≤ wi.val := by rw [← hplen]; exact Nat.le_of_not_gt hlt
      have hwiEq : wi.val = n := Nat.le_antisymm hwi hge
      rw [ite_eq_right hlt, WP.spec_ok]
      simpa [pre, filterByMask, hwiEq] using hfilt
  · exact ⟨rfl, Nat.zero_le _, rfl⟩

/-- Updating frame `revisions` and `births` for a single backfilled write succeeds
within association-list capacity without mutating `index`. -/
theorem backfill_stamps_refines
    (revisions births : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp)
    (index : CellIndex) (oldRoot : CcfKv.radix.RadixRoot) (rows : CellRows)
    (hview : IndexView index oldRoot rows)
    (row : IndexWrite) (stamp : CcfKv.engine.Stamp)
    (hrevRoom : revisions.val.length < Usize.max)
    (hbirthRoom : births.val.length < Usize.max)
    (hkeyRoom : IndexKeyRoom row)
    : WP.spec (CcfKv.engine.backfill_stamps revisions births index oldRoot row stamp)
        (fun (rev1, birth1) =>
          rev1.val.length ≤ revisions.val.length + 1
          ∧ birth1.val.length ≤ births.val.length + 1) := by
  obtain ⟨a, w⟩ := row
  have hstampClone : ∀ st : CcfKv.engine.Stamp,
      CcfKv.engine.Stamp.Insts.CoreCloneClone.clone st = .ok st :=
    fun st => by simp [CcfKv.engine.Stamp.Insts.CoreCloneClone.clone]
  have hrevStep : WP.spec
      (do
        let o ← CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
          revisions a.map
        let (stamp2, should_update) ←
          match o with
          | none => Result.ok (stamp, true)
          | some existing => Result.ok (stamp, existing.version < stamp.version)
        let a2 ← if should_update then do
            let b1 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
            CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
              revisions b1 stamp2
          else Result.ok revisions
        Result.ok (a2, stamp2, a))
      (fun (rev1, st1, a1) =>
        rev1.val.length ≤ revisions.val.length + 1 ∧ st1 = stamp ∧ a1 = a) := by
    apply WP.spec_bind
      (assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
        CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
        revisions a.map (fun k => key_same k a.map) hstampClone)
    intro o _
    cases o with
    | none =>
        simp only [bind_ok, clone_bytes]
        apply WP.spec_bind
          (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
            revisions a.map stamp (fun k => key_same k a.map) clone_bytes hstampClone hrevRoom)
        intro rev1 hrev1
        rw [WP.spec_ok]
        have hle : rev1.val.length ≤ revisions.val.length + 1 := by
          rw [hrev1, Kv.Model.set, List.length_cons]
          have hfl : (erase revisions.val a.map).length ≤ revisions.val.length :=
            List.length_filter_le _ _
          omega
        exact ⟨hle, rfl, rfl⟩
    | some existing =>
        simp only [bind_ok]
        by_cases hlt : existing.version < stamp.version
        · simp only [hlt, decide_true, clone_bytes, bind_ok]
          apply WP.spec_bind
            (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
              revisions a.map stamp (fun k => key_same k a.map) clone_bytes hstampClone hrevRoom)
          intro rev1 hrev1
          rw [WP.spec_ok]
          have hle : rev1.val.length ≤ revisions.val.length + 1 := by
            rw [hrev1, Kv.Model.set, List.length_cons]
            have hfl : (erase revisions.val a.map).length ≤ revisions.val.length :=
              List.length_filter_le _ _
            omega
          exact ⟨hle, rfl, rfl⟩
        · simp [hlt]
  have hbirthStep : ∀ (rev1 : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp),
      rev1.val.length ≤ revisions.val.length + 1 →
      WP.spec
        (do
          let o ← CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
            births a.map
          let (stamp2, should_birth) ←
            match o with
            | none => Result.ok (stamp, true)
            | some existing => Result.ok (stamp, existing.version > stamp.version)
          if should_birth then do
            let b1 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
            let births1 ← CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
              births b1 stamp2
            Result.ok (rev1, births1)
          else Result.ok (rev1, births))
        (fun (r1, b1) =>
          r1.val.length ≤ revisions.val.length + 1
          ∧ b1.val.length ≤ births.val.length + 1) := by
    intro rev1 hrev1Len
    apply WP.spec_bind
      (assoc_get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
        CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
        births a.map (fun k => key_same k a.map) hstampClone)
    intro ob _
    cases ob with
    | none =>
        simp only [bind_ok, clone_bytes]
        apply WP.spec_bind
          (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
            CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
            births a.map stamp (fun k => key_same k a.map) clone_bytes hstampClone hbirthRoom)
        intro birth1 hbirth1
        rw [WP.spec_ok]
        have hle : birth1.val.length ≤ births.val.length + 1 := by
          rw [hbirth1, Kv.Model.set, List.length_cons]
          have hfl : (erase births.val a.map).length ≤ births.val.length :=
            List.length_filter_le _ _
          omega
        exact ⟨hrev1Len, hle⟩
    | some existing =>
        simp only [bind_ok]
        by_cases hgt : existing.version > stamp.version
        · simp only [hgt, decide_true, clone_bytes, bind_ok]
          apply WP.spec_bind
            (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
              CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
              births a.map stamp (fun k => key_same k a.map) clone_bytes hstampClone hbirthRoom)
          intro birth1 hbirth1
          rw [WP.spec_ok]
          have hle : birth1.val.length ≤ births.val.length + 1 := by
            rw [hbirth1, Kv.Model.set, List.length_cons]
            have hfl : (erase births.val a.map).length ≤ births.val.length :=
              List.length_filter_le _ _
            omega
          exact ⟨hrev1Len, hle⟩
        · simp [hgt, hrev1Len]
  cases w with
  | Put val =>
      have hput : CcfKv.engine.backfill_stamps revisions births index oldRoot (a, .Put val) stamp
          = (do
              let (revisions1, stamp1, a1) ← (do
                let o ← CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  revisions a.map
                let (stamp2, should_update) ←
                  match o with
                  | none => Result.ok (stamp, true)
                  | some existing => Result.ok (stamp, existing.version < stamp.version)
                let a2 ← if should_update then do
                    let b1 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
                    CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                      CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                      revisions b1 stamp2
                  else Result.ok revisions
                Result.ok (a2, stamp2, a))
              let o ← CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                births a1.map
              let (stamp2, should_birth) ←
                match o with
                | none => Result.ok (stamp1, true)
                | some existing => Result.ok (stamp1, existing.version > stamp1.version)
              if should_birth then do
                let b1 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a1.map
                let births1 ← CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  births b1 stamp2
                Result.ok (revisions1, births1)
              else Result.ok (revisions1, births)) := by
        unfold CcfKv.engine.backfill_stamps
        change Aeneas.Std.bind (Result.ok true) _ = _
        rw [bind_ok, ite_eq_left rfl]
        rfl
      rw [hput]
      apply WP.spec_bind hrevStep
      rintro ⟨rev1, st1, a1⟩ ⟨hrev1Len, hst1, ha1⟩
      rw [hst1, ha1]
      exact hbirthStep rev1 hrev1Len
  | Remove =>
      have hrem : CcfKv.engine.backfill_stamps revisions births index oldRoot (a, .Remove) stamp
          = (do
              let (revisions1, stamp1, a1) ← (do
                let o ← CcfKv.kv_index.AddressIndex.get index oldRoot a
                if core.option.Option.is_some o then do
                  let o1 ← CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                    CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                    revisions a.map
                  let (stamp2, should_update) ←
                    match o1 with
                    | none => Result.ok (stamp, true)
                    | some existing => Result.ok (stamp, existing.version < stamp.version)
                  let a2 ← if should_update then do
                      let b2 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
                      CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                        CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                        revisions b2 stamp2
                    else Result.ok revisions
                  Result.ok (a2, stamp2, a)
                else Result.ok (revisions, stamp, a))
              let o ← CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                births a1.map
              let (stamp2, should_birth) ←
                match o with
                | none => Result.ok (stamp1, true)
                | some existing => Result.ok (stamp1, existing.version > stamp1.version)
              if should_birth then do
                let b1 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a1.map
                let births1 ← CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                  CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                  births b1 stamp2
                Result.ok (revisions1, births1)
              else Result.ok (revisions1, births)) := by
        unfold CcfKv.engine.backfill_stamps
        change Aeneas.Std.bind (Result.ok false) _ = _
        rw [bind_ok, ite_eq_right (by decide : ¬false = true)]
        rfl
      rw [hrem]
      have hkr : 8 + a.map.val.length + a.key.val.length ≤ Usize.max := by
        dsimp only [IndexKeyRoom] at hkeyRoom; omega
      have hremPart : WP.spec
          (do
            let o ← CcfKv.kv_index.AddressIndex.get index oldRoot a
            if core.option.Option.is_some o then do
              let o1 ← CcfKv.engine.Assoc.get CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                revisions a.map
              let (stamp2, should_update) ←
                match o1 with
                | none => Result.ok (stamp, true)
                | some existing => Result.ok (stamp, existing.version < stamp.version)
              let a2 ← if should_update then do
                  let b2 ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
                  CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
                    CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
                    revisions b2 stamp2
                else Result.ok revisions
              Result.ok (a2, stamp2, a)
            else Result.ok (revisions, stamp, a))
          (fun (rev1, st1, a1) =>
            rev1.val.length ≤ revisions.val.length + 1 ∧ st1 = stamp ∧ a1 = a) := by
        apply WP.spec_bind (index_data_lookup index oldRoot rows hview a hkr)
        intro found _
        cases found with
        | none =>
            simp only [core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
            rw [WP.spec_ok]
            dsimp only
            exact ⟨by omega, rfl, rfl⟩
        | some _ =>
            simp only [core.option.Option.is_some, Option.isSome_some, ↓reduceIte]
            exact hrevStep
      apply WP.spec_bind hremPart
      rintro ⟨rev1, st1, a1⟩ ⟨hrev1Len, hst1, ha1⟩
      rw [hst1, ha1]
      exact hbirthStep rev1 hrev1Len

/-- Applying `backfill_stamps` across a filtered write list succeeds within room bounds. -/
theorem apply_backfill_stamps_refines
    (revisions births : CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp)
    (index : CellIndex) (oldRoot : CcfKv.radix.RadixRoot) (rows : CellRows)
    (hview : IndexView index oldRoot rows)
    (filtered : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (stamp : CcfKv.engine.Stamp)
    (hrevRoom : revisions.val.length + filtered.val.length ≤ Usize.max)
    (hbirthRoom : births.val.length + filtered.val.length ≤ Usize.max)
    (addresses : ∀ row ∈ filtered.val, IndexKeyRoom row)
    : WP.spec (CcfKv.engine.apply_backfill_stamps revisions births index oldRoot filtered stamp)
        (fun (rev1, birth1) =>
          rev1.val.length ≤ revisions.val.length + filtered.val.length
          ∧ birth1.val.length ≤ births.val.length + filtered.val.length) := by
  let n := filtered.val.length
  unfold CcfKv.engine.apply_backfill_stamps CcfKv.engine.apply_backfill_stamps_loop
  apply loop.spec_decr_nat (fun (_, _, _, fi) => n - fi.val)
    (fun (rev, brt, filt, fi) =>
      filt = filtered
      ∧ fi.val ≤ n
      ∧ rev.val.length ≤ revisions.val.length + fi.val
      ∧ brt.val.length ≤ births.val.length + fi.val)
    _ _ _
  · rintro ⟨rev, brt, filt, fi⟩ ⟨hfilt, hfi, hrevL, hbrtL⟩
    dsimp only at hfilt hfi hrevL hbrtL ⊢
    rw [hfilt]
    unfold CcfKv.engine.apply_backfill_stamps_loop.body
    have hflen : (alloc.vec.Vec.len filtered).val = n := alloc.vec.Vec.len_val _
    have hfcap := alloc.vec.Vec.len_ineq filtered
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases hlt : fi < alloc.vec.Vec.len filtered
    · have hfiltLt : fi.val < n := by rwa [← hflen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec filtered fi hfiltLt)
      intro row hrow
      have hrowMem : row ∈ filtered.val := by rw [hrow]; exact List.getElem_mem hfiltLt
      apply WP.spec_bind
        (backfill_stamps_refines rev brt index oldRoot rows hview row stamp
          (by dsimp only [n] at hfiltLt; omega)
          (by dsimp only [n] at hfiltLt; omega)
          (addresses row hrowMem))
      rintro ⟨rev1, brt1⟩ ⟨hrev1, hbrt1⟩
      apply WP.spec_bind (Usize.add_spec (x := fi) (y := 1#usize) (by omega))
      intro fi1 hfi1
      have hfi1Val : fi1.val = fi.val + 1 := by omega
      rw [WP.spec_ok]
      dsimp only
      exact ⟨⟨rfl, by omega, by omega, by omega⟩, by omega⟩
    · have hge : n ≤ fi.val := by rw [← hflen]; exact Nat.le_of_not_gt hlt
      rw [ite_eq_right hlt, WP.spec_ok]
      have hfiLe : fi.val ≤ filtered.val.length := hfi
      exact ⟨le_trans hrevL (Nat.add_le_add_left hfiLe _),
        le_trans hbrtL (Nat.add_le_add_left hfiLe _)⟩
  · exact ⟨rfl, Nat.zero_le _, by omega, by omega⟩

/-! ### Level 2: Pure `Kv.Model.publish` Linearizability & Tight Counterexample -/

/-- Pure iterative survival mask over a list of pre-backfill frame databases
`dbs = [db_0, db_1, ..., db_k]`: write `i` survives at offset `k` iff its committed
cell never changed between any adjacent pre-backfill frames `db_j` and `db_{j+1}`
for `0 ≤ j < k`. -/
def maskAtStep (pending : List IndexWrite)
    (dbs : List (DB (List U8) (List U8) (List U8))) : Nat → List Bool
  | 0 => List.replicate pending.length true
  | k + 1 =>
      match dbs[k]?, dbs[k + 1]? with
      | some prevDb, some curDb =>
          updateActiveMask prevDb curDb pending (maskAtStep pending dbs k)
      | _, _ => maskAtStep pending dbs k

/-- Replay a sequence of `(version, writes)` publications through `Kv.Model.publish`. -/
def replayPublish (base : DB (List U8) (List U8) (List U8))
    : List (Nat × Writes (List U8) (List U8) (List U8)) → DB (List U8) (List U8) (List U8)
  | [] => base
  | (ver, ws) :: rest => replayPublish (Kv.Model.publish base ver ws) rest

/-- Non-interference condition for exact backfill linearizability:
a later commit `(v, ws)` does not perform a silent `Remove` (erasing a key that was
already absent in the pre-backfill database `prevDb`) on any address written by `W_0`. -/
def NoSilentRemove (w0 : Writes (List U8) (List U8) (List U8))
    (prevDb : DB (List U8) (List U8) (List U8))
    (ws : Writes (List U8) (List U8) (List U8)) : Prop :=
  ∀ a, (find w0 a).isSome → find ws a = some none → find prevDb a ≠ none

/-- Every cell stored in a byte-level database was written at version `≤ bound`. -/
def ByteCellsBounded (db : DB (List U8) (List U8) (List U8)) (bound : Nat) : Prop :=
  ∀ a c, find db a = some c → c.version ≤ bound

private theorem find_mem_of_some {K V : Type} [DecidableEq K]
    {xs : Assoc K V} {k : K} {v : V} (h : find xs k = some v)
    : (k, v) ∈ xs := by
  induction xs with
  | nil => simp [find] at h
  | cons hd tl ih =>
      simp only [find] at h
      by_cases heq : hd.1 = k
      · simp only [heq, ↓reduceIte, Option.some.injEq] at h
        subst heq; subst h; exact List.mem_cons_self
      · simp only [heq, ↓reduceIte] at h
        exact List.mem_cons_of_mem _ (ih h)

private theorem findIdx?_lt {α : Type} {xs : List α} {p : α → Bool} {i : Nat}
    (h : xs.findIdx? p = some i) : i < xs.length :=
  (List.findIdx?_eq_some_iff_getElem.mp h).1

private theorem indexedCellData_unique {index : CellIndex} {root : CcfKv.radix.RadixRoot}
    {rows : CellRows} (view : IndexView index root rows)
    : Kv.Properties.Unique (indexedCellData rows) := by
  have hsorted := index_view_sorted view
  unfold Kv.Properties.Unique indexedCellData
  rw [List.map_map]
  change (rows.map fun r => byteAddr r.1).Nodup
  rw [List.nodup_iff_pairwise_ne, List.pairwise_map]
  exact hsorted.imp fun {a b} hlt heq => by
    have hab : a.1 = b.1 := byteAddr_inj heq
    rw [hab] at hlt
    exact lt_irrefl _ hlt

private theorem maskAtStep_length (pending : List IndexWrite)
    (dbs : List (DB (List U8) (List U8) (List U8))) (k : Nat)
    : (maskAtStep pending dbs k).length = pending.length := by
  induction k with
  | zero => simp [maskAtStep]
  | succ k ih =>
      unfold maskAtStep
      cases dbs[k]? <;> cases dbs[k + 1]? <;> simp [updateActiveMask, ih]

private theorem find_byteWrites_filterByMask (pending : List IndexWrite) (mask : List Bool)
    (hUnique : Kv.Properties.Unique (byteWrites pending))
    (a : Addr (List U8) (List U8))
    : find (byteWrites (filterByMask pending mask)) a
      = match pending.findIdx? (fun row => decide (byteAddr row.1 = a)) with
        | none => none
        | some i =>
            if mask.getD i false then
              (pending[i]?).map fun row =>
                match row.2 with | .Put v => some v.val | .Remove => none
            else none := by
  have hbyte : ∀ (xs : List IndexWrite),
      Kv.Properties.Unique (byteWrites xs) →
      ∀ (x : Addr (List U8) (List U8)) (w : Option (List U8)),
        (x, w) ∈ byteWrites xs → find (byteWrites xs) x = some w := by
    intro xs hu x w hmem
    clear hUnique
    induction xs with
    | nil => simp [byteWrites] at hmem
    | cons hd tl ih =>
        simp only [byteWrites, List.map_cons, List.mem_cons] at hmem
        have hu' : byteAddr hd.1 ∉ (byteWrites tl).map Prod.fst ∧ Kv.Properties.Unique (byteWrites tl) := by
          simpa [Kv.Properties.Unique, byteWrites] using hu
        simp only [byteWrites, List.map_cons, find]
        rcases hmem with heq | htl
        · obtain ⟨rfl, rfl⟩ := Prod.mk.inj heq
          simp
        · have hne : byteAddr hd.1 ≠ x := by
            intro hsame
            apply hu'.1
            rw [hsame]
            exact List.mem_map.mpr ⟨(x, w), htl, rfl⟩
          simp [hne]
          exact ih hu'.2 htl
  have hsublist : (filterByMask pending mask).Sublist pending := by
    unfold filterByMask
    have hgen : ∀ (k : Nat), k ≤ pending.length →
        ((List.range k).filterMap fun i =>
          if mask.getD i false then pending[i]? else none).Sublist (pending.take k) := by
      intro k hk
      induction k with
      | zero => simp
      | succ k ih =>
          rw [List.range_succ, List.filterMap_append, List.filterMap_cons, List.filterMap_nil,
            List.take_add_one, List.getElem?_eq_getElem (by omega)]
          have hsub := ih (by omega)
          cases mask.getD k false
          · simp only [Bool.false_eq_true, ↓reduceIte, List.append_nil]
            exact hsub.trans (List.sublist_append_left _ _)
          · simp only [↓reduceIte, Option.toList_some]
            exact hsub.append (List.Sublist.refl _)
    simpa [List.take_length] using hgen pending.length (Nat.le_refl _)
  have hfiltUnique : Kv.Properties.Unique (byteWrites (filterByMask pending mask)) := by
    unfold Kv.Properties.Unique at hUnique ⊢
    exact hUnique.sublist ((hsublist.map _).map _)
  cases hidx : pending.findIdx? (fun row => decide (byteAddr row.1 = a)) with
  | none =>
      have hnone : ∀ row ∈ pending, byteAddr row.1 ≠ a := by
        intro row hrow
        have := List.findIdx?_eq_none_iff.mp hidx row hrow
        simpa using this
      cases hres : find (byteWrites (filterByMask pending mask)) a with
      | none => rfl
      | some w =>
          have hmem := find_mem_of_some hres
          obtain ⟨row, hrowMem, hrowEq⟩ := List.mem_map.mp hmem
          have hrowPend := filterByMask_subset pending mask row hrowMem
          exact (hnone row hrowPend (congrArg Prod.fst hrowEq)).elim
  | some i =>
      have hilt : i < pending.length := findIdx?_lt hidx
      have hrow : byteAddr (pending[i]'hilt).1 = a := by
        have hsat := List.findIdx?_eq_some_iff_getElem.mp hidx
        simpa using hsat.2.1
      have hget : pending[i]? = some (pending[i]'hilt) := List.getElem?_eq_getElem hilt
      dsimp only
      rw [hget, Option.map_some]
      cases hmask : mask.getD i false with
      | true =>
          simp only [↓reduceIte]
          have hmemFilt : (pending[i]'hilt) ∈ filterByMask pending mask := by
            unfold filterByMask
            refine List.mem_filterMap.mpr ⟨i, List.mem_range.mpr hilt, ?_⟩
            rw [hmask, ite_eq_left rfl, hget]
          have hmemBW : (a, match (pending[i]'hilt).2 with | .Put v => some v.val | .Remove => none)
              ∈ byteWrites (filterByMask pending mask) := by
            refine List.mem_map.mpr ⟨pending[i]'hilt, hmemFilt, ?_⟩
            exact Prod.ext hrow rfl
          exact hbyte _ hfiltUnique _ _ hmemBW
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          cases hres : find (byteWrites (filterByMask pending mask)) a with
          | none => rfl
          | some w =>
              have hmem := find_mem_of_some hres
              obtain ⟨row, hrowMem, hrowEq⟩ := List.mem_map.mp hmem
              unfold filterByMask at hrowMem
              obtain ⟨j, hjRange, hjSpec⟩ := List.mem_filterMap.mp hrowMem
              have hjlt : j < pending.length := List.mem_range.mp hjRange
              cases hmj : mask.getD j false with
              | false =>
                  rw [hmj, ite_eq_right (by decide : ¬false = true)] at hjSpec
                  cases hjSpec
              | true =>
                  rw [hmj, ite_eq_left rfl, List.getElem?_eq_getElem hjlt] at hjSpec
                  injection hjSpec with hjEq
                  subst hjEq
                  have hjAddr : byteAddr (pending[j]'hjlt).1 = a := congrArg Prod.fst hrowEq
                  have heqIdx : j = i := by
                    have hnodup : (pending.map (fun r => byteAddr r.1)).Nodup := by
                      simpa [Kv.Properties.Unique, byteWrites, List.map_map, Function.comp_def] using hUnique
                    have h1 : (pending.map (fun r => byteAddr r.1))[j]'(by simpa using hjlt)
                        = (pending.map (fun r => byteAddr r.1))[i]'(by simpa using hilt) := by
                      simp [hjAddr, hrow]
                    exact congrArg Fin.val
                      ((List.nodup_iff_injective_getElem.mp hnodup)
                        (a₁ := ⟨j, by simpa using hjlt⟩) (a₂ := ⟨i, by simpa using hilt⟩) h1)
                  subst heqIdx
                  rw [hmask] at hmj
                  cases hmj

/-- Pure `Kv.Model.publish` linearizability theorem for reserved-slot backfill:
if pre-backfill databases `dbs[0..m]` satisfy `dbs[k+1] = publish dbs[k] v_{k+1} W_{k+1}`
with strictly later versions `reservedVer < v_{k+1}` and `ByteCellsBounded dbs[k] (v_{k+1} - 1)`,
and no later `W_{k+1}` performs a silent `Remove` on an absent key written by `W_0`,
then at every step `k ≤ m` and every address `a`, applying the surviving writes
of `W_0` onto `dbs[k]` yields the exact same lookup as linearly publishing `W_0` at
`reservedVer` first and then replaying `W_1 .. W_k` through `Kv.Model.publish`. -/
theorem backfill_model_linearizes
    (pending : List IndexWrite) (reservedVer : Nat)
    (dbs : List (DB (List U8) (List U8) (List U8)))
    (commits : List (Nat × Writes (List U8) (List U8) (List U8)))
    (hUnique0 : Kv.Properties.Unique (byteWrites pending))
    (hlen : dbs.length = commits.length + 1)
    (hsteps : ∀ k (hk : k < commits.length),
      dbs[k + 1]'(by omega)
        = Kv.Model.publish (dbs[k]'(by omega)) (commits[k]'hk).1 (commits[k]'hk).2
      ∧ reservedVer < (commits[k]'hk).1
      ∧ ByteCellsBounded (dbs[k]'(by omega)) ((commits[k]'hk).1 - 1)
      ∧ NoSilentRemove (byteWrites pending) (dbs[k]'(by omega)) (commits[k]'hk).2)
    (k : Nat) (hk : k ≤ commits.length) (a : Addr (List U8) (List U8))
    : find
        (Kv.Model.publish (dbs[k]'(by omega)) reservedVer
          (byteWrites (filterByMask pending (maskAtStep pending dbs k))))
        a
      = find
          (replayPublish
            (Kv.Model.publish (dbs[0]'(by omega)) reservedVer (byteWrites pending))
            (commits.take k))
          a := by
  induction k with
  | zero =>
      simp only [List.take_zero, replayPublish]
      have hmaskAll : filterByMask pending (maskAtStep pending dbs 0) = pending := by
        unfold filterByMask maskAtStep
        have hgen : ∀ (m : Nat), m ≤ pending.length →
            ((List.range m).filterMap fun j =>
              if (List.replicate pending.length true).getD j false then pending[j]? else none)
            = pending.take m := by
          intro m hm
          induction m with
          | zero => simp
          | succ m ih =>
              rw [List.range_succ, List.filterMap_append, List.filterMap_cons, List.filterMap_nil,
                List.take_add_one, List.getElem?_eq_getElem (by omega)]
              have hrep : (List.replicate pending.length true).getD m false = true := by
                have hmlt : m < pending.length := by omega
                unfold List.getD
                rw [List.getElem?_replicate, ite_eq_left hmlt]
                rfl
              rw [hrep, ite_eq_left rfl, ih (by omega)]
              simp
        rw [hgen pending.length (Nat.le_refl _), List.take_length]
      rw [hmaskAll]
  | succ k ih =>
      have hkLt : k < commits.length := by omega
      obtain ⟨hpub, hverGt, hbound, hnoSilent⟩ := hsteps k hkLt
      have htakeSucc : commits.take (k + 1) = commits.take k ++ [commits[k]'hkLt] := by
        rw [List.take_add_one, List.getElem?_eq_getElem hkLt]; simp
      have hreplayAppend : ∀ base xs step,
          replayPublish base (xs ++ [step]) = Kv.Model.publish (replayPublish base xs) step.1 step.2 := by
        intro base xs step
        induction xs generalizing base with
        | nil => rfl
        | cons hd tl iht => exact iht _
      rw [htakeSucc, hreplayAppend, Kv.Properties.publish_lookup, Kv.Properties.publish_lookup]
      have hih := ih (by omega)
      rw [Kv.Properties.publish_lookup] at hih
      rw [← hih]
      have hfilt_k := find_byteWrites_filterByMask pending (maskAtStep pending dbs k) hUnique0 a
      have hfilt_kp1 := find_byteWrites_filterByMask pending (maskAtStep pending dbs (k + 1)) hUnique0 a
      rw [hfilt_k, hfilt_kp1]
      cases hidx : pending.findIdx? (fun row => decide (byteAddr row.1 = a)) with
      | none =>
          simp [hpub, Kv.Properties.publish_lookup]
      | some i =>
          have hilt : i < pending.length := findIdx?_lt hidx
          have haddrEq : byteAddr (pending[i]'hilt).1 = a := by
            have hsat := List.findIdx?_eq_some_iff_getElem.mp hidx
            simpa using hsat.2.1
          have hgetp : pending[i]? = some (pending[i]'hilt) := List.getElem?_eq_getElem hilt
          have hgetk : dbs[k]? = some (dbs[k]'(by omega)) := List.getElem?_eq_getElem (by omega)
          have hgetkp1 : dbs[k + 1]? = some (dbs[k + 1]'(by omega)) := List.getElem?_eq_getElem (by omega)
          have hmaskStep : (maskAtStep pending dbs (k + 1)).getD i false
              = ((maskAtStep pending dbs k).getD i false
                && decide (find (dbs[k]'(by omega)) a = find (dbs[k + 1]'(by omega)) a)) := by
            conv_lhs => unfold maskAtStep
            rw [hgetk, hgetkp1]
            change ((updateActiveMask (dbs[k]'(by omega)) (dbs[k + 1]'(by omega)) pending
              (maskAtStep pending dbs k))[i]?).getD false = _
            unfold updateActiveMask
            rw [List.getElem?_map, List.getElem?_range hilt, Option.map_some, Option.getD_some,
              hgetp]
            dsimp
            rw [haddrEq]
          dsimp only
          rw [hmaskStep]
          cases hmk : (maskAtStep pending dbs k).getD i false with
          | false =>
              simp [hpub, Kv.Properties.publish_lookup]
          | true =>
              simp only [Bool.true_and, ↓reduceIte, hgetp, Option.map_some]
              have hmemW0 : (find (byteWrites pending) a).isSome := by
                have hmem : (a, match (pending[i]'hilt).2 with | .Put v => some v.val | .Remove => none)
                    ∈ byteWrites pending := by
                  refine List.mem_map.mpr ⟨pending[i]'hilt, List.getElem_mem hilt, ?_⟩
                  exact Prod.ext haddrEq rfl
                have hfound : find (byteWrites pending) a
                    = some (match (pending[i]'hilt).2 with | .Put v => some v.val | .Remove => none) := by
                  have hgen : ∀ (xs : List (Addr (List U8) (List U8) × Option (List U8))),
                      Kv.Properties.Unique xs → ∀ p ∈ xs, find xs p.1 = some p.2 := by
                    intro xs hu p hp
                    induction xs with
                    | nil => cases hp
                    | cons hd tl ihx =>
                        have hu' : hd.1 ∉ tl.map Prod.fst ∧ Kv.Properties.Unique tl := by
                          simpa [Kv.Properties.Unique] using hu
                        simp only [List.mem_cons] at hp
                        rcases hp with rfl | htl
                        · simp [find]
                        · have hne : hd.1 ≠ p.1 := fun h => hu'.1 (h ▸ List.mem_map.mpr ⟨p, htl, rfl⟩)
                          simp [find, hne, ihx hu'.2 htl]
                  exact hgen (byteWrites pending) hUnique0 _ hmem
                simp [hfound]
              cases hws : find (commits[k]'hkLt).2 a with
              | none =>
                  have hsame : find (dbs[k]'(by omega)) a = find (dbs[k + 1]'(by omega)) a := by
                    rw [hpub, Kv.Properties.publish_lookup, hws]
                  rw [decide_eq_true hsame, ite_eq_left rfl]
                  cases (pending[i]'hilt).2 <;> rfl
              | some wLater =>
                  cases wLater with
                  | some vLater =>
                      have hnewCell : find (dbs[k + 1]'(by omega)) a
                          = some { value := vLater, version := (commits[k]'hkLt).1 } := by
                        rw [hpub, Kv.Properties.publish_lookup, hws]
                      have hdiff : find (dbs[k]'(by omega)) a ≠ find (dbs[k + 1]'(by omega)) a := by
                        rw [hnewCell]
                        intro heq
                        have hle := hbound a { value := vLater, version := (commits[k]'hkLt).1 } heq
                        dsimp only at hle
                        omega
                      rw [decide_eq_false hdiff, ite_eq_right (by decide : ¬false = true)]
                      exact hnewCell
                  | none =>
                      have hprevSome : find (dbs[k]'(by omega)) a ≠ none :=
                        hnoSilent a hmemW0 hws
                      have hnewNone : find (dbs[k + 1]'(by omega)) a = none := by
                        rw [hpub, Kv.Properties.publish_lookup, hws]
                      have hdiff : find (dbs[k]'(by omega)) a ≠ find (dbs[k + 1]'(by omega)) a := by
                        rw [hnewNone]; exact hprevSome
                      rw [decide_eq_false hdiff, ite_eq_right (by decide : ¬false = true)]
                      exact hnewNone

/-- Tightness witness: without `NoSilentRemove`, a reserved `Put(a, v)` at version 1
followed by a concurrent `Remove(a)` at version 2 on an empty base diverges between
`same_opt_cell`-based backfill (`some {value := v, version := 1}`) and linearized
`Kv.Model.publish` (`none`). -/
theorem silent_remove_counterexample (a : CcfKv.engine.Address) (v : CcfKv.engine.Bytes)
    : let pending : List IndexWrite := [(a, .Put v)]
      let db0 : DB (List U8) (List U8) (List U8) := []
      let w1 : Writes (List U8) (List U8) (List U8) := [(byteAddr a, none)]
      let db1 := Kv.Model.publish db0 2 w1
      find (Kv.Model.publish db1 1 (byteWrites (filterByMask pending (maskAtStep pending [db0, db1] 1))))
          (byteAddr a)
        = some { value := v.val, version := 1 }
      ∧ find (replayPublish (Kv.Model.publish db0 1 (byteWrites pending)) [(2, w1)]) (byteAddr a)
        = none := by
  simp [maskAtStep, updateActiveMask, filterByMask, replayPublish, Kv.Model.publish,
    byteWrites, Kv.Model.set, erase, find]

/-! ### Level 1 + Level 2 Composition on Extracted `Store.apply_backfill_ccf` -/

/-- Capacity bounds ensuring `apply_backfill_ccf` completes without overflow across
every frame in `startOff ..< activeFrames.length`. -/
structure BackfillRoom (s : CcfKv.engine.Store) (pending : List IndexWrite)
    (extraPins : List U32) (startOff : Nat) : Prop where
  startLt : startOff < s.history.activeFrames.length
  nextId : s.history.next_identity.val < U64.max
  addresses : ∀ row ∈ pending, IndexKeyRoom row
  stampsRoom
    : ∀ j (hj : j < s.history.activeFrames.length),
        startOff ≤ j →
        (s.history.activeFrames[j]'hj).revisions.val.length + pending.length ≤ Usize.max
        ∧ (s.history.activeFrames[j]'hj).births.val.length + pending.length ≤ Usize.max
  indexDirs
    : ∀ (peakRows : Nat),
        (∀ j (hj : j < s.history.activeFrames.length),
          (indexRows s.history.index (s.history.activeFrames[j]'hj).data).length ≤ peakRows) →
        let span := s.history.activeFrames.length - startOff
        let perStepDirs := pending.length * (peakRows + pending.length + 1)
        let totalDirs := span * perStepDirs
        let totalRows := span * pending.length
        s.history.index.values.dirs.val.length + totalDirs + (peakRows + pending.length + 1)
          ≤ 2147483647
        ∧ s.history.index.values.rows.val.length + totalRows ≤ 2147483647
        ∧ (s.history.activeFrames.length + extraPins.length)
            + 17 * (s.history.index.values.dirs.val.length + totalDirs + 2) + 2
          ≤ U32.max
        ∧ 2 * ((s.history.index.values.dirs.val.length + totalDirs)
              + (s.history.index.values.rows.val.length + totalRows)) + 1
          ≤ Usize.max

private theorem framePins_set_perm (frames : List CcfKv.engine.Frame) (k : Nat)
    (old new : CcfKv.engine.Frame) (hget : frames[k]? = some old)
    : (if new.data = 0#u32 then framePins frames else new.data :: framePins frames).Perm
        (if old.data = 0#u32 then framePins (frames.set k new)
         else old.data :: framePins (frames.set k new)) := by
  induction frames generalizing k with
  | nil => simp at hget
  | cons hd tl ih =>
      cases k with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at hget
          subst hget
          simp only [List.set_cons_zero, framePins, List.filterMap_cons]
          by_cases hnew : new.data = 0#u32 <;> by_cases hold : hd.data = 0#u32 <;>
            simp [hnew, hold]
          exact List.Perm.swap _ _ _
      | succ j =>
          simp only [List.getElem?_cons_succ] at hget
          have hsub := ih j hget
          simp only [List.set_cons_succ, framePins, List.filterMap_cons]
          by_cases hhd : hd.data = 0#u32
          · simp only [hhd, ↓reduceIte]
            exact hsub
          · simp only [hhd, ↓reduceIte]
            by_cases hnew : new.data = 0#u32 <;> by_cases hold : old.data = 0#u32
            · simp only [hnew, hold, ↓reduceIte] at hsub ⊢
              exact hsub.cons hd.data
            · simp only [hnew, hold, ↓reduceIte] at hsub ⊢
              exact (hsub.cons hd.data).trans (List.Perm.swap _ _ _)
            · simp only [hnew, hold, ↓reduceIte] at hsub ⊢
              exact (List.Perm.swap _ _ _).trans (hsub.cons hd.data)
            · simp only [hnew, hold, ↓reduceIte] at hsub ⊢
              exact ((List.Perm.swap _ _ _).trans (hsub.cons hd.data)).trans (List.Perm.swap _ _ _)

/-- `Store.apply_backfill_ccf` updates active frames `startOff ..< activeFrames.length`
in place, preserving `BranchValid`, `HistoryIndexValid`, exact `IndexLiveness`
(balanced radix refcounts across every replaced frame and released old root),
`IndexPreservesPins` for all external pins, and applying the exact surviving writes
of `pending` to every frame `startOff + d`. -/
theorem apply_backfill_ccf_refines (s : CcfKv.engine.Store)
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (reservedVer : U64) (startOff : Usize) (extraPins : List U32)
    (valid : BranchValid s.history.log)
    (idxValid : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (framePins s.history.activeFrames ++ extraPins))
    (room : BackfillRoom s pending.val extraPins startOff.val)
    : WP.spec (CcfKv.engine.Store.apply_backfill_ccf s pending reservedVer startOff)
        (fun after =>
          let origFrames := s.history.activeFrames
          let dbs := (origFrames.drop startOff.val).map fun f =>
            indexedCellData (indexRows s.history.index f.data)
          after.history.activeFrames.length = origFrames.length
          ∧ after.history.retained = s.history.retained
          ∧ after.history.global = s.history.global
          ∧ after.history.term = s.history.term
          ∧ after.history.next_identity.val = s.history.next_identity.val + 1
          ∧ after.history.reuse_compacted_images = s.history.reuse_compacted_images
          ∧ after.txs = s.txs
          ∧ BranchValid after.history.log
          ∧ HistoryIndexValid after.history
          ∧ IndexLiveness after.history.index (framePins after.history.activeFrames ++ extraPins)
          ∧ IndexPreservesPins s.history.index after.history.index extraPins
          ∧ (∀ j, j < startOff.val → after.history.activeFrames[j]? = origFrames[j]?)
          ∧ (∀ d (hd : startOff.val + d < origFrames.length),
              let origF := origFrames[startOff.val + d]'hd
              ∃ newF,
                after.history.activeFrames[startOff.val + d]? = some newF
                ∧ newF.version = origF.version
                ∧ (indexedCellData (indexRows after.history.index newF.data)).Perm
                    (Kv.Model.publish
                      (indexedCellData (indexRows s.history.index origF.data))
                      reservedVer.val
                      (byteWrites (filterByMask pending.val (maskAtStep pending.val dbs d)))))) := by
  let origFrames := s.history.activeFrames
  let origLen := origFrames.length
  let dbs : List (DB (List U8) (List U8) (List U8)) :=
    (origFrames.drop startOff.val).map fun f =>
      indexedCellData (indexRows s.history.index f.data)
  let peakRows := origFrames.foldl (fun acc f => max acc (indexRows s.history.index f.data).length) 0
  have hpeakBound : ∀ j (hj : j < origLen),
      (indexRows s.history.index (origFrames[j]'hj).data).length ≤ peakRows := by
    have hfold : ∀ (fs : List CcfKv.engine.Frame) (init : Nat),
        init ≤ fs.foldl (fun acc f => max acc (indexRows s.history.index f.data).length) init
        ∧ ∀ f ∈ fs, (indexRows s.history.index f.data).length
            ≤ fs.foldl (fun acc f => max acc (indexRows s.history.index f.data).length) init := by
      intro fs
      induction fs with
      | nil => intro init; simp
      | cons hd tl ih =>
          intro init
          obtain ⟨h1, h2⟩ := ih (max init (indexRows s.history.index hd.data).length)
          refine ⟨le_trans (Nat.le_max_left _ _) h1, ?_⟩
          intro f hf
          rcases List.mem_cons.mp hf with rfl | htl
          · exact le_trans (Nat.le_max_right _ _) h1
          · exact h2 f htl
    intro j hj
    exact (hfold origFrames 0).2 _ (List.getElem_mem hj)
  obtain ⟨hdirsTotal, hrowsTotal, hrefTotal, hqueueTotal⟩ := room.indexDirs peakRows hpeakBound
  unfold CcfKv.engine.Store.apply_backfill_ccf
  have hlenAct : CcfKv.branch_log.BranchLog.active_len s.history.log = .ok s.history.log.len := rfl
  rw [hlenAct, bind_ok]
  have hlogLen : s.history.log.len.val = origLen := (branch_values_length s.history.log valid).symm
  have hpendLen : (alloc.vec.Vec.len pending).val = pending.val.length := alloc.vec.Vec.len_val _
  have hpendCap := alloc.vec.Vec.len_ineq pending
  have hinitLoop : WP.spec
      (CcfKv.engine.Store.apply_backfill_ccf_loop0 (alloc.vec.Vec.len pending)
        (alloc.vec.Vec.with_capacity Bool (alloc.vec.Vec.len pending)) 0#usize)
      (fun aw => aw.val = List.replicate pending.val.length true) := by
    unfold CcfKv.engine.Store.apply_backfill_ccf_loop0
    apply loop.spec_decr_nat (fun (_, wi) => pending.val.length - wi.val)
      (fun (aw, wi) => wi.val ≤ pending.val.length ∧ aw.val = List.replicate wi.val true)
      _ _ _
    · rintro ⟨aw, wi⟩ ⟨hwi, haw⟩
      dsimp only at hwi haw ⊢
      unfold CcfKv.engine.Store.apply_backfill_ccf_loop0.body
      have hone : (1#usize : Usize).val = 1 := rfl
      by_cases hlt : wi < alloc.vec.Vec.len pending
      · have hwilt : wi.val < pending.val.length := by rwa [← hpendLen]
        rw [ite_eq_left hlt]
        have hawLen : aw.val.length = wi.val := by rw [haw, List.length_replicate]
        apply WP.spec_bind (alloc.vec.Vec.push_spec aw true (by omega))
        intro aw1 haw1
        apply WP.spec_bind (Usize.add_spec (x := wi) (y := 1#usize) (by omega))
        intro wi1 hwi1
        have hwi1Val : wi1.val = wi.val + 1 := by omega
        rw [WP.spec_ok]
        dsimp only
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [haw1, haw, hwi1Val, List.replicate_succ']
      · have hge : pending.val.length ≤ wi.val := by rw [← hpendLen]; exact Nat.le_of_not_gt hlt
        have heq : wi.val = pending.val.length := Nat.le_antisymm hwi hge
        rw [ite_eq_right hlt, WP.spec_ok]
        dsimp only
        rw [haw, heq]
    · simp [alloc.vec.Vec.with_capacity]
  apply WP.spec_bind hinitLoop
  intro aw0 haw0
  let optPin (p : Option CcfKv.radix.RadixRoot) : List U32 :=
    match p with
    | none => []
    | some r => if r = 0#u32 then [] else [r]
  let perStepDirs := pending.val.length * (peakRows + pending.val.length + 1)
  have hmainLoop : WP.spec
      (CcfKv.engine.Store.apply_backfill_ccf_loop1 s.history.log s.history.index
        pending reservedVer reservedVer s.history.next_identity s.history.log.len
        aw0 none startOff)
      (fun (bl, ai, prevOpt) =>
        BranchValid bl
        ∧ (branchValues bl).length = origLen
        ∧ IndexLiveness ai (optPin prevOpt ++ (framePins (branchValues bl) ++ extraPins))
        ∧ IndexKeeps s.history.index ai
        ∧ (∀ f ∈ branchValues bl, IndexView ai f.data (indexRows ai f.data))
        ∧ ai.values.dirs.val.length ≤ s.history.index.values.dirs.val.length
            + (origLen - startOff.val) * perStepDirs
        ∧ ai.values.rows.val.length ≤ s.history.index.values.rows.val.length
            + (origLen - startOff.val) * pending.val.length
        ∧ (∀ j, j < startOff.val → (branchValues bl)[j]? = origFrames[j]?)
        ∧ (∀ d (hd : startOff.val + d < origLen),
            let origF := origFrames[startOff.val + d]'hd
            ∃ newF,
              (branchValues bl)[startOff.val + d]? = some newF
              ∧ newF.version = origF.version
              ∧ (indexedCellData (indexRows ai newF.data)).Perm
                  (Kv.Model.publish
                    (indexedCellData (indexRows s.history.index origF.data))
                    reservedVer.val
                    (byteWrites (filterByMask pending.val (maskAtStep pending.val dbs d)))))) := by
    unfold CcfKv.engine.Store.apply_backfill_ccf_loop1
    apply loop.spec_decr_nat (fun (_, _, _, _, off) => origLen - off.val)
      (fun (bl, ai, aw, prevOpt, off) =>
        startOff.val ≤ off.val
        ∧ off.val ≤ origLen
        ∧ BranchValid bl
        ∧ bl.len = s.history.log.len
        ∧ (branchValues bl).length = origLen
        ∧ IndexLiveness ai (optPin prevOpt ++ (framePins (branchValues bl) ++ extraPins))
        ∧ IndexKeeps s.history.index ai
        ∧ (∀ f ∈ branchValues bl, IndexView ai f.data (indexRows ai f.data))
        ∧ ai.values.dirs.val.length ≤ s.history.index.values.dirs.val.length
            + (off.val - startOff.val) * perStepDirs
        ∧ ai.values.rows.val.length ≤ s.history.index.values.rows.val.length
            + (off.val - startOff.val) * pending.val.length
        ∧ (∀ j, j < startOff.val → (branchValues bl)[j]? = origFrames[j]?)
        ∧ (∀ j, off.val ≤ j → (branchValues bl)[j]? = origFrames[j]?)
        ∧ (∀ d (hd : startOff.val + d < off.val),
            ∃ origF newF,
              origFrames[startOff.val + d]? = some origF
              ∧ (branchValues bl)[startOff.val + d]? = some newF
              ∧ newF.version = origF.version
              ∧ (indexedCellData (indexRows ai newF.data)).Perm
                  (Kv.Model.publish
                    (indexedCellData (indexRows s.history.index origF.data))
                    reservedVer.val
                    (byteWrites (filterByMask pending.val (maskAtStep pending.val dbs d)))))
        ∧ (if off.val = startOff.val then
            prevOpt = none ∧ aw.val = List.replicate pending.val.length true
          else
            ∃ hprev : off.val - 1 < origLen,
              prevOpt = some (origFrames[off.val - 1]'hprev).data
              ∧ aw.val = maskAtStep pending.val dbs (off.val - 1 - startOff.val)))
      _ _ _
    · rintro ⟨bl, ai, aw, prevOpt, off⟩
        ⟨hgeStart, hleEnd, hblValid, hblLenEq, hbvLen, haiLive, haiKeeps, haiViews,
          hdirsB, hrowsB, hpreEq, hsufEq, hdoneFrames, hprevInv⟩
      dsimp only
      unfold CcfKv.engine.Store.apply_backfill_ccf_loop1.body
      have hcapLog : s.history.log.len.val ≤ Usize.max := by scalar_tac
      have hone : (1#usize : Usize).val = 1 := rfl
      by_cases hlt : off < s.history.log.len
      · have hoffLt : off.val < origLen := by rw [← hlogLen]; exact hlt
        rw [ite_eq_left hlt]
        let origF := origFrames[off.val]'hoffLt
        have hblGet : (branchValues bl)[off.val]? = some origF := by
          rw [hsufEq off.val (Nat.le_refl _), List.getElem?_eq_getElem hoffLt]
        apply WP.spec_bind (branch_active_at bl hblValid off origF hblGet)
        intro fCur hfCur; rw [hfCur]
        have hcurOrigView : IndexView ai origF.data (indexRows s.history.index origF.data) :=
          index_keeps_view haiKeeps origF.data _ (idxValid.active origF (List.getElem_mem hoffLt))
        have hcurRowsEq : indexRows ai origF.data = indexRows s.history.index origF.data :=
          index_rows_eq hcurOrigView
        let dCur := off.val - startOff.val
        have hdbsCur : dbs[dCur]? = some (indexedCellData (indexRows s.history.index origF.data)) := by
          unfold dbs
          rw [List.getElem?_map, List.getElem?_drop, show startOff.val + dCur = off.val by omega,
            List.getElem?_eq_getElem hoffLt]
          rfl
        have hfilterStep : WP.spec
            (match prevOpt with
              | none => Result.ok (ai, aw)
              | some prev => do
                  let aw2 ← CcfKv.engine.filter_overwritten_writes ai prev origF.data pending aw
                  let ai2 ← CcfKv.kv_index.AddressIndex.release_root ai prev
                  Result.ok (ai2, aw2))
            (fun (ai1, aw1) =>
              ai1.values = ai.values
              ∧ IndexLiveness ai1 (framePins (branchValues bl) ++ extraPins)
              ∧ aw1.val = maskAtStep pending.val dbs dCur) := by
          by_cases hfirst : off.val = startOff.val
          · rw [ite_eq_left hfirst] at hprevInv
            obtain ⟨rfl, hawEq⟩ := hprevInv
            rw [WP.spec_ok]
            refine ⟨rfl, ?_, ?_⟩
            · simpa [optPin] using haiLive
            · have hd0 : dCur = 0 := by omega
              rw [hd0, maskAtStep, hawEq]
          · rw [ite_eq_right hfirst] at hprevInv
            obtain ⟨hprevLt, rfl, hawEq⟩ := hprevInv
            let prevF := origFrames[off.val - 1]'hprevLt
            have hprevView : IndexView ai prevF.data (indexRows s.history.index prevF.data) :=
              index_keeps_view haiKeeps prevF.data _ (idxValid.active prevF (List.getElem_mem hprevLt))
            have hawLen : aw.val.length = pending.val.length := by
              rw [hawEq, maskAtStep_length]
            apply WP.spec_bind
              (filter_overwritten_writes_refines ai prevF.data origF.data
                (indexRows s.history.index prevF.data) (indexRows s.history.index origF.data)
                hprevView hcurOrigView pending aw hawLen room.addresses)
            intro aw2 ⟨_, haw2Eq⟩
            have hqAi : 2 * (ai.values.dirs.val.length + ai.values.rows.val.length) + 1 ≤ Usize.max := by
              have hleSpan : off.val - startOff.val ≤ origLen - startOff.val := by omega
              have hdMul : (off.val - startOff.val) * perStepDirs ≤ (origLen - startOff.val) * perStepDirs :=
                Nat.mul_le_mul_right _ hleSpan
              have hrMul : (off.val - startOff.val) * pending.val.length ≤ (origLen - startOff.val) * pending.val.length :=
                Nat.mul_le_mul_right _ hleSpan
              dsimp only [perStepDirs, origLen, origFrames] at hdirsB hrowsB hdMul hrMul
              omega
            have hrelSpec : WP.spec (CcfKv.kv_index.AddressIndex.release_root ai prevF.data)
                (fun ai2 => ai2.values = ai.values ∧ IndexLiveness ai2 (framePins (branchValues bl) ++ extraPins)) := by
              have hliveMatch : IndexLiveness ai
                  (if prevF.data = 0#u32 then framePins (branchValues bl) ++ extraPins
                   else prevF.data :: (framePins (branchValues bl) ++ extraPins)) := by
                by_cases hz : prevF.data = 0#u32 <;> simpa [optPin, prevF, hz] using haiLive
              exact index_release_root_refines ai (framePins (branchValues bl) ++ extraPins)
                prevF.data hliveMatch hqAi
            apply WP.spec_bind hrelSpec
            intro ai2 ⟨hai2Vals, hai2Live⟩
            rw [WP.spec_ok]
            refine ⟨hai2Vals, hai2Live, ?_⟩
            have hdSucc : dCur = (off.val - 1 - startOff.val) + 1 := by omega
            have hdbsPrev : dbs[off.val - 1 - startOff.val]?
                = some (indexedCellData (indexRows s.history.index prevF.data)) := by
              unfold dbs
              rw [List.getElem?_map, List.getElem?_drop,
                show startOff.val + (off.val - 1 - startOff.val) = off.val - 1 by omega,
                List.getElem?_eq_getElem hprevLt]
              rfl
            have hdbsNext : dbs[(off.val - 1 - startOff.val) + 1]?
                = some (indexedCellData (indexRows s.history.index origF.data)) := by
              rw [← hdSucc]; exact hdbsCur
            rw [hdSucc, maskAtStep, hdbsPrev, hdbsNext, ← hawEq]
            exact haw2Eq
        apply WP.spec_bind hfilterStep
        rintro ⟨ai1, aw1⟩ ⟨hai1Vals, hai1Live, haw1Eq⟩
        have haw1Len : aw1.val.length = pending.val.length := by
          rw [haw1Eq, maskAtStep_length]
        apply WP.spec_bind (collect_active_writes_refines pending aw1 haw1Len)
        intro filtered hfiltEq
        have hfiltSub : ∀ row ∈ filtered.val, row ∈ pending.val := by
          rw [hfiltEq]; exact filterByMask_subset pending.val aw1.val
        have hfiltLenLe : filtered.val.length ≤ pending.val.length := by
          rw [hfiltEq]; exact filterByMask_length_le pending.val aw1.val
        have hemptySpec : alloc.vec.Vec.is_empty filtered = .ok (decide (filtered.val = [])) := by
          simp [alloc.vec.Vec.is_empty]
        rw [hemptySpec, bind_ok]
        by_cases hempty : filtered.val = []
        · rw [decide_eq_true hempty, ite_eq_left rfl, WP.spec_ok]
          have hai1Keeps : IndexKeeps s.history.index ai1 := by
            have h1 : IndexKeeps ai ai1 := by unfold IndexKeeps; rw [hai1Vals]; exact .refl _
            exact haiKeeps.trans h1
          have hmaskEmptyLater : ∀ d, dCur ≤ d → startOff.val + d < origLen →
              filterByMask pending.val (maskAtStep pending.val dbs d) = [] := by
            intro d hdGe hdLt
            have hzero : ∀ i (hi : i < pending.val.length),
                (maskAtStep pending.val dbs dCur).getD i false = false := by
              intro i hi
              by_contra hne
              have htrue : (maskAtStep pending.val dbs dCur).getD i false = true := by
                cases h : (maskAtStep pending.val dbs dCur).getD i false <;> simp_all
              have hmem : (pending.val[i]'hi) ∈ filtered.val := by
                rw [hfiltEq, haw1Eq]
                unfold filterByMask
                refine List.mem_filterMap.mpr ⟨i, List.mem_range.mpr hi, ?_⟩
                rw [htrue, ite_eq_left rfl, List.getElem?_eq_getElem hi]
              rw [hempty] at hmem; cases hmem
            have hmono : ∀ m, dCur ≤ m → ∀ i (hi : i < pending.val.length),
                (maskAtStep pending.val dbs m).getD i false = false := by
              intro m hm
              induction m with
              | zero =>
                  have : dCur = 0 := by omega
                  rw [← this]; exact hzero
              | succ m ihm =>
                  by_cases hmeq : m + 1 = dCur
                  · rw [hmeq]; exact hzero
                  · intro i hi
                    have hprevF := ihm (by omega) i hi
                    unfold maskAtStep
                    cases dbs[m]? <;> cases dbs[m + 1]?
                    · exact hprevF
                    · exact hprevF
                    · exact hprevF
                    · change ((updateActiveMask _ _ _ _)[i]?).getD false = false
                      unfold updateActiveMask
                      rw [List.getElem?_map, List.getElem?_range hi, Option.map_some,
                        Option.getD_some, hprevF]
                      rfl
            apply List.eq_nil_iff_forall_not_mem.mpr
            intro row hmem
            unfold filterByMask at hmem
            obtain ⟨i, hiRange, hiSpec⟩ := List.mem_filterMap.mp hmem
            have hi : i < pending.val.length := List.mem_range.mp hiRange
            rw [hmono d hdGe i hi] at hiSpec
            simp at hiSpec
          have hleSpan : off.val - startOff.val ≤ origLen - startOff.val := by omega
          refine ⟨hblValid, hbvLen, by simpa [optPin] using hai1Live, hai1Keeps, ?_,
            by rw [hai1Vals]; exact le_trans hdirsB (Nat.add_le_add_left (Nat.mul_le_mul_right _ hleSpan) _),
            by rw [hai1Vals]; exact le_trans hrowsB (Nat.add_le_add_left (Nat.mul_le_mul_right _ hleSpan) _),
            hpreEq, ?_⟩
          · intro f hf
            have hv := index_keeps_view (by unfold IndexKeeps; rw [hai1Vals]; exact .refl _ : IndexKeeps ai ai1)
              f.data _ (haiViews f hf)
            rw [index_rows_eq hv]; exact hv
          · intro d hd
            by_cases hdDone : startOff.val + d < off.val
            · obtain ⟨origF', newF, horigGet, hnewGet, hverD, hpermD⟩ := hdoneFrames d hdDone
              have horigEq : origF' = origFrames[startOff.val + d]'hd := by
                rw [List.getElem?_eq_getElem hd] at horigGet
                exact Option.some.inj horigGet.symm
              subst horigEq
              have hrowsStay : indexRows ai1 newF.data = indexRows ai newF.data := by
                have hv := index_keeps_view (by unfold IndexKeeps; rw [hai1Vals]; exact .refl _ : IndexKeeps ai ai1)
                  _ _ (haiViews _ (List.mem_of_getElem? hnewGet))
                exact index_rows_eq hv
              exact ⟨newF, hnewGet, hverD, by rwa [hrowsStay]⟩
            · have hstillOrig : (branchValues bl)[startOff.val + d]? = some (origFrames[startOff.val + d]'hd) := by
                rw [hsufEq (startOff.val + d) (by omega), List.getElem?_eq_getElem hd]
              have hrowsStay : indexRows ai1 (origFrames[startOff.val + d]'hd).data
                  = indexRows s.history.index (origFrames[startOff.val + d]'hd).data := by
                have hv := index_keeps_view hai1Keeps _ _ (idxValid.active _ (List.getElem_mem hd))
                exact index_rows_eq hv
              refine ⟨origFrames[startOff.val + d]'hd, hstillOrig, rfl, ?_⟩
              rw [hrowsStay, hmaskEmptyLater d (by omega) hd]
              simp [byteWrites, Kv.Model.publish]
        · rw [decide_eq_false hempty, ite_eq_right (by decide : ¬false = true)]
          rw [clone_assoc, bind_ok, clone_assoc, bind_ok]
          have hcurView1 : IndexView ai1 origF.data (indexRows s.history.index origF.data) :=
            index_keeps_view (by unfold IndexKeeps; rw [hai1Vals]; exact .refl _ : IndexKeeps ai ai1)
              origF.data _ hcurOrigView
          obtain ⟨hrevRm, hbrtRm⟩ := room.stampsRoom off.val hoffLt hgeStart
          apply WP.spec_bind
            (apply_backfill_stamps_refines origF.revisions origF.births ai1 origF.data
              (indexRows s.history.index origF.data) hcurView1 filtered
              { version := reservedVer, identity := s.history.next_identity }
              (by dsimp only [origF, origFrames] at *; omega)
              (by dsimp only [origF, origFrames] at *; omega)
              (fun r hr => room.addresses r (hfiltSub r hr)))
          rintro ⟨rev1, brt1⟩ _
          have hrootPin : origF.data = 0#u32 ∨ origF.data ∈ framePins (branchValues bl) ++ extraPins := by
            by_cases hz : origF.data = 0#u32
            · exact Or.inl hz
            · refine Or.inr (List.mem_append_left extraPins ?_)
              exact List.mem_filterMap.mpr ⟨origF, List.mem_of_getElem? hblGet, by simp [hz]⟩
          have hrowPeak : (indexRows s.history.index origF.data).length ≤ peakRows :=
            hpeakBound off.val hoffLt
          have hfpLen : (framePins (branchValues bl) ++ extraPins).length
              ≤ origLen + extraPins.length := by
            rw [List.length_append]
            have : (framePins (branchValues bl)).length ≤ origLen := by
              unfold framePins
              calc ((branchValues bl).filterMap _).length ≤ (branchValues bl).length := List.length_filterMap_le _ _
                _ = origLen := hbvLen
            omega
          have hbatchRoom : IndexBatchRoom ai1 (framePins (branchValues bl) ++ extraPins).length
              ((indexRows s.history.index origF.data).length + filtered.val.length)
              filtered.val.length := by
            have hrem : off.val - startOff.val + 1 ≤ origLen - startOff.val := by omega
            have hdirsNext : ai1.values.dirs.val.length + perStepDirs
                ≤ s.history.index.values.dirs.val.length + (origLen - startOff.val) * perStepDirs := by
              rw [hai1Vals]
              have hmul : (off.val - startOff.val) * perStepDirs + perStepDirs
                  = (off.val - startOff.val + 1) * perStepDirs := by
                rw [Nat.add_mul, Nat.one_mul]
              have hle : (off.val - startOff.val + 1) * perStepDirs
                  ≤ (origLen - startOff.val) * perStepDirs := Nat.mul_le_mul_right _ hrem
              omega
            have hrowsNext : ai1.values.rows.val.length + pending.val.length
                ≤ s.history.index.values.rows.val.length + (origLen - startOff.val) * pending.val.length := by
              rw [hai1Vals]
              have hmul : (off.val - startOff.val) * pending.val.length + pending.val.length
                  = (off.val - startOff.val + 1) * pending.val.length := by
                rw [Nat.add_mul, Nat.one_mul]
              have hle : (off.val - startOff.val + 1) * pending.val.length
                  ≤ (origLen - startOff.val) * pending.val.length := Nat.mul_le_mul_right _ hrem
              omega
            have hfiltMul : filtered.val.length * ((indexRows s.history.index origF.data).length + filtered.val.length + 1)
                ≤ perStepDirs := by
              exact Nat.mul_le_mul hfiltLenLe (by omega)
            dsimp only [perStepDirs, origLen, origFrames] at hdirsNext hrowsNext hfiltMul hfpLen
            refine ⟨?_, ?_, ?_, ?_⟩
            · omega
            · omega
            · omega
            · omega
          apply WP.spec_bind
            (indexed_publication_refines ai1 origF.data (indexRows s.history.index origF.data)
              filtered reservedVer (framePins (branchValues bl) ++ extraPins) hcurView1 hai1Live
              hrootPin hbatchRoom (fun r hr => room.addresses r (hfiltSub r hr)))
          rintro ⟨newRoot, ai2⟩ ⟨⟨outRows, houtView, houtPerm⟩, hai2Live, hai2Keeps, hai2Growth⟩
          let newF : CcfKv.engine.Frame :=
            { origF with data := newRoot, revisions := rev1, births := brt1 }
          have hoffBlLt : off.val < bl.len.val := by rw [hblLenEq, hlogLen]; exact hoffLt
          apply WP.spec_bind (branch_replace_active_at_refines bl off newF hblValid hoffBlLt)
          rintro ⟨oldFrame, bl1⟩ ⟨holdGet, hbl1Valid, hbl1Len, _, _, hbl1Vals⟩
          have holdEq : oldFrame = origF := Option.some.inj (holdGet.symm.trans hblGet)
          subst holdEq
          apply WP.spec_bind (Usize.add_spec (x := off) (y := 1#usize) (by omega))
          intro off1 hoff1
          have hoff1Val : off1.val = off.val + 1 := by omega
          rw [WP.spec_ok]
          dsimp only
          have hai1KeepsS : IndexKeeps s.history.index ai1 :=
            haiKeeps.trans (by unfold IndexKeeps; rw [hai1Vals]; exact .refl _)
          have hai2KeepsS : IndexKeeps s.history.index ai2 := hai1KeepsS.trans hai2Keeps
          have hai2KeepsAi : IndexKeeps ai ai2 :=
            (by unfold IndexKeeps; rw [hai1Vals]; exact .refl _ : IndexKeeps ai ai1).trans hai2Keeps
          have hliveAfter : IndexLiveness ai2 (optPin (some origF.data) ++ (framePins (branchValues bl1) ++ extraPins)) := by
            have hfpSwap := framePins_set_perm (branchValues bl) off.val origF newF hblGet
            rw [← hbl1Vals] at hfpSwap
            have hperm : (if newRoot = 0#u32 then framePins (branchValues bl) ++ extraPins
                else newRoot :: (framePins (branchValues bl) ++ extraPins)).Perm
                (optPin (some origF.data) ++ (framePins (branchValues bl1) ++ extraPins)) := by
              have h1 : (if newRoot = 0#u32 then framePins (branchValues bl) ++ extraPins
                  else newRoot :: (framePins (branchValues bl) ++ extraPins))
                  = (if newF.data = 0#u32 then framePins (branchValues bl)
                    else newF.data :: framePins (branchValues bl)) ++ extraPins := by
                by_cases hnr : newRoot = 0#u32 <;> simp [newF, hnr]
              have h2 : optPin (some origF.data) ++ (framePins (branchValues bl1) ++ extraPins)
                  = (if origF.data = 0#u32 then framePins (branchValues bl1)
                    else origF.data :: framePins (branchValues bl1)) ++ extraPins := by
                by_cases ho : origF.data = 0#u32 <;> simp [optPin, ho]
              rw [h1, h2]
              exact hfpSwap.append_right extraPins
            exact hai2Live.perm hperm
          have hbv1Len : (branchValues bl1).length = origLen := by
            rw [hbl1Vals, List.length_set, hbvLen]
          have hviewsAfter : ∀ f ∈ branchValues bl1, IndexView ai2 f.data (indexRows ai2 f.data) := by
            intro f hf
            rw [hbl1Vals] at hf
            obtain ⟨idxF, hidxLt, hidxEq⟩ := List.getElem_of_mem hf
            rw [List.length_set] at hidxLt
            by_cases hkeq : idxF = off.val
            · subst hkeq
              rw [List.getElem_set_self] at hidxEq
              rw [← hidxEq]
              change IndexView ai2 newRoot (indexRows ai2 newRoot)
              rw [index_rows_eq houtView]; exact houtView
            · rw [List.getElem_set_ne (Ne.symm hkeq)] at hidxEq
              have holdMem : f ∈ branchValues bl := by rw [← hidxEq]; exact List.getElem_mem hidxLt
              have hv := index_keeps_view hai2KeepsAi f.data _ (haiViews f holdMem)
              rw [index_rows_eq hv]; exact hv
          have hdirsAfter : ai2.values.dirs.val.length
              ≤ s.history.index.values.dirs.val.length + (off1.val - startOff.val) * perStepDirs := by
            have hstepD : filtered.val.length * ((indexRows s.history.index origF.data).length + filtered.val.length + 1)
                ≤ perStepDirs := Nat.mul_le_mul hfiltLenLe (by omega)
            have hmul : (off1.val - startOff.val) * perStepDirs
                = (off.val - startOff.val) * perStepDirs + perStepDirs := by
              rw [show off1.val - startOff.val = (off.val - startOff.val) + 1 by omega,
                Nat.add_mul, Nat.one_mul]
            have hg := hai2Growth.1
            rw [hai1Vals] at hg
            omega
          have hrowsAfter : ai2.values.rows.val.length
              ≤ s.history.index.values.rows.val.length + (off1.val - startOff.val) * pending.val.length := by
            have hmul : (off1.val - startOff.val) * pending.val.length
                = (off.val - startOff.val) * pending.val.length + pending.val.length := by
              rw [show off1.val - startOff.val = (off.val - startOff.val) + 1 by omega,
                Nat.add_mul, Nat.one_mul]
            have hg := hai2Growth.2
            rw [hai1Vals] at hg
            omega
          refine ⟨⟨by omega, by omega, hbl1Valid, hbl1Len.trans hblLenEq, hbv1Len, hliveAfter,
            hai2KeepsS, hviewsAfter, hdirsAfter, hrowsAfter, ?_, ?_, ?_, ?_⟩, by omega⟩
          · intro j hj
            rw [hbl1Vals, List.getElem?_set_ne (by omega)]
            exact hpreEq j hj
          · intro j hj
            rw [hbl1Vals, List.getElem?_set_ne (by omega)]
            exact hsufEq j (by omega)
          · intro d hd
            by_cases hdeq : startOff.val + d = off.val
            · have hdEqCur : d = dCur := by omega
              have hgetNew : (branchValues bl1)[startOff.val + d]? = some newF := by
                rw [hbl1Vals, hdeq, List.getElem?_set_self (by omega)]
              have hgetOrig : origFrames[startOff.val + d]? = some origF := by
                rw [hdeq, List.getElem?_eq_getElem hoffLt]
              refine ⟨origF, newF, hgetOrig, hgetNew, rfl, ?_⟩
              change (indexedCellData (indexRows ai2 newRoot)).Perm _
              rw [index_rows_eq houtView]
              have hproj := indexed_fold_projects (indexRows s.history.index origF.data) filtered.val reservedVer
              have hpermCell : (indexedCellData outRows).Perm
                  (indexedCellData (filtered.val.foldr (applyIndexedWrite reservedVer)
                    (indexRows s.history.index origF.data))) := by
                unfold indexedCellData
                exact houtPerm.map _
              rw [hproj, hfiltEq, haw1Eq, ← hdEqCur] at hpermCell
              exact hpermCell
            · have hltPrev : startOff.val + d < off.val := by omega
              obtain ⟨origF', newF', horigGet, hgetPrev, hverD, hpermD⟩ := hdoneFrames d hltPrev
              have hgetEq : (branchValues bl1)[startOff.val + d]? = some newF' := by
                rw [hbl1Vals, List.getElem?_set_ne (show off.val ≠ startOff.val + d by omega), hgetPrev]
              have hrowsStay : indexRows ai2 newF'.data = indexRows ai newF'.data := by
                have hv := index_keeps_view hai2KeepsAi _ _ (haiViews _ (List.mem_of_getElem? hgetPrev))
                exact index_rows_eq hv
              exact ⟨origF', newF', horigGet, hgetEq, hverD, by rwa [hrowsStay]⟩
          · rw [ite_eq_right (by omega)]
            refine ⟨by omega, ?_, ?_⟩
            · simp only [show off1.val - 1 = off.val by omega]; rfl
            · simp only [show off1.val - 1 - startOff.val = dCur by omega]; exact haw1Eq
      · have hge : origLen ≤ off.val := by rw [← hlogLen]; exact Nat.le_of_not_gt hlt
        have hoffEq : off.val = origLen := Nat.le_antisymm hleEnd hge
        rw [ite_eq_right hlt, WP.spec_ok]
        refine ⟨hblValid, hbvLen, haiLive, haiKeeps, haiViews,
          by simpa [hoffEq] using hdirsB, by simpa [hoffEq] using hrowsB, hpreEq, ?_⟩
        intro d hd
        obtain ⟨origF', newF', horigGet, hnewGet, hverD, hpermD⟩ := hdoneFrames d (by omega)
        have horigEq : origF' = origFrames[startOff.val + d]'hd := by
          rw [List.getElem?_eq_getElem hd] at horigGet
          exact Option.some.inj horigGet.symm
        subst horigEq
        exact ⟨newF', hnewGet, hverD, hpermD⟩
    · refine ⟨Nat.le_refl _, Nat.le_of_lt room.startLt, valid, rfl, rfl, ?_, .refl _,
        idxValid.active, by simp, by simp, fun _ _ => rfl, fun _ _ => rfl, ?_, ?_⟩
      · simpa [optPin] using live
      · intro d hd; omega
      · rw [ite_eq_left rfl]; exact ⟨rfl, haw0⟩
  apply WP.spec_bind hmainLoop
  rintro ⟨bl, ai, prevOpt⟩ ⟨hblValid, hbvLen, haiLive, haiKeeps, haiViews, hdirsB, hrowsB, hpreEq, hdone⟩
  have hqAi : 2 * (ai.values.dirs.val.length + ai.values.rows.val.length) + 1 ≤ Usize.max := by
    dsimp only [perStepDirs, origLen, origFrames] at hdirsB hrowsB
    omega
  have hrelFinal : WP.spec
      (match prevOpt with
        | none => Result.ok ai
        | some prev => CcfKv.kv_index.AddressIndex.release_root ai prev)
      (fun ai1 =>
        ai1.values = ai.values
        ∧ IndexLiveness ai1 (framePins (branchValues bl) ++ extraPins)) := by
    cases prevOpt with
    | none =>
        rw [WP.spec_ok]
        exact ⟨rfl, by simpa [optPin] using haiLive⟩
    | some prev =>
        have hliveMatch : IndexLiveness ai
            (if prev = 0#u32 then framePins (branchValues bl) ++ extraPins
             else prev :: (framePins (branchValues bl) ++ extraPins)) := by
          by_cases hz : prev = 0#u32 <;> simpa [optPin, hz] using haiLive
        exact index_release_root_refines ai (framePins (branchValues bl) ++ extraPins)
          prev hliveMatch hqAi
  apply WP.spec_bind hrelFinal
  rintro ai1 ⟨hai1Vals, hai1Live⟩
  have hone64 : (1#u64 : U64).val = 1 := rfl
  apply WP.spec_bind (U64.add_spec (x := s.history.next_identity) (y := 1#u64) (by have := room.nextId; omega))
  intro nextId hnextId
  have hqAi1 : 2 * (ai1.values.dirs.val.length + ai1.values.rows.val.length) + 1 ≤ Usize.max := by
    rw [hai1Vals]; exact hqAi
  apply WP.spec_bind
    (index_retire_budget_refines ai1 (framePins (branchValues bl) ++ extraPins)
      CcfKv.engine.RETIRE_BUDGET hai1Live hqAi1)
  rintro ⟨_, ai2⟩ ⟨hai2Live, hai2Pres, _, _⟩
  change WP.spec (Result.ok _) _
  rw [WP.spec_ok]
  have haiKeeps1 : IndexKeeps s.history.index ai1 :=
    haiKeeps.trans (by unfold IndexKeeps; rw [hai1Vals]; exact .refl _)
  have hpresExtra : IndexPreservesPins s.history.index ai2 extraPins := by
    have h1 : IndexPreservesPins s.history.index ai1 extraPins := fun r _ links sv =>
      single_retains_views s.history.index ai1 haiKeeps1 r links sv
    have h2 : IndexPreservesPins ai1 ai2 extraPins := fun r hr links sv =>
      hai2Pres r (List.mem_append_right _ hr) links sv
    exact h1.trans h2
  have hpresBl : IndexPreservesPins ai ai2 (framePins (branchValues bl)) := by
    have h1 : IndexPreservesPins ai ai1 (framePins (branchValues bl)) := fun r _ links sv =>
      single_retains_views ai ai1 (by rw [hai1Vals]; exact .refl _) r links sv
    have h2 : IndexPreservesPins ai1 ai2 (framePins (branchValues bl)) := fun r hr links sv =>
      hai2Pres r (List.mem_append_left _ hr) links sv
    exact h1.trans h2
  have hviews2 : ∀ f ∈ branchValues bl, IndexView ai2 f.data (indexRows ai2 f.data)
      ∧ indexRows ai2 f.data = indexRows ai f.data := by
    intro f hf
    have hv0 := haiViews f hf
    by_cases hz : f.data = 0#u32
    · have hEmptyView (idx : CellIndex) : IndexView idx 0#u32 [] := by
        have h := index_empty_root_refines idx
        unfold CcfKv.kv_index.AddressIndex.empty_root CcfKv.radix.SingleRadix.empty_root at h
        rw [WP.spec_ok] at h
        exact h.2
      have hvZero2 : IndexView ai2 0#u32 [] := hEmptyView ai2
      have hvZero : IndexView ai 0#u32 [] := hEmptyView ai
      have h0 : indexRows ai 0#u32 = [] := index_rows_eq hvZero
      rw [hz, index_rows_eq hvZero2, h0]
      exact ⟨hvZero2, rfl⟩
    · have hmem : f.data ∈ framePins (branchValues bl) :=
        List.mem_filterMap.mpr ⟨f, hf, by simp [hz]⟩
      obtain ⟨links, sv, proj⟩ := hv0.witness
      obtain ⟨sv2, same⟩ := hpresBl f.data hmem links sv
      have hv1 : IndexView ai2 f.data (indexRows ai f.data) :=
        ⟨links, sv2, same.trans proj⟩
      rw [index_rows_eq hv1]
      exact ⟨hv1, rfl⟩
  have hnextEq : nextId.val = s.history.next_identity.val + 1 := by
    have h1 := hnextId
    rw [hone64] at h1
    exact h1
  refine ⟨hbvLen, rfl, rfl, rfl, hnextEq, rfl, rfl, hblValid,
    ⟨hai2Live.valid, fun f hf => (hviews2 f hf).1, idxValid.retainedEmpty⟩,
    hai2Live, hpresExtra, hpreEq, ?_⟩
  intro d hd
  obtain ⟨newF, hgetNew, hverD, hpermD⟩ := hdone d hd
  have hmemD : newF ∈ branchValues bl := List.mem_of_getElem? hgetNew
  exact ⟨newF, hgetNew, hverD, by rw [(hviews2 _ hmemD).2]; exact hpermD⟩

/-- End-to-end linearizability of extracted `Store.apply_backfill_ccf`:
under `NoSilentRemove` and `Kv.Model.publish` post-reservation history steps,
every backfilled frame `startOff + d` produced by Rust `Store::apply_backfill_ccf`
agrees on `Kv.Model.find` at every address with linearly publishing `pending` at
`reservedVer` first and then replaying `commits.take d` through `Kv.Model.publish`. -/
theorem apply_backfill_ccf_linearizes (s : CcfKv.engine.Store)
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (reservedVer : U64) (startOff : Usize) (extraPins : List U32)
    (commits : List (Nat × Writes (List U8) (List U8) (List U8)))
    (valid : BranchValid s.history.log)
    (idxValid : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (framePins s.history.activeFrames ++ extraPins))
    (room : BackfillRoom s pending.val extraPins startOff.val)
    (hUnique0 : Kv.Properties.Unique (byteWrites pending.val))
    (hSpan : s.history.activeFrames.length - startOff.val = commits.length + 1)
    (hSteps :
      let dbs := (s.history.activeFrames.drop startOff.val).map fun f =>
        indexedCellData (indexRows s.history.index f.data)
      ∀ k (hk : k < commits.length),
        dbs[k + 1]'(by simp [dbs]; omega)
          = Kv.Model.publish (dbs[k]'(by simp [dbs]; omega)) (commits[k]'hk).1 (commits[k]'hk).2
        ∧ reservedVer.val < (commits[k]'hk).1
        ∧ ByteCellsBounded (dbs[k]'(by simp [dbs]; omega)) ((commits[k]'hk).1 - 1)
        ∧ NoSilentRemove (byteWrites pending.val) (dbs[k]'(by simp [dbs]; omega)) (commits[k]'hk).2)
    : WP.spec (CcfKv.engine.Store.apply_backfill_ccf s pending reservedVer startOff)
        (fun after =>
          let dbs := (s.history.activeFrames.drop startOff.val).map fun f =>
            indexedCellData (indexRows s.history.index f.data)
          after.history.activeFrames.length = s.history.activeFrames.length
          ∧ BranchValid after.history.log
          ∧ HistoryIndexValid after.history
          ∧ IndexLiveness after.history.index (framePins after.history.activeFrames ++ extraPins)
          ∧ ∀ d (_ : d ≤ commits.length) (a : Addr (List U8) (List U8)),
              ∃ newF,
                after.history.activeFrames[startOff.val + d]? = some newF
                ∧ find (indexedCellData (indexRows after.history.index newF.data)) a
                  = find
                      (replayPublish
                        (Kv.Model.publish (dbs[0]'(by simp [dbs]; omega)) reservedVer.val
                          (byteWrites pending.val))
                        (commits.take d))
                      a) := by
  apply WP.spec_mono
    (apply_backfill_ccf_refines s pending reservedVer startOff extraPins valid idxValid live room)
  intro after ⟨hlen, _, _, _, _, _, _, hblValid, hidxValid, hlive, _, _, hframes⟩
  refine ⟨hlen, hblValid, hidxValid, hlive, ?_⟩
  intro d hd a
  let dbs := (s.history.activeFrames.drop startOff.val).map fun f =>
    indexedCellData (indexRows s.history.index f.data)
  have hdbsLen : dbs.length = commits.length + 1 := by simp [dbs, hSpan]
  have hdLt : startOff.val + d < s.history.activeFrames.length := by
    have := room.startLt; omega
  obtain ⟨newF, hnewGet, _, hperm⟩ := hframes d hdLt
  have huniqBase : Kv.Properties.Unique
      (indexedCellData (indexRows s.history.index (s.history.activeFrames[startOff.val + d]'hdLt).data)) :=
    indexedCellData_unique (idxValid.active _ (List.getElem_mem hdLt))
  have huniqPub : Kv.Properties.Unique
      (Kv.Model.publish
        (indexedCellData (indexRows s.history.index (s.history.activeFrames[startOff.val + d]'hdLt).data))
        reservedVer.val
        (byteWrites (filterByMask pending.val (maskAtStep pending.val dbs d)))) :=
    Kv.Properties.publish_unique _ _ _ huniqBase
  have hfindPerm : find (indexedCellData (indexRows after.history.index newF.data)) a
      = find
          (Kv.Model.publish
            (indexedCellData (indexRows s.history.index (s.history.activeFrames[startOff.val + d]'hdLt).data))
            reservedVer.val
            (byteWrites (filterByMask pending.val (maskAtStep pending.val dbs d)))) a :=
    lookup_perm hperm (unique_of_perm hperm.symm huniqPub) a
  have hdbsAt : dbs[d]'(by omega)
      = indexedCellData (indexRows s.history.index (s.history.activeFrames[startOff.val + d]'hdLt).data) := by
    simp [dbs]
  refine ⟨newF, hnewGet, ?_⟩
  rw [hfindPerm, ← hdbsAt]
  exact backfill_model_linearizes pending.val reservedVer.val dbs commits hUnique0 hdbsLen hSteps d hd a

end KvRust
