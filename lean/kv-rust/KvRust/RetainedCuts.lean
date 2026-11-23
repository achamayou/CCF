-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Assoc

@[expose] public section

namespace KvRust

open Kv.Model

private theorem erase_on_map (db : Data) (m k : String)
    : image (erase db (m, k)) m = erase (image db m) k := by
  induction db with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨⟨table, key⟩, cell⟩ := row
      by_cases mapEq : table = m
      · subst table
        by_cases keyEq : key = k <;> simp [erase, image, keyEq] at ih ⊢ <;> rw [ih]
      · simp [erase, image, mapEq] at ih ⊢
        exact ih

private theorem erase_other_map (db : Data) (m : String) (addr : Addr String String)
    (other : addr.1 ≠ m)
    : image (erase db addr) m = image db m := by
  induction db with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨address, cell⟩ := row
      by_cases same : address = addr
      · subst address
        simp [erase, image, other] at ih ⊢
        exact ih
      · simp [erase, image, same] at ih ⊢
        simp only [List.filterMap_cons]
        rw [ih]

private theorem erase_absent_key {K V : Type} [DecidableEq K]
    (rows : Assoc K V) (key : K) (missing : find rows key = none)
    : erase rows key = rows := by
  induction rows with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨k, v⟩ := row
      by_cases same : k = key
      · simp [find, same] at missing
      · simp [find, same] at missing
        simp [erase, same, show rest.filter (fun p => p.1 != key) = rest from ih missing]

private theorem image_lookup (db : Data) (m k : String)
    : find (image db m) k = find db (m, k) := by
  induction db with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨⟨table, key⟩, c⟩ := row
      by_cases same : table = m
      · subst table
        by_cases hk : key = k
        · simp [image, find, hk]
        · simpa [image, find, hk] using ih
      · simp [image, find, same] at ih ⊢
        exact ih

/-- Revision metadata is updated for a put or a deletion of a present key. -/
def mapWriteTouches (db : Data) (m : String) (row : Addr String String × Option String)
    : Bool :=
  (row.1.1 == m) && (row.2.isSome || (find db row.1).isSome)

theorem publish_untouched_image (db : Data) (m : String) (version : Nat)
    (writes : Pending) (quiet : writes.any (mapWriteTouches db m) = false)
    : image (publish db version writes) m = image db m := by
  induction writes with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨addr, value⟩ := row
      simp only [List.any_cons, Bool.or_eq_false_iff] at quiet
      obtain ⟨quietHead, quietTail⟩ := quiet
      have unchanged := ih quietTail
      by_cases onMap : addr.1 = m
      · obtain ⟨table, key⟩ := addr
        change table = m at onMap
        subst table
        have quiet' := quietHead
        simp [mapWriteTouches] at quiet'
        cases value with
        | some v => simp at quiet'
        | none =>
            have missing : find db (m, key) = none := by
              cases h : find db (m, key) <;> simp_all
            change image (erase (publish db version rest) (m, key)) m = image db m
            rw [erase_on_map, unchanged, erase_absent_key _ _ (by rwa [image_lookup])]
      · cases value with
        | none =>
            change image (erase (publish db version rest) addr) m = _
            rw [erase_other_map _ _ _ onMap, unchanged]
        | some v =>
            change image (Kv.Model.set (publish db version rest) addr {value := v, version}) m = _
            simpa [Kv.Model.set, image, onMap]
              using (erase_other_map (publish db version rest) m addr onMap).trans
                unchanged

private theorem revisions_fold (db : Data) (m : String) (stamp : Stamp)
    (writes : Pending) (initial : Assoc String Stamp)
    : find
        (writes.foldl
          (fun rows (addr, value) =>
            if value.isSome || (find db addr).isSome then
              Kv.Model.set rows addr.1 stamp
            else
              rows)
          initial)
        m
      = if writes.any (mapWriteTouches db m) then some stamp else find initial m := by
  induction writes generalizing initial with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨addr, value⟩ := row
      simp only [List.foldl_cons, List.any_cons]
      rw [ih]
      by_cases tail : rest.any (mapWriteTouches db m)
      · simp [tail]
      · simp only [tail, Bool.false_eq_true, ite_false, Bool.or_false, mapWriteTouches]
        by_cases effect : (value.isSome || (find db addr).isSome) = true
        · by_cases eq : addr.1 = m
          · simp [effect, eq, find_set_key]
          · simp [effect, eq, Ne.symm eq, find_set_key]
        · simp [effect]

/-- A publication with an unchanged map revision leaves its exact ordered
image intact. The bound is on the old stamp, not on the data or write set. -/
theorem advance_preserves_same_revision (store : Store) (m : String) (writes : Pending)
    (bounded : (revision store.head m).version ≤ store.head.version)
    : (revision store.head m).version ≤ (revision (advance store writes).head m).version
      ∧ ((revision (advance store writes).head m).version
            = (revision store.head m).version
          → image (advance store writes).head.data m = image store.head.data m)
      ∧ (revision (advance store writes).head m).version
        ≤ (advance store writes).head.version := by
  let stamp : Stamp := {version := store.head.version + 1, identity := store.nextIdentity}
  have folded := revisions_fold store.head.data m stamp writes store.head.revisions
  have rev : revision (advance store writes).head m =
      if writes.any (mapWriteTouches store.head.data m) then stamp else revision store.head m := by
    calc
      _ = (if writes.any (mapWriteTouches store.head.data m) then
              some stamp
            else
              find store.head.revisions m).getD
            {} :=
        congrArg (fun result : Option Stamp => result.getD {}) folded
      _ = _ := by split <;> rfl
  by_cases touched : writes.any (mapWriteTouches store.head.data m) = true
  · simp only [rev, touched, ite_true]
    change _ ≤ store.head.version + 1 ∧ (store.head.version + 1 = _ → _)
      ∧ store.head.version + 1 ≤ store.head.version + 1
    exact ⟨by omega, fun same => (by omega : False).elim, Nat.le_refl _⟩
  · have quiet : writes.any (mapWriteTouches store.head.data m) = false :=
      Bool.eq_false_of_not_eq_true touched
    simp only [rev, quiet, Bool.false_eq_true, ite_false]
    exact ⟨Nat.le_refl _, fun _ => publish_untouched_image store.head.data m _ writes quiet,
      Nat.le_trans bounded (Nat.le_succ _)⟩

/-- On one branch, a map's revision orders its images, including their scan order. -/
def RevisionFlow (newer older : Frame) : Prop :=
  ∀ m,
    (revision older m).version ≤ (revision newer m).version
    ∧ ((revision newer m).version = (revision older m).version
        → image newer.data m = image older.data m)

theorem RevisionFlow.refl (f : Frame) : RevisionFlow f f :=
  fun _ => ⟨Nat.le_refl _, fun _ => rfl⟩

theorem RevisionFlow.trans {newer middle older : Frame}
    (first : RevisionFlow newer middle) (second : RevisionFlow middle older)
    : RevisionFlow newer older := by
  intro m
  obtain ⟨hm, sameNew⟩ := first m
  obtain ⟨ho, sameOld⟩ := second m
  exact ⟨
    ho.trans hm,
    fun equal =>
      (sameNew (by omega)).trans (sameOld (by omega))
  ⟩

structure RevisionHistory (frames : List Frame) : Prop where
  bounds : ∀ f ∈ frames, ∀ m, (revision f m).version ≤ f.version
  flow : frames.Pairwise RevisionFlow

theorem revision_history_new : RevisionHistory [{}] := by
  refine ⟨?_, by simp⟩
  intro frame member m
  have eq := List.mem_singleton.mp member
  simp [eq, revision, find]

theorem RevisionHistory.advance {store : Store} (stable : RevisionHistory store.history)
    (head : store.history.head? = some store.head) (writes : Pending)
    : RevisionHistory (Kv.Model.advance store writes).history := by
  have member : store.head ∈ store.history := by
    cases ks : store.history with
    | nil => simp [ks] at head
    | cons h rest =>
        have eq : h = store.head := by simpa [ks] using head
        simp [eq]
  have bounded := stable.bounds store.head member
  have step (m : String) := advance_preserves_same_revision store m writes (bounded m)
  have first : RevisionFlow (Kv.Model.advance store writes).head store.head :=
    fun m => ⟨(step m).1, (step m).2.1⟩
  change RevisionHistory ((Kv.Model.advance store writes).head :: store.history)
  refine ⟨?_, List.pairwise_cons.mpr ⟨?_, stable.flow⟩⟩
  · intro f member m
    rcases List.mem_cons.mp member with rfl | earlier
    · exact (step m).2.2
    · exact stable.bounds f earlier m
  · intro f member
    apply first.trans
    cases hs : store.history with
    | nil => simp [hs] at head
    | cons h rest =>
        have eq : h = store.head := by simpa [hs] using head
        subst h
        rw [hs] at member
        rcases List.mem_cons.mp member with rfl | old
        · exact RevisionFlow.refl _
        · have pairs := stable.flow
          rw [hs] at pairs
          exact (List.pairwise_cons.mp pairs).1 f old

theorem RevisionHistory.filter {frames : List Frame} (stable : RevisionHistory frames)
    (keep : Frame → Bool)
    : RevisionHistory (frames.filter keep) :=
  ⟨
    fun f member => stable.bounds f (List.mem_of_mem_filter member),
    stable.flow.filter keep
  ⟩

theorem revision_flow_at_cuts (frames : List Frame) (flow : frames.Pairwise RevisionFlow)
    (earlier later : Nat) (order : earlier ≤ later) (old new : Frame)
    (oldCut : frames.find? (fun frame => frame.version ≤ earlier) = some old)
    (newCut : frames.find? (fun frame => frame.version ≤ later) = some new)
    : RevisionFlow new old := by
  induction frames with
  | nil => simp at oldCut
  | cons head rest ih =>
      have ⟨top, tail⟩ := List.pairwise_cons.mp flow
      by_cases onOld : head.version ≤ earlier
      · have onNew : head.version ≤ later := onOld.trans order
        simp [onOld] at oldCut
        simp [onNew] at newCut
        exact oldCut ▸ newCut ▸ RevisionFlow.refl head
      · simp [onOld] at oldCut
        by_cases onNew : head.version ≤ later
        · simp [onNew] at newCut
          exact newCut ▸ top old (List.mem_of_find?_eq_some oldCut)
        · simp [onNew] at newCut
          exact ih tail oldCut newCut

/-- An available acquisition at or before the global cut needs either an empty
map or exactly the global map image. Older frame metadata still decides availability. -/
theorem available_compacted_image (store : Store) (stable : RevisionHistory store.history)
    (snap : Snapshot) (m : String) (past : snap.current.version ≤ store.global)
    (canRead : available store snap m = true)
    : find (captureLocal store snap m).births m = none
      ∨ image (captureLocal store snap m).data m
        = image (atCut store store.global).data m := by
  cases atLocal
        : store.history.find? (fun frame => frame.version ≤ snap.current.version) with
  | none => exact Or.inl (by simp [captureLocal, atCut, atLocal, find])
  | some localFrame =>
      have localEq : atCut store snap.current.version = localFrame := by simp [atCut, atLocal]
      cases birth : find localFrame.births m with
      | none => exact Or.inl (by simp [captureLocal, localEq, birth, find])
      | some stamp =>
          have captured : captureLocal store snap m = localFrame := by
            simp [captureLocal, localEq, birth]
          cases atGlobal
                : store.history.find? (fun frame => frame.version ≤ store.global) with
          | none =>
              have member := List.mem_of_find?_eq_some atLocal
              have before : localFrame.version ≤ snap.current.version :=
                of_decide_eq_true (List.find?_some
                  (p := fun frame : Frame => decide (frame.version ≤ snap.current.version)) atLocal)
              have missing := List.find?_eq_none.mp atGlobal localFrame member
              simp [before.trans past] at missing
          | some globalFrame =>
              have globalEq : atCut store store.global = globalFrame := by
                simp [atCut, atGlobal]
              have monotone := revision_flow_at_cuts store.history stable.flow _ _ past
                localFrame globalFrame atLocal atGlobal m
              have notStale
                  : (revision globalFrame m).version
                    ≤ (revision localFrame m).version := by
                simp only [available, captured, mapAvailable, birth, globalEq, Bool.and_eq_true,
                  decide_eq_true_eq] at canRead
                exact canRead.1
              rw [captured, globalEq]
              exact Or.inr (monotone.2 (Nat.le_antisymm notStale monotone.1)).symm

end KvRust
