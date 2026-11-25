-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Assoc
public import KvRust.OrderEquivalence

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

private theorem births_fold (m : String) (stamp : Stamp) (writes : Pending)
    (initial : Assoc String Stamp)
    : find
        (writes.foldl
          (fun rows (addr, _) =>
            if (find rows addr.1).isSome then rows else Kv.Model.set rows addr.1 stamp)
          initial) m
      = (find initial m).or
          (if writes.any (fun row => row.1.1 == m) then some stamp else none) := by
  induction writes generalizing initial with
  | nil => simp
  | cons row rest ih =>
      obtain ⟨⟨table, key⟩, value⟩ := row
      simp only [List.foldl_cons, List.any_cons]
      rw [ih]
      by_cases target : table = m
      · subst table
        cases old : find initial m <;> simp [old, find_set_key]
      · have different : (table == m) = false :=
          Bool.eq_false_of_not_eq_true (fun h => target (beq_iff_eq.mp h))
        let touched := rest.any (fun row => row.1.1 == m)
        change (find (if (find initial table).isSome then initial else
          Kv.Model.set initial table stamp) m).or (if touched then some stamp else none) =
          (find initial m).or (if (table == m || touched) then some stamp else none)
        rw [different, Bool.false_or]
        cases find initial table <;> simp [Ne.symm target, find_set_key]

/-- Publishing reordered writes changes neither the next version nor any
cell, birth, or map revision selected by lookup. -/
theorem advance_order_eq (s t : Store) (xs ys : Pending)
    (heads : FrameOrderEq s.head t.head) (identity : s.nextIdentity = t.nextIdentity)
    (related : xs.Perm ys) (baseUnique : Kv.Properties.Unique s.head.data)
    (writesUnique : Kv.Properties.Unique xs)
    : FrameOrderEq (advance s xs).head (advance t ys).head := by
  have version := heads.version
  have stamp : ({version := s.head.version + 1, identity := s.nextIdentity} : Stamp) =
      {version := t.head.version + 1, identity := t.nextIdentity} := by rw [version, identity]
  refine ⟨congrArg (· + 1) version, ?_, ?_, ?_⟩
  · change (publish s.head.data (s.head.version + 1) xs).Perm
      (publish t.head.data (t.head.version + 1) ys)
    rw [← version]
    exact publication_perm _ heads.data related baseUnique writesUnique
  · intro m
    have touches : mapWriteTouches s.head.data m = mapWriteTouches t.head.data m := by
      funext row
      simp only [mapWriteTouches, lookup_perm heads.data baseUnique]
    simp only [advance, revisions_fold, stamp, heads.revisions m, touches, related.any_eq]
  · intro m
    simp only [advance, births_fold, stamp, heads.births m, related.any_eq]

/-- A publication with an unchanged map revision leaves its exact ordered
image intact. The bound is on the old stamp, not on the data or write set. -/
theorem advance_preserves_same_revision (store : Store) (m : String) (writes : Pending)
    (bounded : (revision store.head m).version ≤ store.head.version)
    : (revision store.head m).version ≤ (revision (advance store writes).head m).version
      ∧ ((revision (advance store writes).head m).version
            = (revision store.head m).version
          → image (advance store writes).head.data m = image store.head.data m
            ∧ revision (advance store writes).head m = revision store.head m)
      ∧ ((find store.head.births m).isSome
          → find (advance store writes).head.births m = find store.head.births m)
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
  have hbirth : (find store.head.births m).isSome →
      find (advance store writes).head.births m = find store.head.births m := by
    intro hsome
    have hfold : ∀ (ws : Pending) (bs : Assoc String Stamp),
        (find bs m).isSome = true →
        find (ws.foldl (fun acc (a, _) =>
          if (find acc a.1).isSome then acc else set acc a.1 stamp) bs) m = find bs m := by
      intro ws
      induction ws with
      | nil => intro bs _; rfl
      | cons w rest ih =>
          rcases w with ⟨a, val⟩
          intro bs hbs
          simp only [List.foldl_cons]
          by_cases hfm : (find bs a.1).isSome = true
          · rw [ite_eq_left hfm]
            exact ih bs hbs
          · rw [ite_eq_right hfm]
            have hne : a.1 ≠ m := by
              intro heq; subst heq; exact hfm hbs
            have hset : find (set bs a.1 stamp) m = find bs m := by
              simp [find_set_key, Ne.symm hne]
            rw [ih (set bs a.1 stamp) (hset.symm ▸ hbs), hset]
    exact hfold writes store.head.births hsome
  by_cases touched : writes.any (mapWriteTouches store.head.data m) = true
  · simp only [rev, touched, ite_true]
    change _ ≤ store.head.version + 1 ∧ (store.head.version + 1 = _ → _)
      ∧ _ ∧ store.head.version + 1 ≤ store.head.version + 1
    exact ⟨by omega, fun same => (by omega : False).elim, hbirth, Nat.le_refl _⟩
  · have quiet : writes.any (mapWriteTouches store.head.data m) = false :=
      Bool.eq_false_of_not_eq_true touched
    have revEq : revision (advance store writes).head m = revision store.head m := by
      simp [rev, quiet]
    refine ⟨by rw [revEq], ?_, hbirth, by rw [revEq]; exact Nat.le_trans bounded (Nat.le_succ _)⟩
    intro _
    exact ⟨publish_untouched_image store.head.data m _ writes quiet, revEq⟩

/-- On one branch, a map's revision orders its images and stamps, including birth persistence. -/
def RevisionFlow (newer older : Frame) : Prop :=
  ∀ m,
    (revision older m).version ≤ (revision newer m).version
    ∧ ((revision newer m).version = (revision older m).version
        → image newer.data m = image older.data m ∧ revision newer m = revision older m)
    ∧ ((find older.births m).isSome → find newer.births m = find older.births m)

theorem RevisionFlow.refl (f : Frame) : RevisionFlow f f :=
  fun _ => ⟨Nat.le_refl _, fun _ => ⟨rfl, rfl⟩, fun _ => rfl⟩

theorem RevisionFlow.trans {newer middle older : Frame}
    (first : RevisionFlow newer middle) (second : RevisionFlow middle older)
    : RevisionFlow newer older := by
  intro m
  obtain ⟨hm, sameNew, birthNew⟩ := first m
  obtain ⟨ho, sameOld, birthOld⟩ := second m
  exact ⟨
    ho.trans hm,
    fun equal =>
      ⟨
        (sameNew (by omega)).1.trans (sameOld (by omega)).1,
        (sameNew (by omega)).2.trans (sameOld (by omega)).2
      ⟩,
    fun hsome => by
      have hmid := birthOld hsome
      exact (birthNew (hmid.symm ▸ hsome)).trans hmid
  ⟩

/-- If an older and newer frame on the same branch share a map's birth and revision stamps,
every frame between them on that branch has the same birth and revision stamps. -/
theorem RevisionFlow.stamps_between {newer middle older : Frame}
    (hnm : RevisionFlow newer middle) (hmo : RevisionFlow middle older) (m : String)
    (hbirth : find older.births m = find newer.births m)
    (hrev : revision older m = revision newer m)
    : find middle.births m = find older.births m
      ∧ revision middle m = revision older m := by
  obtain ⟨hnmLe, _, hnmBirth⟩ := hnm m
  obtain ⟨hmoLe, hmoEq, hmoBirth⟩ := hmo m
  have hrevVer : (revision middle m).version = (revision older m).version := by
    have heqVer : (revision older m).version = (revision newer m).version :=
      congrArg Stamp.version hrev
    omega
  refine ⟨?_, (hmoEq hrevVer).2⟩
  cases ho : find older.births m with
  | some b =>
      have := hmoBirth (by simp [ho])
      rwa [ho] at this
  | none =>
      cases hm : find middle.births m with
      | none => rfl
      | some b =>
          have hnb := hnmBirth (by simp [hm])
          rw [hm] at hnb
          rw [hnb] at hbirth
          simp [ho] at hbirth

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
    fun m => ⟨(step m).1, (step m).2.1, (step m).2.2.1⟩
  change RevisionHistory ((Kv.Model.advance store writes).head :: store.history)
  refine ⟨?_, List.pairwise_cons.mpr ⟨?_, stable.flow⟩⟩
  · intro f member m
    rcases List.mem_cons.mp member with rfl | earlier
    · exact (step m).2.2.2
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

theorem RevisionHistory.advance_order {s : Store} (stable : RevisionHistory s.history)
    (head : s.history.head? = some s.head) (writes : Pending) (next : Frame)
    (order : FrameOrderEq next (Kv.Model.advance s writes).head)
    (canon
      : ∀ f ∈ s.history,
          ∀ m,
            (image next.data m).Perm (image f.data m)
            → image next.data m = image f.data m)
    : RevisionHistory (next :: s.history) := by
  have hExact := stable.advance head writes
  change RevisionHistory ((Kv.Model.advance s writes).head :: s.history) at hExact
  refine ⟨?_, ?_⟩
  · intro f hf m
    rcases List.mem_cons.mp hf with rfl | old
    · have hb := hExact.bounds (Kv.Model.advance s writes).head List.mem_cons_self m
      rw [order.version, order.revision_eq m]
      exact hb
    · exact stable.bounds f old m
  · refine List.pairwise_cons.mpr ⟨?_, stable.flow⟩
    intro f hf m
    have hflow := (List.pairwise_cons.mp hExact.flow).1 f hf m
    refine ⟨by rw [order.revision_eq m]; exact hflow.1, ?_, ?_⟩
    · intro heq
      rw [order.revision_eq m] at heq
      have hEqExact := hflow.2.1 heq
      have hperm : (image next.data m).Perm (image f.data m) :=
        hEqExact.1 ▸ order.image_perm m
      exact ⟨canon f hf m hperm, by rw [order.revision_eq m]; exact hEqExact.2⟩
    · intro hsome
      rw [order.births]
      exact hflow.2.2 hsome

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
              exact Or.inr (monotone.2.1 (Nat.le_antisymm notStale monotone.1)).1.symm

/-- Projection of a frame whose payload may be reclaimed, but whose lineage
metadata must still be available to lazy acquisitions and validation. -/
def retainedFrame (floor : Nat) (f : Frame) : Frame :=
  { f with data := if floor ≤ f.version then f.data else [] }

def retainedBranch (s : Store) : Store :=
  { s with history := s.history.map (retainedFrame s.global) }

theorem retainedFrame_eq {floor : Nat} {f : Frame} (live : floor ≤ f.version)
    : retainedFrame floor f = f := by
  cases f
  simp [retainedFrame, live]

theorem retained_branch_at_cut (s : Store) (cut : Nat)
    : atCut (retainedBranch s) cut = retainedFrame s.global (atCut s cut) := by
  unfold atCut retainedBranch
  have select (frames : List Frame) :
      ((frames.map (retainedFrame s.global)).find? (fun f => f.version ≤ cut)) =
        (frames.find? (fun f => f.version ≤ cut)).map (retainedFrame s.global) := by
    induction frames with
    | nil => rfl
    | cons frame rest ih =>
        by_cases eligible : frame.version ≤ cut <;>
          simp [retainedFrame, ih, eligible]
  simp only [select]
  cases s.history.find? (fun f => f.version ≤ cut) <;> simp [retainedFrame]

theorem retained_branch_live_cut (s : Store) (cut : Nat)
    (live : s.global ≤ (atCut s cut).version)
    : atCut (retainedBranch s) cut = atCut s cut :=
  (retained_branch_at_cut s cut).trans (retainedFrame_eq live)

theorem retained_branch_lineage (s : Store) (m : String) (f : Frame)
    : mapLineage (retainedBranch s) f m = mapLineage s f m := by
  simp [mapLineage, retainedBranch, List.any_map, Function.comp_def, revision, retainedFrame]

theorem retained_branch_eligible (s : Store) (tx : Tx)
    : canApply (retainedBranch s) tx = canApply s tx := by
  have term : (retainedBranch s).term = s.term := rfl
  have head : (retainedBranch s).head = s.head := rfl
  unfold canApply validLineage
  simp only [term, head, retained_branch_lineage]

theorem retained_branch_available (s : Store) (snap : Snapshot) (m : String)
    (globalLive : s.global ≤ (atCut s s.global).version)
    : available (retainedBranch s) snap m = available s snap m := by
  have global : (retainedBranch s).global = s.global := rfl
  unfold available captureLocal
  rw [retained_branch_at_cut]
  cases birth : find (atCut s snap.current.version).births m with
  | none => simp [retainedFrame, birth, mapAvailable, find, image]
  | some stamp =>
      have lb : find (retainedFrame s.global (atCut s snap.current.version)).births m =
          some stamp := birth
      have same : revision (retainedFrame s.global (atCut s snap.current.version)) m =
          revision (atCut s snap.current.version) m := rfl
      simp only [lb, birth, Option.isSome_some, ite_true, mapAvailable, global,
        retained_branch_live_cut s s.global globalLive, same, retained_branch_lineage]
      rfl

/-- Compute the local image for an available lazy acquisition without
reading a compacted frame's discarded data. Existing pins are not replaced. -/
def retainedAcquisitionImage (s : Store) (snap : Snapshot) (m : String)
    : Assoc String (Cell String) :=
  let retained := retainedBranch s
  let current := atCut retained snap.current.version
  if (find current.births m).isNone then
    []
  else if snap.current.version < s.global then
    image (atCut retained s.global).data m
  else
    image current.data m

theorem retained_acquisition_image (s : Store) (stable : RevisionHistory s.history)
    (snap : Snapshot) (m : String) (canRead : available s snap m = true)
    (globalLive : s.global ≤ (atCut s s.global).version)
    (localLive
      : s.global ≤ snap.current.version
        → s.global ≤ (atCut s snap.current.version).version)
    : retainedAcquisitionImage s snap m = image (captureLocal s snap m).data m := by
  unfold retainedAcquisitionImage
  dsimp only
  rw [retained_branch_at_cut s snap.current.version]
  cases birth : find (atCut s snap.current.version).births m with
  | none => simp [retainedFrame, captureLocal, birth, image]
  | some stamp =>
      have lb : find (retainedFrame s.global (atCut s snap.current.version)).births m =
          some stamp := birth
      have localFrame : captureLocal s snap m = atCut s snap.current.version := by
        simp [captureLocal, birth]
      simp only [lb, Option.isNone_some, Bool.false_eq_true, ite_false]
      by_cases older : snap.current.version < s.global
      · rw [ite_eq_left older, retained_branch_live_cut _ _ globalLive]
        rcases available_compacted_image s stable snap m (Nat.le_of_lt older) canRead with missing | equal
        · simp [localFrame, birth] at missing
        · exact equal.symm
      · rw [ite_eq_right older, retainedFrame_eq (localLive (Nat.le_of_not_gt older)), localFrame]

theorem retained_branch_rollback (s : Store) (request term : Nat)
    (live : s.global ≤ (atCut s (rollbackCut s request)).version)
    : rollbackStore (retainedBranch s) request term
      = retainedBranch (rollbackStore s request term) := by
  have cut : rollbackCut (retainedBranch s) request = rollbackCut s request := rfl
  unfold rollbackStore
  dsimp only
  rw [cut, retained_branch_live_cut s _ live]
  simp [retainedBranch, List.filter_map, Function.comp_def, retainedFrame]
  rfl

theorem retained_branch_advance (s : Store) (writes : Pending)
    (headLive : s.global ≤ s.head.version)
    : advance (retainedBranch s) writes = retainedBranch (advance s writes) := by
  have nextLive : s.global ≤ (advance s writes).head.version := by
    change s.global ≤ s.head.version + 1
    omega
  have keep := retainedFrame_eq nextLive
  simp [retainedBranch, advance] at keep ⊢
  exact keep.symm

private theorem retained_frame_raise {older newer : Nat} (ordered : older ≤ newer)
    (f : Frame)
    : retainedFrame newer (retainedFrame older f) = retainedFrame newer f := by
  by_cases keep : newer ≤ f.version
  · rw [retainedFrame_eq (ordered.trans keep)]
  · simp [retainedFrame, keep]

theorem retained_branch_compact (s : Store) (request : Nat)
    : retainedBranch (compactStore (retainedBranch s) request)
      = retainedBranch (compactStore s request) := by
  have raised : s.global ≤ (compactStore s request).global := by
    unfold compactStore
    split <;> simp
  have compacted : compactStore (retainedBranch s) request =
      {compactStore s request with history := (retainedBranch s).history} := by
    unfold compactStore
    change (if request ≤ s.head.version then _ else _) = _
    split <;> rfl
  rw [compacted]
  have history : (compactStore s request).history = s.history := by
    unfold compactStore
    split <;> rfl
  simp only [retainedBranch, history, List.map_map]
  congr 1
  simp only [Function.comp_def, retained_frame_raise raised]

/-- Across all frames ever produced by one store (even across rollbacks),
each map revision stamp uniquely determines the exact ordered image of that map,
unborn maps are empty, and all cells are bounded by their frame version. -/
structure ArchiveConsistent (frames : List Frame) (nextIdentity : Nat) : Prop where
  emptyPresent : ({} : Frame) ∈ frames
  identities : ∀ f ∈ frames, ∀ m, (revision f m).identity < nextIdentity
  unborn
    : ∀ f ∈ frames,
        ∀ m, find f.births m = none → image f.data m = [] ∧ find f.revisions m = none
  sameRevision
    : ∀ f1 ∈ frames,
      ∀ f2 ∈ frames,
        ∀ m, revision f1 m = revision f2 m → image f1.data m = image f2.data m
  bounded : ∀ f ∈ frames, Kv.Properties.CellsBounded f.data f.version
  unique : ∀ f ∈ frames, Kv.Properties.Unique f.data

theorem archive_consistent_new : ArchiveConsistent [{}] 1 := by
  refine ⟨List.mem_cons_self, ?_, ?_, ?_, ?_, ?_⟩
  · intro f hf m
    rw [List.mem_singleton.mp hf]
    simp [revision, find]
  · intro f hf m _
    rw [List.mem_singleton.mp hf]
    simp [image, find]
  · intro f1 h1 f2 h2 m _
    rw [List.mem_singleton.mp h1, List.mem_singleton.mp h2]
  · intro f hf k c hc
    rw [List.mem_singleton.mp hf] at hc
    simp [find] at hc
  · intro f hf
    rw [List.mem_singleton.mp hf]
    exact List.Pairwise.nil

private theorem publish_cells_bounded (db : Data) (version : Nat) (writes : Pending)
    (prior : Nat) (hbound : Kv.Properties.CellsBounded db prior) (hle : prior ≤ version)
    : Kv.Properties.CellsBounded (publish db version writes) version := by
  intro key cell found
  rw [Kv.Properties.publish_lookup] at found
  cases hw : find writes key with
  | none =>
      rw [hw] at found
      exact Nat.le_trans (hbound key cell found) hle
  | some w =>
      cases w with
      | none => rw [hw] at found; cases found
      | some v =>
          rw [hw] at found
          have eq := Option.some.inj found
          rw [← eq]

theorem ArchiveConsistent.append {frames : List Frame} {s : Store}
    (inv : ArchiveConsistent frames s.nextIdentity) (headIn : s.head ∈ frames)
    (writes : Pending)
    : ArchiveConsistent (frames ++ [(advance s writes).head]) (s.nextIdentity + 1) := by
  let next := (advance s writes).head
  let stamp : Stamp := {version := s.head.version + 1, identity := s.nextIdentity}
  have revEq (m : String) : revision next m =
      if writes.any (mapWriteTouches s.head.data m) then stamp else revision s.head m := by
    have folded := revisions_fold s.head.data m stamp writes s.head.revisions
    change find next.revisions m = _ at folded
    unfold revision
    rw [folded]
    split <;> rfl
  have birthEq (m : String) : find next.births m =
      (find s.head.births m).or (if writes.any (fun row => row.1.1 == m) then some stamp else none) :=
    births_fold m stamp writes s.head.births
  have headRevLt (f : Frame) (hf : f ∈ frames) (m : String) :
      (revision f m).identity < s.nextIdentity := inv.identities f hf m
  have nextIdLt (m : String) : (revision next m).identity < s.nextIdentity + 1 := by
    rw [revEq m]
    split
    · exact Nat.lt_succ_self _
    · exact Nat.lt_trans (headRevLt s.head headIn m) (Nat.lt_succ_self _)
  have nextUnborn (m : String) (absent : find next.births m = none) :
      image next.data m = [] ∧ find next.revisions m = none := by
    rw [birthEq m] at absent
    have oldAbsent : find s.head.births m = none := by
      cases h : find s.head.births m <;> simp [h] at absent ⊢
    have noWrite : writes.any (fun row => row.1.1 == m) = false := by
      cases h : writes.any (fun row => row.1.1 == m) <;> simp [oldAbsent, h] at absent ⊢
    have quiet : writes.any (mapWriteTouches s.head.data m) = false := by
      apply List.any_eq_false.mpr
      intro row hr
      have hne := List.any_eq_false.mp noWrite row hr
      simp [mapWriteTouches, hne]
    obtain ⟨oldImg, oldRev⟩ := inv.unborn s.head headIn m oldAbsent
    refine ⟨?_, ?_⟩
    · exact (publish_untouched_image s.head.data m (s.head.version + 1) writes quiet).trans oldImg
    · have folded := revisions_fold s.head.data m stamp writes s.head.revisions
      change find next.revisions m = _ at folded
      rw [folded, quiet]
      simpa using oldRev
  have nextSameRev (f : Frame) (hf : f ∈ frames) (m : String)
      (eq : revision f m = revision next m) : image f.data m = image next.data m := by
    rw [revEq m] at eq
    by_cases touched : writes.any (mapWriteTouches s.head.data m) = true
    · rw [ite_eq_left touched] at eq
      have lt := headRevLt f hf m
      have bad := congrArg Stamp.identity eq
      change (revision f m).identity = s.nextIdentity at bad
      omega
    · have quiet : writes.any (mapWriteTouches s.head.data m) = false :=
        Bool.eq_false_of_not_eq_true touched
      rw [ite_eq_right touched] at eq
      exact (inv.sameRevision f hf s.head headIn m eq).trans
        (publish_untouched_image s.head.data m (s.head.version + 1) writes quiet).symm
  refine ⟨List.mem_append_left _ inv.emptyPresent, ?_, ?_, ?_, ?_, ?_⟩
  · intro f hf m
    rcases List.mem_append.mp hf with old | fresh
    · exact Nat.lt_trans (headRevLt f old m) (Nat.lt_succ_self _)
    · rw [List.mem_singleton.mp fresh]; exact nextIdLt m
  · intro f hf m absent
    rcases List.mem_append.mp hf with old | fresh
    · exact inv.unborn f old m absent
    · rw [List.mem_singleton.mp fresh] at absent ⊢; exact nextUnborn m absent
  · intro f1 h1 f2 h2 m eq
    rcases List.mem_append.mp h1 with o1 | n1 <;> rcases List.mem_append.mp h2 with o2 | n2
    · exact inv.sameRevision f1 o1 f2 o2 m eq
    · rw [List.mem_singleton.mp n2] at eq ⊢; exact nextSameRev f1 o1 m eq
    · rw [List.mem_singleton.mp n1] at eq ⊢; exact (nextSameRev f2 o2 m eq.symm).symm
    · rw [List.mem_singleton.mp n1, List.mem_singleton.mp n2]
  · intro f hf
    rcases List.mem_append.mp hf with old | fresh
    · exact inv.bounded f old
    · rw [List.mem_singleton.mp fresh]
      exact publish_cells_bounded s.head.data (s.head.version + 1) writes s.head.version
        (inv.bounded s.head headIn) (Nat.le_succ _)
  · intro f hf
    rcases List.mem_append.mp hf with old | fresh
    · exact inv.unique f old
    · rw [List.mem_singleton.mp fresh]
      exact Kv.Properties.publish_unique s.head.data (s.head.version + 1) writes
        (inv.unique s.head headIn)

theorem ArchiveConsistent.append_order {frames : List Frame} {s : Store}
    (inv : ArchiveConsistent frames s.nextIdentity) (headIn : s.head ∈ frames)
    (writes : Pending) (next : Frame) (order : FrameOrderEq next (advance s writes).head)
    (canon
      : ∀ f ∈ frames,
          ∀ m,
            (image next.data m).Perm (image f.data m)
            → image next.data m = image f.data m)
    : ArchiveConsistent (frames ++ [next]) (s.nextIdentity + 1) := by
  have hExact := inv.append headIn writes
  have hNextMem : (advance s writes).head ∈ frames ++ [(advance s writes).head] :=
    List.mem_append_right _ List.mem_cons_self
  refine ⟨List.mem_append_left _ inv.emptyPresent, ?_, ?_, ?_, ?_, ?_⟩
  · intro f hf m
    rcases List.mem_append.mp hf with old | fresh
    · exact Nat.lt_trans (inv.identities f old m) (Nat.lt_succ_self _)
    · rw [List.mem_singleton.mp fresh, order.revision_eq m]
      exact hExact.identities _ hNextMem m
  · intro f hf m absent
    rcases List.mem_append.mp hf with old | fresh
    · exact inv.unborn f old m absent
    · rw [List.mem_singleton.mp fresh] at absent ⊢
      rw [order.births] at absent
      obtain ⟨himg, hrev⟩ := hExact.unborn _ hNextMem m absent
      refine ⟨?_, by rwa [order.revisions]⟩
      have hperm := order.image_perm m
      rw [himg] at hperm
      exact hperm.symm.nil_eq.symm
  · intro f1 h1 f2 h2 m eq
    rcases List.mem_append.mp h1 with o1 | n1 <;> rcases List.mem_append.mp h2 with o2 | n2
    · exact inv.sameRevision f1 o1 f2 o2 m eq
    · rw [List.mem_singleton.mp n2] at eq ⊢
      rw [order.revision_eq m] at eq
      have hEq := hExact.sameRevision f1 (List.mem_append_left _ o1) _ hNextMem m eq
      have hperm : (image next.data m).Perm (image f1.data m) :=
        hEq ▸ order.image_perm m
      exact (canon f1 o1 m hperm).symm
    · rw [List.mem_singleton.mp n1] at eq ⊢
      rw [order.revision_eq m] at eq
      have hEq := hExact.sameRevision _ hNextMem f2 (List.mem_append_left _ o2) m eq
      have hperm : (image next.data m).Perm (image f2.data m) :=
        hEq ▸ order.image_perm m
      exact canon f2 o2 m hperm
    · rw [List.mem_singleton.mp n1, List.mem_singleton.mp n2]
  · intro f hf
    rcases List.mem_append.mp hf with old | fresh
    · exact inv.bounded f old
    · rw [List.mem_singleton.mp fresh]
      intro k c hfind
      have hunique := hExact.unique _ hNextMem
      have hperm := order.data
      have hfind' : find (advance s writes).head.data k = some c := by
        rw [lookup_perm hperm (unique_of_perm hperm.symm hunique)] at hfind
        exact hfind
      rw [order.version]
      exact hExact.bounded _ hNextMem k c hfind'
  · intro f hf
    rcases List.mem_append.mp hf with old | fresh
    · exact inv.unique f old
    · rw [List.mem_singleton.mp fresh]
      exact unique_of_perm order.data.symm (hExact.unique _ hNextMem)

theorem archive_image_cells_bounded {frames : List Frame} {nextId : Nat}
    (inv : ArchiveConsistent frames nextId) {f : Frame} (hf : f ∈ frames) (m : String)
    : ∀ row ∈ image f.data m, row.2.version ≤ f.version := by
  intro ⟨k, c⟩ hmem
  have uniqueImg := unique_image f.data m (inv.unique f hf)
  have hfind := (lookup_eq_some_iff_mem (image f.data m) uniqueImg k c).mpr hmem
  have hdb : find f.data (m, k) = some c := by
    have hi : find (image f.data m) k = find f.data (m, k) := by
      induction f.data with
      | nil => rfl
      | cons row rest ih =>
          obtain ⟨⟨table, key⟩, cell⟩ := row
          by_cases hm : table = m
          · subst table
            simp [image, find] at ih ⊢
            by_cases hk : key = k <;> simp [hk, ih]
          · simp [image, find, hm] at ih ⊢
            exact ih
    exact hi.symm.trans hfind
  exact inv.bounded f hf (m, k) c hdb

end KvRust
