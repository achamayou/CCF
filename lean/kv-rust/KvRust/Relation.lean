-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Scan
public import KvRust.RetainedCuts

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Project the native commit lifecycle without changing its applied version. -/
def modelPhase : Spike.engine.Phase → Phase
  | .Active => .active
  | .Committing => .committing
  | .Applied version => .applied version.val
  | .Finished => .finished

/-- An inactive native phase disables active-only reference operations. -/
theorem model_phase_inactive (p : Spike.engine.Phase) (h : p ≠ .Active)
    : (modelPhase p != .active) = true := by
  cases p with
  | Active => exact (h rfl).elim
  | Committing => rfl
  | Applied _ => rfl
  | Finished => rfl

/-- Commit outcomes distinguish a conflict from a failure to replicate. -/
def modelOutcome : Spike.engine.Outcome → Outcome
  | .Success => .success
  | .Conflict => .conflict
  | .NoReplicate => .noReplicate

/-- Encode native observations as reference results. -/
def modelOutput (encode : List U8 → String) : Spike.engine.Output → Output
  | .Unit => .unit
  | .Snapshot v g t => .snapshot v.val g.val t.val
  | .Acquired v g => .acquired v.val g.val
  | .Unavailable => .unavailable
  | .Value v => .value (encodeValue encode v)
  | .Presence b => .presence b
  | .Previous v => .previous (v.map UScalar.val)
  | .Entries rows => .entries (modelEntries encode rows)
  | .Size len => .size len.val
  | .Applied v t writes => .applied v.val t.val (encodeReport encode writes)
  | .Committed outcome version => .committed (modelOutcome outcome) version.val
  | .Compacted v => .compacted v.val
  | .RolledBack v => .rolledBack v.val
  | .RollbackRejected => .rollbackRejected

/-- The native transaction stores only the version and term of the captured frame. -/
def modelSnapshot (r : Spike.engine.Snapshot) : Nat × Nat := (r.version.val, r.term.val)

/-- Read metadata relevant to the engine; the model retains the complete frame. -/
def snapshotCut (s : Snapshot) : Nat × Nat := (s.current.version, s.term)

/-- The two attempts differ in representation, write/image order, and the model-only normal operation log. -/
structure AttemptMatches (encode : List U8 → String) (sid : Nat)
    (index : CellIndex) (natArchive archive : List Frame)
    (native : Spike.engine.Tx) (model : Tx)
    : Prop where
  /-- The model attempt belongs to the represented store. -/
  store : model.store = sid
  /-- The snapshot metadata agrees even after the original frame has been rolled back. -/
  snapshot : model.snapshot.map snapshotCut = native.snapshot.map modelSnapshot
  /-- The operation phases agree. -/
  phase : model.phase = modelPhase native.phase
  /-- The acquired map names and stamps agree; pinned cell images match up to permutation. -/
  views
    : ViewsOrderEq (modelPinnedViews model.globalViews)
        (rustPinnedViews encode index native.views)
  live : ViewsLive index native.views
  nativeOrig : ViewsOrigin encode index natArchive native.views
  modelViewsIn
    : ∀ row ∈ model.globalViews, row.2.current ∈ archive ∧ row.2.frame ∈ archive
  /-- The model's flattened read image agrees with each independently pinned view. -/
  data
    : ∀ m,
        image model.data m
        = ((find model.globalViews m).map (fun v => image v.current.data m)).getD []
  /-- Every pinned read image has unique keys, including views from rolled-back branches. -/
  dataUnique : ∀ m, Kv.Properties.Unique (image model.data m)
  /-- The model log only mentions maps already acquired in this attempt. -/
  log : ∀ op ∈ model.normal.log, (find model.globalViews op.map).isSome
  /-- No map can have been acquired without a snapshot. -/
  noSnapshot : native.snapshot = none → native.views.val = []
  /-- An acquisition that could not retain its version prevents applying the attempt. -/
  unavailable : model.unavailable = native.unavailable
  /-- The staged overlay includes removals and matches the model up to permutation. -/
  writes : (pointWrites encode native).Perm model.normal.writes
  /-- Native pending writes stay strictly ordered by key for binary-search updates. -/
  sorted : PendingSorted native.pending.val
  /-- Each native condition corresponds to the reference dependency up to map-entry order. -/
  deps : List.Forall₂ DependencyOrderEq (pointDeps encode index native) model.normal.deps
  nativeDeps : NativeDepsFromViews encode index native
  depsPins : DepsPinsInViews native
  modelDeps : ModelDepsFromViews model

/-- The native active offsets project via the ghost archive to frames matching the
model's newest-first branch modulo order. -/
structure HistoryMatches (encode : List U8 → String)
    (native : Spike.engine.History) (model : Store) (natArchive archive : List Frame)
    : Prop where
  /-- The initial frame is retained. -/
  nonempty : native.activeFrames ≠ []
  /-- The entire surviving branch is represented modulo binding order. -/
  frames : List.Forall₂ FrameOrderEq (natModelFrames native.log natArchive) model.history
  /-- The selected model head is the first projected frame. -/
  head : model.history.head? = some model.head
  /-- Frame versions equal their native indices. -/
  indexed
    : ∀ i (h : i < native.activeFrames.length), native.activeFrames[i].version.val = i
  /-- The compacted frontier agrees. -/
  global : model.global = native.global.val
  /-- The compacted frontier lies within the surviving branch. -/
  globalBound : native.global.val < native.activeFrames.length
  /-- The current term agrees. -/
  term : model.term = native.term.val
  /-- The next identity agrees, including after local version reuse. -/
  identity : model.nextIdentity = native.next_identity.val
  valid : BranchValid native.log
  unique : BranchUnique native.log
  indexValid : HistoryIndexValid native
  aligned : ArchiveAligned encode native natArchive
  revisions : RevisionHistory (natModelFrames native.log natArchive)
  nativeArchive : ArchiveConsistent natArchive native.next_identity.val
  natSorted : ∀ f ∈ natArchive, ∀ m, (image f.data m).Pairwise (encKeyLt encode)
  modelSub : ∀ f ∈ model.history, f ∈ archive
  modelArchive : ArchiveConsistent archive model.nextIdentity

/-- The single Rust store represents one live store in the reference transition system,
with exact refcounted liveness over all active frame and transaction pins. -/
structure StateMatches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Store) (model : State)
    : Prop where
  /-- Find the represented store, its ghost and model frame archives, and related live attempts. -/
  history
    : ∃ store natArchive archive,
        find model.stores sid = some store
        ∧ HistoryMatches encode native.history store natArchive archive
        ∧ ∀ id : U64,
            Option.Rel (AttemptMatches encode sid native.history.index natArchive archive)
              (find native.txs.val id) (find model.txs id.val)
  /-- Exact radix liveness over all active frame and live transaction root pins. -/
  liveness : IndexLiveness native.history.index (storePins native)
  /-- The native attempt table contains one row per live ID. -/
  unique : (native.txs.val.map Prod.fst).Nodup
  /-- The reference execution started from its real initial state. -/
  reachable : transitionSystem.Reachable model

/-- Retrieve the exact split used by the extracted history proofs. -/
theorem HistoryMatches.split {encode : List U8 → String} {n : Spike.engine.History}
    {s : Store} {natArchive archive : List Frame}
    (h : HistoryMatches encode n s natArchive archive)
    : ∃ prior head,
        n.activeFrames = prior ++ [head]
        ∧ FrameOrderEq (modelFrame encode n.index head) s.head := by
  obtain he | ⟨priorIds, headId, hbr⟩ := List.eq_nil_or_concat n.log.branch.val
  · exact (h.valid.1 he).elim
  · have hbr' : n.log.branch.val = priorIds ++ [headId] := by simpa using hbr
    have hheadIdLt : headId.val < n.log.frames.val.length :=
      h.valid.2 headId (by rw [hbr']; simp)
    have hheadIdLtG : headId.val < natArchive.length := h.aligned.len.symm ▸ hheadIdLt
    let head := n.log.frames.val[headId.val]
    let gfHead := natArchive[headId.val]
    have hheadSaved : n.log.frames.val[headId.val]? = some head := List.getElem?_eq_getElem hheadIdLt
    have hgfSaved : natArchive[headId.val]? = some gfHead := List.getElem?_eq_getElem hheadIdLtG
    have hactSplit : n.activeFrames =
        (priorIds.filterMap fun id => n.log.frames.val[id.val]?) ++ [head] := by
      unfold Spike.engine.History.activeFrames branchValues
      rw [hbr', List.filterMap_append, List.filterMap_cons, List.filterMap_nil, hheadSaved]
    have hactLen : n.activeFrames.length = priorIds.length + 1 := by
      rw [branch_values_length n.log h.valid, hbr', List.length_append, List.length_singleton]
    have hheadAt : n.activeFrames[priorIds.length]'(by omega) = head := by
      have hlenPrior : (priorIds.filterMap fun id => n.log.frames.val[id.val]?).length = priorIds.length := by
        have := congrArg List.length hactSplit
        rw [List.length_append, List.length_singleton, hactLen] at this
        omega
      apply Option.some.inj
      rw [← List.getElem?_eq_getElem (by omega), hactSplit,
        List.getElem?_append_right (by omega), hlenPrior, Nat.sub_self]
      rfl
    have hheadVer : head.version.val = priorIds.length := by
      rw [← hheadAt]
      exact h.indexed priorIds.length (by omega)
    have hheadLive : modelFrame encode n.index head = gfHead :=
      h.aligned.activeLive priorIds.length headId head gfHead
        (by rw [hbr', List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl)
        hheadSaved hgfSaved (fun _ => by have := h.globalBound; omega)
    refine ⟨priorIds.filterMap (fun id => n.log.frames.val[id.val]?), head, hactSplit, ?_⟩
    rw [hheadLive]
    have hh := h.head
    have hf := h.frames
    unfold natModelFrames at hf
    rw [hbr', List.reverse_append, List.reverse_singleton, List.singleton_append,
      List.filterMap_cons, hgfSaved] at hf
    dsimp only at hf
    cases hs : s.history with
    | nil => simp [hs] at hh
    | cons mh rest =>
        rw [hs] at hh hf
        have hm : mh = s.head := Option.some.inj hh
        subst mh
        exact (List.forall₂_cons.mp hf).1

/-- A native attempt and its reference counterpart are found together by the real lookup. -/
theorem lookup_of_attempts {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Store} {w : State} {s : Store} {natArchive archive : List Frame}
    (hs : find w.stores sid = some s)
    (attempts
      : ∀ id : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val id) (find w.txs id.val))
    {id : U64} {t : Spike.engine.Tx} (ht : find n.txs.val id = some t)
    : ∃ tx,
        lookupTx w sid id.val = some (s, tx)
        ∧ AttemptMatches encode sid n.history.index natArchive archive t tx := by
  have ha := attempts id
  rw [ht] at ha
  cases hv : find w.txs id.val with
  | none => rw [hv] at ha; cases ha
  | some tx =>
      rw [hv] at ha
      cases ha with
      | some hr =>
          exact ⟨tx, by simp [lookupTx, hs, hv, hr.store], hr⟩

/-- A missing native attempt also has no reference binding. -/
theorem lookup_missing_of_attempts {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Store} {w : State} {natArchive archive : List Frame}
    (attempts
      : ∀ id : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val id) (find w.txs id.val))
    {id : U64} (ht : find n.txs.val id = none)
    : find w.txs id.val = none := by
  have ha := attempts id
  rw [ht] at ha
  cases hv : find w.txs id.val with
  | none => rfl
  | some tx => rw [hv] at ha; cases ha

/-- Relate lookup results for one live attempt, including absent attempts. -/
theorem lookupRelated_of_attempts {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Store} {w : State} {s : Store} {natArchive archive : List Frame}
    (hs : find w.stores sid = some s)
    (attempts
      : ∀ id : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val id) (find w.txs id.val))
    (id : U64)
    : Option.Rel
        (fun t (store, tx) =>
          store = s ∧ AttemptMatches encode sid n.history.index natArchive archive t tx)
        (find n.txs.val id) (lookupTx w sid id.val) := by
  cases ht : find n.txs.val id with
  | none =>
      have he : lookupTx w sid id.val = none := by
        simp [lookupTx, hs, lookup_missing_of_attempts attempts ht]
      rw [he]
      exact .none
  | some t =>
      obtain ⟨tx, he, hrel⟩ := lookup_of_attempts hs attempts ht
      rw [he]
      exact .some ⟨rfl, hrel⟩

/-- A handle that is not yet acquired cannot already occur in the reference log. -/
theorem AttemptMatches.fresh_log {encode : List U8 → String} {sid : Nat}
    {index : CellIndex} {natArchive archive : List Frame} {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid index natArchive archive n t)
    {m : String} (missing : find t.globalViews m = none)
    : t.normal.log.all (fun op => op.map != m) = true := by
  apply List.all_eq_true.mpr
  intro op hop
  by_cases hm : op.map = m
  · have hv := h.log op hop
    simp [hm, missing] at hv
  · simp [hm]

/-- The duplicated model image is read from the local, not global, part of the handle. -/
theorem AttemptMatches.localImage {encode : List U8 → String} {sid : Nat}
    {index : CellIndex} {natArchive archive : List Frame} {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid index natArchive archive n t)
    {m : String} {v : GlobalView} (hv : find t.globalViews m = some v)
    : image v.current.data m = image t.data m := by rw [h.data m, hv]; rfl

/-- Changing commit phase leaves the rest of the attempt relation intact. -/
theorem AttemptMatches.withPhase {encode : List U8 → String} {sid : Nat}
    {index : CellIndex} {natArchive archive : List Frame} {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid index natArchive archive n t)
    (p : Spike.engine.Phase)
    : AttemptMatches encode sid index natArchive archive {n with phase := p}
        {t with phase := modelPhase p} :=
  {h with phase := rfl}

/-- Snapshot capture adds only the frozen metadata. -/
theorem AttemptMatches.withSnapshot {encode : List U8 → String} {sid : Nat}
    {index : CellIndex} {natArchive archive : List Frame} {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid index natArchive archive n t)
    (native : Spike.engine.Snapshot) (model : Snapshot)
    (hCut : snapshotCut model = modelSnapshot native)
    : AttemptMatches encode sid index natArchive archive {n with snapshot := some native}
        {t with snapshot := some model} :=
  {
    h with
      snapshot := congrArg some hCut
      noSnapshot := fun hn => by cases hn
  }

/-- Every frame on a reachable reference branch has unique addresses. -/
theorem history_data_unique {frames : List Frame} {version : Nat}
    (h : Kv.Properties.History frames version)
    : ∀ f ∈ frames, Kv.Properties.Unique f.data := by
  induction h with
  | zero =>
      intro f hf
      simp only [List.mem_singleton] at hf
      subst f
      exact List.Pairwise.nil
  | succ f n tail version effect ht ih =>
      intro found hf
      rcases List.mem_cons.mp hf with he | he
      · subst found
        obtain ⟨writes, hw⟩ := effect
        rw [hw]
        apply Kv.Properties.publish_unique
        cases tail with
        | nil => exact List.Pairwise.nil
        | cons g rest => exact ih g List.mem_cons_self
      · exact ih found he

/-- A reference lookup succeeds only for an attempt owned by the selected store. -/
theorem lookup_owner {w : State} {sid tid : Nat} {s : Store} {tx : Tx}
    (h : lookupTx w sid tid = some (s, tx))
    : tx.store = sid := by
  cases hs : find w.stores sid <;> cases ht : find w.txs tid <;> simp [lookupTx, hs, ht] at h
  rename_i store t
  by_cases he : t.store = sid
  · simp [he] at h
    rw [← h.2]
    exact he
  · simp [he] at h

/-- Relate the stamp portions of matching captured views for the eligibility theorem. -/
theorem AttemptMatches.stamps {encode : List U8 → String} {sid : Nat}
    {index : CellIndex} {natArchive archive : List Frame} {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid index natArchive archive n t)
    : t.globalViews.map capturedStamps
      = n.views.val.map (viewStamps (encode ∘ alloc.vec.Vec.val)) :=
  h.views.stamps

private theorem pointDeps_preserved_of_pins (encode : List U8 → String)
    {before after : CellIndex} {pins : List U32}
    (pres : IndexPreservesPins before after pins) (n : Spike.engine.Tx)
    (inPins : ∀ row ∈ n.views.val, ∀ r ∈ viewPins row.2, r ∈ pins)
    (live : ViewsLive before n.views) (dp : DepsPinsInViews n)
    : pointDeps encode after n = pointDeps encode before n := by
  unfold pointDeps
  congr 1
  apply List.map_congr_left
  intro d hd
  cases d with
  | Key a c => rfl
  | Map m pin =>
      obtain ⟨row, hrow, hmap, hpin⟩ := dp m pin hd
      have hsub : ∀ r ∈ pinPins pin, r ∈ pins := by
        intro r hr
        exact inPins row hrow r (List.mem_append_left _ (hpin ▸ hr))
      have hlive : PinLive before pin := hpin ▸ (live row hrow).1
      have hEq := (pin_preserved_of_pins pres m pin hsub hlive).2
      simp only [Function.comp_def, byteDependency, encodeDependency, hEq]

theorem AttemptMatches.withPreservedPins {encode : List U8 → String} {sid : Nat}
    {before after : CellIndex} {pins : List U32}
    {natArchive natArchive' archive archive' : List Frame}
    {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid before natArchive archive n t)
    (pres : IndexPreservesPins before after pins)
    (inPins : ∀ row ∈ n.views.val, ∀ r ∈ viewPins row.2, r ∈ pins)
    (natSub : ∀ f ∈ natArchive, f ∈ natArchive')
    (sub : ∀ f ∈ archive, f ∈ archive')
    : AttemptMatches encode sid after natArchive' archive' n t := by
  obtain ⟨live, views⟩ := pinned_views_preserved_of_pins encode pres n.views inPins h.live
  have orig := views_origin_preserved_of_pins encode pres natSub n.views inPins h.live h.nativeOrig
  have hdepsEq := pointDeps_preserved_of_pins encode pres n inPins h.live h.depsPins
  refine {
    h with
      views := views.symm ▸ h.views
      live
      nativeOrig := orig
      modelViewsIn :=
        fun row hr =>
          ⟨sub _ (h.modelViewsIn row hr).1, sub _ (h.modelViewsIn row hr).2⟩
      deps := hdepsEq.symm ▸ h.deps
      nativeDeps :=
        fun d hd => by
          rw [hdepsEq] at hd
          have hd' := h.nativeDeps d hd
          cases d with
          | key _ _ => trivial
          | map m expected => rwa [views]
  }

theorem AttemptMatches.withHistory {encode : List U8 → String} {sid : Nat}
    {before after : CellIndex} {natArchive natArchive' archive archive' : List Frame}
    {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid before natArchive archive n t)
    (kept : IndexKeeps before after)
    (natSub : ∀ f ∈ natArchive, f ∈ natArchive')
    (sub : ∀ f ∈ archive, f ∈ archive')
    : AttemptMatches encode sid after natArchive' archive' n t := by
  obtain ⟨live, views⟩ := pinned_views_preserved encode kept n.views h.live
  have orig := views_origin_preserved encode kept natSub n.views h.live h.nativeOrig
  have hdepsEq : pointDeps encode after n = pointDeps encode before n := by
    unfold pointDeps
    congr 1
    apply List.map_congr_left
    intro d hd
    cases d with
    | Key a c => rfl
    | Map m pin =>
        obtain ⟨row, hrow, _, hpin⟩ := h.depsPins m pin hd
        have hEq := (pin_preserved kept m pin (hpin ▸ (h.live row hrow).1)).2
        simp only [Function.comp_def, byteDependency, encodeDependency, hEq]
  refine {
    h with
      views := views.symm ▸ h.views
      live
      nativeOrig := orig
      modelViewsIn :=
        fun row hr =>
          ⟨sub _ (h.modelViewsIn row hr).1, sub _ (h.modelViewsIn row hr).2⟩
      deps := hdepsEq.symm ▸ h.deps
      nativeDeps :=
        fun d hd => by
          rw [hdepsEq] at hd
          have hd' := h.nativeDeps d hd
          cases d with
          | key _ _ => trivial
          | map m expected => rwa [views]
  }

private theorem find_tx_pins_in_store {s : Spike.engine.Store} {q : U64}
    {t : Spike.engine.Tx} (hf : find s.txs.val q = some t)
    : ∀ row ∈ t.views.val, ∀ r ∈ viewPins row.2, r ∈ storePins s := by
  have hmem : (q, t) ∈ s.txs.val := by
    generalize s.txs.val = rows at hf
    induction rows with
    | nil => simp [find] at hf
    | cons hd tl ih =>
        obtain ⟨k, v⟩ := hd
        by_cases he : k = q
        · subst k
          simp [find] at hf
          subst v
          exact List.mem_cons_self
        · simp [find, he] at hf
          exact List.mem_cons_of_mem _ (ih hf)
  intro row hrow r hr
  apply List.mem_append_right
  exact List.mem_flatMap.mpr ⟨(q, t), hmem, List.mem_flatMap.mpr ⟨row, hrow, hr⟩⟩

/-- Replace a modeled attempt at its native index, preserving every other binding and the key set. -/
theorem replace_attempts {encode : List U8 → String} {sid : Nat}
    {n n' : Spike.engine.Store} {w w' : State}
    {natArchive natArchive' archive archive' : List Frame}
    (uniqueBefore : (n.txs.val.map Prod.fst).Nodup)
    (attemptsBefore
      : ∀ id : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val id) (find w.txs id.val))
    (id : U64) (i : Nat) (old next : Spike.engine.Tx) (tx : Tx)
    (hidx : n.txs.val[i]? = some (id, old))
    (hn : n'.txs.val = n.txs.val.set i (id, next))
    (hw : w'.txs = Kv.Model.set w.txs id.val tx)
    (ht : AttemptMatches encode sid n'.history.index natArchive' archive' next tx)
    (pres : IndexPreservesPins n.history.index n'.history.index (storePins n'))
    (natSub : ∀ f ∈ natArchive, f ∈ natArchive')
    (sub : ∀ f ∈ archive, f ∈ archive')
    : (n'.txs.val.map Prod.fst).Nodup
      ∧ ∀ q : U64,
          Option.Rel (AttemptMatches encode sid n'.history.index natArchive' archive')
            (find n'.txs.val q) (find w'.txs q.val) := by
  constructor
  · rw [hn, index_update_keys _ _ _ _ _ hidx]
    exact uniqueBefore
  · intro q
    have hfindQ : find n'.txs.val q =
        if q = id then some next else find n.txs.val q := by
      rw [hn, find_index_update _ _ _ _ _ _ hidx uniqueBefore, find_set_key]
    rw [hfindQ, hw, find_set_key]
    by_cases h : q = id
    · subst q
      simpa using Option.Rel.some ht
    · have hn' : q.val ≠ id.val := fun e => h (UScalar.eq_of_val_eq e)
      simp only [h, hn', ite_false]
      have hprev := attemptsBefore q
      cases hfq : find n.txs.val q with
      | none =>
          rw [hfq] at hprev
          cases hfm : find w.txs q.val with
          | none => exact .none
          | some _ => rw [hfm] at hprev; cases hprev
      | some tq =>
          rw [hfq] at hprev
          cases hfm : find w.txs q.val with
          | none => rw [hfm] at hprev; cases hprev
          | some txq =>
              rw [hfm] at hprev
              have hrel := Option.rel_some_some.mp hprev
              have hfq' : find n'.txs.val q = some tq := by rw [hfindQ, ite_eq_right h, hfq]
              exact .some
                (hrel.withPreservedPins pres (find_tx_pins_in_store hfq') natSub sub)

/-- Lift a successful one-step reference transition to reachability for the relation. -/
theorem reachable_execute {w w' : State} {action : Action} {output : Output}
    (h : transitionSystem.Reachable w) (he : execute w action = some (w', output))
    : transitionSystem.Reachable w' := by
  apply CCF.TransitionSystem.Reachable.step (action := action) h
  change step w action = some w'
  simp [step, he]

/-- A successful attempt update preserves the relation whenever the updated row does. -/
theorem replace_attempt {encode : List U8 → String} {sid : Nat}
    {n n' : Spike.engine.Store} {w w' : State} {s' : Store}
    {natArchive natArchive' archive archive' : List Frame}
    (uniqueBefore : (n.txs.val.map Prod.fst).Nodup)
    (attemptsBefore
      : ∀ id : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val id) (find w.txs id.val))
    (id : U64) (i : Nat) (old next : Spike.engine.Tx) (tx : Tx)
    (hidx : n.txs.val[i]? = some (id, old))
    (hn : n'.txs.val = n.txs.val.set i (id, next))
    (hw : w'.txs = Kv.Model.set w.txs id.val tx) (hs' : find w'.stores sid = some s')
    (hAfter : HistoryMatches encode n'.history s' natArchive' archive')
    (liveAfter : IndexLiveness n'.history.index (storePins n'))
    (ht : AttemptMatches encode sid n'.history.index natArchive' archive' next tx)
    (reach : transitionSystem.Reachable w')
    (pres : IndexPreservesPins n.history.index n'.history.index (storePins n'))
    (natSub : ∀ f ∈ natArchive, f ∈ natArchive')
    (sub : ∀ f ∈ archive, f ∈ archive')
    : StateMatches encode sid n' w' :=
  let ⟨unique, attempts⟩ :=
    replace_attempts uniqueBefore attemptsBefore id i old next tx hidx
      hn hw ht pres natSub sub
  ⟨⟨s', natArchive', archive', hs', hAfter, attempts⟩, liveAfter, unique, reach⟩

/-- Frame-order-equivalent reference history forces the native array's versions to equal its indices. -/
theorem history_related {encode : List U8 → String} {n : Spike.engine.History}
    {w : State} {sid : Nat} {s : Store} {natArchive archive : List Frame}
    (reach : transitionSystem.Reachable w) (hs : find w.stores sid = some s)
    (frames : List.Forall₂ FrameOrderEq (natModelFrames n.log natArchive) s.history)
    (global : s.global = n.global.val) (term : s.term = n.term.val)
    (ident : s.nextIdentity = n.next_identity.val)
    (valid : BranchValid n.log) (unique : BranchUnique n.log)
    (indexed : HistoryIndexValid n) (aligned : ArchiveAligned encode n natArchive)
    (revisions : RevisionHistory (natModelFrames n.log natArchive))
    (nativeArchive : ArchiveConsistent natArchive n.next_identity.val)
    (natSorted : ∀ f ∈ natArchive, ∀ m, (image f.data m).Pairwise (encKeyLt encode))
    (modelSub : ∀ f ∈ s.history, f ∈ archive)
    (modelArchive : ArchiveConsistent archive s.nextIdentity)
    : HistoryMatches encode n s natArchive archive := by
  have h := Kv.Properties.reachable_store_invariants w sid s reach hs
  have versions {rows : List Frame} {v : Nat} (hh : Kv.Properties.History rows v) :
      rows.reverse.map Frame.version = List.range (v + 1) := by
    induction hh with
    | zero => rfl
    | succ f k rest hversion _ _ ih =>
        simp only [List.reverse_cons, List.map_append, List.map_cons, List.map_nil, ih, hversion]
        exact (List.range_succ (n := k + 1)).symm
  have sameVersions : (natModelFrames n.log natArchive).map Frame.version =
      s.history.map Frame.version := by
    generalize natModelFrames n.log natArchive = nfs at frames
    generalize s.history = mfs at frames
    induction frames with
    | nil => rfl
    | @cons x y xs ys head _ ih => simp [head.version, ih]
  have hnatVersions : (natModelFrames n.log natArchive).reverse.map Frame.version =
      n.activeFrames.map (fun f => f.version.val) := by
    unfold natModelFrames Spike.engine.History.activeFrames branchValues
    rw [List.filterMap_reverse, List.reverse_reverse]
    have hbd : ∀ id ∈ n.log.branch.val, id.val < n.log.frames.val.length := valid.2
    have hmeta := aligned.metaEq
    have hlen := aligned.len
    generalize n.log.branch.val = ids at hbd
    induction ids with
    | nil => rfl
    | cons a t ih =>
        have ha : a.val < n.log.frames.val.length := hbd a List.mem_cons_self
        have haG : a.val < natArchive.length := hlen.symm ▸ ha
        simp only [List.filterMap_cons, List.getElem?_eq_getElem ha, List.getElem?_eq_getElem haG,
          List.map_cons]
        have hm := hmeta a.val n.log.frames.val[a.val] natArchive[a.val]
          (List.getElem?_eq_getElem ha) (List.getElem?_eq_getElem haG)
        exact congrArg₂ List.cons hm.1 (ih (fun x hx => hbd x (List.mem_cons_of_mem _ hx)))
  have hn : (n.activeFrames.map fun f => f.version.val) =
      List.range (s.head.version + 1) := by
    have hrev := congrArg List.reverse sameVersions
    simp only [← List.map_reverse] at hrev
    rw [hnatVersions] at hrev
    exact hrev.trans (versions h.1)
  have hlenAct : n.activeFrames.length = s.head.version + 1 := by
    have := congrArg List.length hn
    simpa only [List.length_map, List.length_range] using this
  have hgb : n.global.val < n.activeFrames.length := by
    have := h.2.2.1
    omega
  refine ⟨
    ?_,
    frames,
    h.2.1,
    ?_,
    global,
    hgb,
    term,
    ident,
    valid,
    unique,
    indexed,
    aligned,
    revisions,
    nativeArchive,
    natSorted,
    modelSub,
    modelArchive
  ⟩
  · intro he
    simp [he] at hn
  · intro i hi
    have hAt := congrArg (fun rows : List Nat => rows[i]?) hn
    have hir : i < (List.range (s.head.version + 1)).length := by
      rw [List.length_range]; omega
    rw [List.getElem?_eq_getElem (by simpa using hi), List.getElem?_eq_getElem hir,
      List.getElem_map, List.getElem_range] at hAt
    exact Option.some.inj hAt

/-- The modeled store changes without changing the table of attempts. -/
theorem replace_history {encode : List U8 → String} {sid : Nat}
    {n n' : Spike.engine.Store} {w w' : State} {s' : Store}
    {natArchive natArchive' archive archive' : List Frame}
    (uniqueBefore : (n.txs.val.map Prod.fst).Nodup)
    (attemptsBefore
      : ∀ id : U64,
          Option.Rel (AttemptMatches encode sid n.history.index natArchive archive)
            (find n.txs.val id) (find w.txs id.val))
    (history : HistoryMatches encode n'.history s' natArchive' archive')
    (liveAfter : IndexLiveness n'.history.index (storePins n'))
    (hs : find w'.stores sid = some s') (hn : n'.txs = n.txs) (hw : w'.txs = w.txs)
    (reach : transitionSystem.Reachable w')
    (pres : IndexPreservesPins n.history.index n'.history.index (storePins n'))
    (natSub : ∀ f ∈ natArchive, f ∈ natArchive')
    (sub : ∀ f ∈ archive, f ∈ archive')
    : StateMatches encode sid n' w' := by
  refine ⟨⟨s', natArchive', archive', hs, history, ?_⟩, liveAfter, ?_, reach⟩
  · intro id
    rw [hn, hw]
    have hprev := attemptsBefore id
    cases hfq : find n.txs.val id with
    | none =>
        rw [hfq] at hprev
        cases hfm : find w.txs id.val with
        | none => exact .none
        | some _ => rw [hfm] at hprev; cases hprev
    | some tq =>
        rw [hfq] at hprev
        cases hfm : find w.txs id.val with
        | none => rw [hfm] at hprev; cases hprev
        | some txq =>
            rw [hfm] at hprev
            have hrel := Option.rel_some_some.mp hprev
            exact .some (hrel.withPreservedPins pres (find_tx_pins_in_store (hn.symm ▸ hfq)) natSub sub)
  · rw [hn]; exact uniqueBefore

/-- A bounded Rust step either agrees with the reference action modulo relaxed order
or rejects without mutation. -/
def StepMatches (encode : List U8 → String) (sid : Nat) (action : Action)
    (before : Spike.engine.Store)
    (expected : Option (State × Output))
    (actual
      : core.result.Result Spike.engine.Output Spike.engine.Error × Spike.engine.Store)
    : Prop :=
  match expected with
  | none => actual = (.Err .Disabled, before)
  | some (model, output) =>
      ∃ nativeOutput,
        actual.1 = .Ok nativeOutput
        ∧ OutputMatches action (modelOutput encode nativeOutput) output
        ∧ StateMatches encode sid actual.2 model

end KvRust
