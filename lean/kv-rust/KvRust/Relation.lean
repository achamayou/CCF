-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Scan

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

/-- The two attempts differ in representation and in the model-only normal operation log. -/
structure AttemptMatches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Tx) (model : Tx)
    : Prop where
  /-- The model attempt belongs to the represented store. -/
  store : model.store = sid
  /-- The snapshot metadata agrees even after the original frame has been rolled back. -/
  snapshot : model.snapshot.map snapshotCut = native.snapshot.map modelSnapshot
  /-- The operation phases agree. -/
  phase : model.phase = modelPhase native.phase
  /-- The sequence of acquired maps, stamps, and local/global images agrees. -/
  views : modelPinnedViews model.globalViews = rustPinnedViews encode native.views
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
  /-- The staged overlay includes removals and its order is observable through scans. -/
  writes : pointWrites encode native = model.normal.writes
  /-- Each native condition is tested by the reference, in reverse recording order. -/
  deps : pointDeps encode native = model.normal.deps

/-- A native contiguous oldest-first array represents the model's newest-first branch. -/
structure HistoryMatches (encode : List U8 → String)
    (native : Spike.engine.History) (model : Store)
    : Prop where
  /-- The initial frame is retained. -/
  nonempty : native.frames.val ≠ []
  /-- The entire surviving branch is represented. -/
  frames : model.history = modelFrames native (modelFrame encode)
  /-- The selected model head is the first projected frame. -/
  head : model.history.head? = some model.head
  /-- Frame versions equal their native indices. -/
  indexed
    : ∀ i (h : i < native.frames.val.length),
        (modelFrame encode native.frames.val[i]).version = i
  /-- The compacted frontier agrees. -/
  global : model.global = native.global.val
  /-- The current term agrees. -/
  term : model.term = native.term.val
  /-- The next identity agrees, including after local version reuse. -/
  identity : model.nextIdentity = native.next_identity.val

/-- The single Rust store represents one live store in the reference transition system. -/
structure StateMatches (encode : List U8 → String) (sid : Nat)
    (native : Spike.engine.Store) (model : State)
    : Prop where
  /-- Find the represented store and compare its complete history. -/
  history
    : ∃ store,
        find model.stores sid = some store ∧ HistoryMatches encode native.history store
  /-- The native attempt table contains one row per live ID. -/
  unique : (native.txs.val.map Prod.fst).Nodup
  /-- Pointwise lookup forgets differences in the ordering of the attempt tables. -/
  attempts
    : ∀ id : U64,
        Option.Rel (AttemptMatches encode sid)
          (find native.txs.val id) (find model.txs id.val)
  /-- The reference execution started from its real initial state. -/
  reachable : transitionSystem.Reachable model

/-- Retrieve the exact split used by the extracted history proofs. -/
theorem HistoryMatches.split {encode : List U8 → String} {n : Spike.engine.History}
    {s : Store} (h : HistoryMatches encode n s)
    : ∃ prior head, n.frames.val = prior ++ [head] ∧ s.head = modelFrame encode head := by
  obtain he | ⟨prior, head, he⟩ := List.eq_nil_or_concat n.frames.val
  · exact (h.nonempty he).elim
  · have he' : n.frames.val = prior ++ [head] := by simpa using he
    refine ⟨prior, head, he', ?_⟩
    have hh := h.head
    rw [h.frames, modelFrames, he', List.reverse_append] at hh
    simpa using hh.symm

/-- A native attempt and its reference counterpart are found together by the real lookup. -/
theorem StateMatches.lookup {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Store} {w : State} (h : StateMatches encode sid n w)
    {s : Store} (hs : find w.stores sid = some s) {id : U64} {t : Spike.engine.Tx}
    (ht : find n.txs.val id = some t)
    : ∃ tx, lookupTx w sid id.val = some (s, tx) ∧ AttemptMatches encode sid t tx := by
  have ha := h.attempts id
  rw [ht] at ha
  cases hv : find w.txs id.val with
  | none => rw [hv] at ha; cases ha
  | some tx =>
      rw [hv] at ha
      cases ha with
      | some hr =>
          exact ⟨tx, by simp [lookupTx, hs, hv, hr.store], hr⟩

/-- A missing native attempt also has no reference binding. -/
theorem StateMatches.lookup_missing {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Store} {w : State} (h : StateMatches encode sid n w)
    {id : U64} (ht : find n.txs.val id = none)
    : find w.txs id.val = none := by
  have ha := h.attempts id
  rw [ht] at ha
  cases hv : find w.txs id.val with
  | none => rfl
  | some tx => rw [hv] at ha; cases ha

/-- Relate lookup results for one live attempt, including absent attempts. -/
theorem StateMatches.lookupRelated {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Store} {w : State} (h : StateMatches encode sid n w)
    {s : Store} (hs : find w.stores sid = some s) (id : U64)
    : Option.Rel (fun t (store, tx) => store = s ∧ AttemptMatches encode sid t tx)
        (find n.txs.val id) (lookupTx w sid id.val) := by
  cases ht : find n.txs.val id with
  | none =>
      have he : lookupTx w sid id.val = none := by
        simp [lookupTx, hs, h.lookup_missing ht]
      rw [he]
      exact .none
  | some t =>
      obtain ⟨tx, he, hrel⟩ := h.lookup hs ht
      rw [he]
      exact .some ⟨rfl, hrel⟩

/-- A handle that is not yet acquired cannot already occur in the reference log. -/
theorem AttemptMatches.fresh_log {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Tx} {t : Tx} (h : AttemptMatches encode sid n t)
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
    {n : Spike.engine.Tx} {t : Tx} (h : AttemptMatches encode sid n t)
    {m : String} {v : GlobalView} (hv : find t.globalViews m = some v)
    : image v.current.data m = image t.data m := by rw [h.data m, hv]; rfl

/-- Changing commit phase leaves the rest of the attempt relation intact. -/
theorem AttemptMatches.withPhase {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Tx} {t : Tx} (h : AttemptMatches encode sid n t)
    (p : Spike.engine.Phase)
    : AttemptMatches encode sid {n with phase := p} {t with phase := modelPhase p} :=
  {h with phase := rfl}

/-- Snapshot capture adds only the frozen metadata. -/
theorem AttemptMatches.withSnapshot {encode : List U8 → String} {sid : Nat}
    {n : Spike.engine.Tx} {t : Tx} (h : AttemptMatches encode sid n t)
    (native : Spike.engine.Snapshot) (model : Snapshot)
    (hCut : snapshotCut model = modelSnapshot native)
    : AttemptMatches encode sid {n with snapshot := some native}
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
    {n : Spike.engine.Tx} {t : Tx} (h : AttemptMatches encode sid n t)
    : t.globalViews.map capturedStamps
      = n.views.val.map (viewStamps (encode ∘ alloc.vec.Vec.val)) := by
  let project := fun (p : String × PinnedView) => (p.1, p.2.birth, p.2.revision)
  calc
    _ = (modelPinnedViews t.globalViews).map project := by
      rw [modelPinnedViews, List.map_map]
      apply List.map_congr_left
      rintro ⟨k, v⟩ _
      rfl
    _ = (rustPinnedViews encode n.views).map project :=
      congrArg (List.map project) h.views
    _ = _ := by
      rw [rustPinnedViews, List.map_map]
      apply List.map_congr_left
      rintro ⟨k, v⟩ _
      rfl

/-- Replace a modeled attempt at its native index, preserving every other binding and the key set. -/
theorem replace_attempts {encode : List U8 → String} {sid : Nat}
    {n n' : Spike.engine.Store} {w w' : State} (before : StateMatches encode sid n w)
    (id : U64) (i : Nat) (old next : Spike.engine.Tx) (tx : Tx)
    (hidx : n.txs.val[i]? = some (id, old))
    (hn : n'.txs.val = n.txs.val.set i (id, next))
    (hw : w'.txs = Kv.Model.set w.txs id.val tx)
    (ht : AttemptMatches encode sid next tx)
    : (n'.txs.val.map Prod.fst).Nodup
      ∧ ∀ q : U64,
          Option.Rel (AttemptMatches encode sid)
            (find n'.txs.val q) (find w'.txs q.val) := by
  constructor
  · rw [hn, index_update_keys _ _ _ _ _ hidx]
    exact before.unique
  · intro q
    rw [hn, hw, find_index_update _ _ _ _ _ _ hidx before.unique, find_set_key, find_set_key]
    by_cases h : q = id
    · subst q
      simpa using Option.Rel.some ht
    · have hn' : q.val ≠ id.val := fun e => h (UScalar.eq_of_val_eq e)
      simpa [h, hn'] using before.attempts q

/-- Lift a successful one-step reference transition to reachability for the relation. -/
theorem reachable_execute {w w' : State} {action : Action} {output : Output}
    (h : transitionSystem.Reachable w) (he : execute w action = some (w', output))
    : transitionSystem.Reachable w' := by
  apply CCF.TransitionSystem.Reachable.step (action := action) h
  change step w action = some w'
  simp [step, he]

/-- A successful attempt update preserves the relation whenever the updated row does. -/
theorem replace_attempt {encode : List U8 → String} {sid : Nat}
    {n n' : Spike.engine.Store} {w w' : State} (h : StateMatches encode sid n w)
    (id : U64) (i : Nat) (old next : Spike.engine.Tx) (tx : Tx)
    (hidx : n.txs.val[i]? = some (id, old))
    (hn : n'.txs.val = n.txs.val.set i (id, next))
    (hw : w'.txs = Kv.Model.set w.txs id.val tx)
    (history : ∃ s, find w'.stores sid = some s ∧ HistoryMatches encode n'.history s)
    (ht : AttemptMatches encode sid next tx) (reach : transitionSystem.Reachable w')
    : StateMatches encode sid n' w' :=
  let ⟨unique, attempts⟩ := replace_attempts h id i old next tx hidx hn hw ht
  ⟨history, unique, attempts, reach⟩

/-- Exact reference history forces the native array's versions to equal its indices. -/
theorem history_related {encode : List U8 → String} {n : Spike.engine.History}
    {w : State} {sid : Nat} {s : Store}
    (reach : transitionSystem.Reachable w) (hs : find w.stores sid = some s)
    (frames : s.history = modelFrames n (modelFrame encode))
    (global : s.global = n.global.val) (term : s.term = n.term.val)
    (ident : s.nextIdentity = n.next_identity.val)
    : HistoryMatches encode n s := by
  have h := Kv.Properties.reachable_store_invariants w sid s reach hs
  have versions {rows : List Frame} {v : Nat} (hh : Kv.Properties.History rows v) :
      rows.reverse.map Frame.version = List.range (v + 1) := by
    induction hh with
    | zero => rfl
    | succ f k rest hversion _ _ ih =>
        simp only [List.reverse_cons, List.map_append, List.map_cons, List.map_nil, ih, hversion]
        exact (List.range_succ (n := k + 1)).symm
  have hn : (n.frames.val.map fun f => (modelFrame encode f).version) =
      List.range (s.head.version + 1) := by
    simpa only [frames, modelFrames, ← List.map_reverse, List.reverse_reverse,
      List.map_map, Function.comp_def]
      using versions h.1
  refine ⟨?_, frames, h.2.1, ?_, global, term, ident⟩
  · intro he
    simp [he] at hn
  · intro i hi
    have hAt := congrArg (fun rows : List Nat => rows[i]?) hn
    have hir : i < (List.range (s.head.version + 1)).length := by
      have hl := congrArg List.length hn
      simp only [List.length_map] at hl
      omega
    rw [List.getElem?_eq_getElem (by simpa using hi), List.getElem?_eq_getElem hir,
      List.getElem_map, List.getElem_range] at hAt
    exact Option.some.inj hAt

/-- The modeled store changes without changing the table of attempts. -/
theorem replace_history {encode : List U8 → String} {sid : Nat}
    {n n' : Spike.engine.Store} {w w' : State} (h : StateMatches encode sid n w)
    {s : Store} (history : HistoryMatches encode n'.history s)
    (hs : find w'.stores sid = some s) (hn : n'.txs = n.txs) (hw : w'.txs = w.txs)
    (reach : transitionSystem.Reachable w')
    : StateMatches encode sid n' w' := by
  refine ⟨⟨s, hs, history⟩, ?_, ?_, reach⟩
  · rw [hn]; exact h.unique
  · intro id
    rw [hn, hw]
    exact h.attempts id

/-- A bounded Rust step either agrees with the reference action or rejects without mutation. -/
def StepMatches (encode : List U8 → String) (sid : Nat)
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
        ∧ modelOutput encode nativeOutput = output
        ∧ StateMatches encode sid actual.2 model

end KvRust
