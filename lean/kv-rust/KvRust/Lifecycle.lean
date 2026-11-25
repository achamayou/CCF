-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Apply
public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private abbrev NativeResult :=
  core.result.Result Spike.engine.Output Spike.engine.Error

private abbrev NativeStep := NativeResult × Spike.engine.Store

private def emptyFrame (root : Spike.radix.DualRoot) : Spike.engine.Frame :=
  {
    version := 0#u64
    data := root
    revisions := alloc.vec.Vec.new _
    births := alloc.vec.Vec.new _
  }

/-- The extracted constructor creates the model's empty version-zero history. -/
theorem store_new_lifecycle (encode : List U8 → String) (term : U64)
    : WP.spec (Spike.engine.Store.new term)
        (fun s =>
          ∃ head,
            s.history.activeFrames = [head]
            ∧ s.history.log.frames.val = [head]
            ∧ modelFrame encode s.history.index head = ({term := term.val} : Store).head
            ∧ modelFrames s.history (modelFrame encode s.history.index)
              = ({term := term.val} : Store).history
            ∧ s.history.global.val = 0
            ∧ s.history.term = term
            ∧ s.history.next_identity.val = 1
            ∧ s.txs.val = []
            ∧ BranchValid s.history.log
            ∧ HistoryIndexValid s.history) := by
  simp only [Spike.engine.Store.new, Spike.engine.History.new, Spike.engine.Frame.empty,
    Spike.engine.Assoc.new, Aeneas.Std.bind_assoc, bind_ok]
  apply WP.spec_bind (index_new_refines Spike.engine.Cell)
  intro index ⟨indexValid, empty⟩
  apply WP.spec_bind empty
  intro root view
  apply WP.spec_bind (branch_new_refines (emptyFrame root))
  intro log ⟨valid, hframes, saved⟩
  simp only [WP.spec_ok]
  have zero : modelFrame encode index (emptyFrame root) = ({term := term.val} : Store).head := by
    change {modelMetadata (encode ∘ alloc.vec.Vec.val) (emptyFrame root) with
      data := encodeData encode (indexedCellData (indexRows index root))} = _
    rw [index_rows_eq view]
    rfl
  refine ⟨
    emptyFrame root,
    hframes,
    saved,
    zero,
    ?_,
    by simp,
    by simp,
    by simp,
    by simp,
    valid,
    ⟨indexValid, ?_⟩
  ⟩
  · simp [modelFrames, Spike.engine.History.activeFrames, hframes, zero]
  · intro i frame h
    change log.frames.val[i]? = some frame at h
    rw [saved] at h
    have same := List.mem_singleton.mp (List.mem_iff_getElem?.mpr ⟨i, h⟩)
    subst frame
    change IndexView index root (indexRows index root)
    rwa [index_rows_eq view]

/-- The exact native transaction installed by a fresh `Begin`. -/
def lifecycleNewTx : Spike.engine.Tx :=
  {
    snapshot := none
    views := alloc.vec.Vec.new _
    pending := alloc.vec.Vec.new _
    deps := alloc.vec.Vec.new _
    unavailable := false
    phase := .Active
  }

/-- The extracted transaction constructor initializes every attempt field. -/
theorem tx_new_lifecycle : Spike.engine.Tx.new = .ok lifecycleNewTx := by
  simp [Spike.engine.Tx.new, Spike.engine.Assoc.new, lifecycleNewTx]

private theorem clone_dependencies (rows : alloc.vec.Vec Spike.engine.Dependency)
    : alloc.vec.CloneVec.clone Spike.engine.Dependency.Insts.CoreCloneClone rows
      = .ok rows := by
  have hsingle (d : Spike.engine.Dependency)
      : Spike.engine.Dependency.Insts.CoreCloneClone.clone d = .ok d := by
    cases d with
    | Key addr cell =>
        cases cell <;> simp [Spike.engine.Dependency.Insts.CoreCloneClone.clone,
          Spike.engine.copy_cell, clone_address, clone_cell]
    | Map map image =>
        simp [Spike.engine.Dependency.Insts.CoreCloneClone.clone, clone_bytes, clone_assoc]
  generalize hr :
    alloc.vec.CloneVec.clone Spike.engine.Dependency.Insts.CoreCloneClone rows = result
  suffices h : WP.spec result (fun next => next = rows) by
    cases result using Result.cases with
    | ret next => simpa using h
    | vis _ _ => simp at h
    | div => simp at h
  rw [← hr, alloc.vec.CloneVec.clone]
  apply WP.spec_bind (Slice.clone_spec (s := rows.slice) (fun a _ => hsingle a))
  intro next hn
  subst next
  cases rows
  simp

private theorem clone_tx (t : Spike.engine.Tx)
    : Spike.engine.Tx.Insts.CoreCloneClone.clone t = .ok t := by
  simp [Spike.engine.Tx.Insts.CoreCloneClone.clone, clone_assoc, clone_dependencies]

/-- Enabled `Begin` prepends the fresh attempt; duplicate IDs leave the store unchanged. -/
theorem execute_begin_lifecycle (s : Spike.engine.Store) (id : U64)
    (room : find s.txs.val id = none → s.txs.val.length < Usize.max)
    : WP.spec (Spike.engine.Store.execute s (.Begin id))
        (fun (out, after) =>
          match find s.txs.val id with
          | none =>
              out = .Ok .Unit
              ∧ after.history = s.history
              ∧ after.txs.val = Kv.Model.set s.txs.val id lifecycleNewTx
          | some _ => (out, after) = (.Err .Disabled, s)) := by
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (assoc_index Spike.U64.Insts.Ccf_kv_spikeEngineKey s.txs id
    (fun _ => rfl))
  intro index hi
  cases index with
  | none =>
      change find s.txs.val id = none at hi
      simp only [hi, core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true,
        ite_false, tx_new_lifecycle, bind_ok]
      apply WP.spec_bind (assoc_set Spike.U64.Insts.Ccf_kv_spikeEngineKey
        core.clone.CloneU64 Spike.engine.Tx.Insts.CoreCloneClone s.txs id lifecycleNewTx
        (fun _ => rfl) (fun _ => rfl) clone_tx (room hi))
      intro next hn
      simp [hn]
  | some i =>
      obtain ⟨t, _, ht⟩ := hi
      simp [core.option.Option.is_some, ht]

private abbrev AttemptRows := alloc.vec.Vec (U64 × Spike.engine.Tx)

private theorem drop_after_set {α : Type} (rows : List α) (i : Nat) (x : α)
    : (rows.set i x).drop (i + 1) = rows.drop (i + 1) := by
  induction rows generalizing i with
  | nil => simp
  | cons row rest ih =>
      cases i with
      | zero => rfl
      | succ i => exact ih i

private theorem move_other_attempt_matches (kept : AttemptRows)
    (row : U64 × Spike.engine.Tx) (id : U64) (room : kept.val.length < Usize.max)
    : WP.spec (Spike.engine.move_other_attempt kept row id)
        (fun (next, _) =>
          next.val = kept.val ++ erase [row] id
          ∧ next.val.length ≤ kept.val.length + 1) := by
  obtain ⟨key, tx⟩ := row
  unfold Spike.engine.move_other_attempt
  change WP.spec (if key != id then do
      let tmp ← Spike.engine.Tx.new
      let (moved, empty) := core.mem.swap tmp tx
      let out ← alloc.vec.Vec.push kept (key, moved)
      Result.ok (out, (key, empty))
    else Result.ok (kept, (key, tx))) _
  by_cases same : key = id
  · simp [same, erase]
  · rw [show (key != id) = true from bne_iff_ne.mpr same]
    simp only [ite_true, tx_new_lifecycle, bind_ok, core.mem.swap]
    apply WP.spec_bind (alloc.vec.Vec.push_spec kept (key, tx) room)
    intro next he
    rw [WP.spec_ok]
    simp [he, erase, same]

/-- Ending an attempt moves untouched rows without copying their observations or values. -/
private theorem erase_attempt_matches (rows : AttemptRows) (id : U64)
    : WP.spec (Spike.engine.erase_attempt rows id)
        (fun next => next.val = erase rows.val id) := by
  unfold Spike.engine.erase_attempt
  apply WP.spec_bind (Pₘ := fun out => out.val = erase rows.val id)
  · unfold Spike.engine.erase_attempt_loop
    apply loop.spec_decr_nat (fun (_, _, i) => rows.val.length - (i : Usize).val)
      (fun (working, kept, i) =>
        working.val.length = rows.val.length
        ∧ kept.val.length ≤ i.val
        ∧ kept.val ++ erase (working.val.drop i.val) id = erase rows.val id)
      _ _ _
    · rintro ⟨working, kept, i⟩ ⟨size, keptBound, suffix⟩
      dsimp only at size keptBound suffix ⊢
      unfold Spike.engine.erase_attempt_loop.body
      have len : (alloc.vec.Vec.len working).val = working.val.length :=
        alloc.vec.Vec.len_val working
      have space := alloc.vec.Vec.len_ineq working
      have one : (1#usize : Usize).val = 1 := rfl
      by_cases run : i < alloc.vec.Vec.len working
      · have inside : i.val < working.val.length := by rwa [← len]
        rw [ite_eq_left run, alloc.vec.Vec.index_mut_slice_index]
        apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec working i inside)
        rintro ⟨row, back⟩ ⟨read, update⟩
        apply WP.spec_bind (move_other_attempt_matches kept row id (by omega))
        rintro ⟨out, blank⟩ ⟨copied, growth⟩
        change WP.spec (do
          let j ← i + 1#usize
          Result.ok (ControlFlow.cont (back blank, out, j))) _
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
        intro j hj
        have next : j.val = i.val + 1 := by omega
        have set : (back blank).val = working.val.set i.val blank := by
          rw [update]
          exact alloc.vec.Vec.set_val_eq _ _ _
        rw [WP.spec_ok]
        dsimp only at copied growth ⊢
        refine ⟨⟨by simpa [set] using size, by omega, ?_⟩, by omega⟩
        have shifted : (back blank).val.drop j.val = working.val.drop (i.val + 1) := by
          rw [set, next, drop_after_set]
        have split : working.val.drop i.val = [row] ++ working.val.drop (i.val + 1) := by
          rw [List.drop_eq_getElem_cons inside, ← read]
          rfl
        rw [copied, List.append_assoc, shifted]
        rw [split] at suffix
        simpa only [erase, List.filter_append] using suffix
      · have beyond : working.val.length ≤ i.val := by rw [← len]; exact Nat.le_of_not_gt run
        rw [ite_eq_right run, WP.spec_ok]
        simpa [List.drop_eq_nil_of_le beyond, erase] using suffix
    · simp [alloc.vec.Vec.with_capacity]
  · intro out h
    simpa using h

/-- Enabled `End` erases the ID without changing history; missing IDs leave the store unchanged. -/
theorem execute_end_lifecycle (s : Spike.engine.Store) (id : U64)
    : WP.spec (Spike.engine.Store.execute s (.End id))
        (fun (out, after) =>
          match find s.txs.val id with
          | none => (out, after) = (.Err .Disabled, s)
          | some _ =>
              out = .Ok .Unit
              ∧ after.history = s.history
              ∧ after.txs.val = erase s.txs.val id) := by
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (tx_index s id)
  intro index hi
  cases index with
  | Err why =>
      obtain ⟨rfl, hmissing⟩ := hi
      simp [hmissing, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | Ok i =>
      obtain ⟨t, _, ht⟩ := hi
      simp only [ht, core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
      apply WP.spec_bind (erase_attempt_matches s.txs id)
      intro next hn
      simp [hn]

/-- `SetTerm` changes only the term, including on equality, and rejects a decrease. -/
theorem execute_set_term_lifecycle (s : Spike.engine.Store) (term : U64)
    : WP.spec (Spike.engine.Store.execute s (.SetTerm term))
        (fun r =>
          r
          = if term.val < s.history.term.val then
              (.Err .Disabled, s)
            else
              (.Ok .Unit, {s with history := {s.history with term}})) := by
  change WP.spec
    (α := NativeStep)
    (if term.val < s.history.term.val then Result.ok (.Err .Disabled, s)
      else Result.ok (.Ok .Unit, {s with history := {s.history with term}})) _
  split <;> simp [*]

/-- An in-place attempt update preserves history and changes exactly the selected row. -/
def LifecycleRowUpdate (s after : Spike.engine.Store) (id : U64)
    (t next : Spike.engine.Tx)
    : Prop :=
  after.history = s.history
  ∧ ∃ index : Nat,
      s.txs.val[index]? = some (id, t) ∧ after.txs.val = s.txs.val.set index (id, next)

/-- A guarded attempt update either takes its designated step or leaves the store untouched. -/
def LifecycleTxPost (s : Spike.engine.Store) (id : U64)
    (step : Spike.engine.Tx → Option (Spike.engine.Output × Spike.engine.Tx))
    (r : core.result.Result Spike.engine.Output Spike.engine.Error × Spike.engine.Store)
    : Prop :=
  match (find s.txs.val id).bind step with
  | none => r = (.Err .Disabled, s)
  | some (out, next) =>
      r.1 = .Ok out ∧ ∃ t, find s.txs.val id = some t ∧ LifecycleRowUpdate s r.2 id t next

private theorem vec_index {α : Type} (rows : alloc.vec.Vec α) (i : Usize) (a : α)
    (h : rows.val[i.val]? = some a)
    : alloc.vec.Vec.index_usize rows i = .ok a := by
  simp [alloc.vec.Vec.index_usize, alloc.vec.Vec.getElem?_Nat_eq, h]

private theorem index_mut_row (s : Spike.engine.Store) (i : Usize) (id : U64)
    (t : Spike.engine.Tx) (h : s.txs.val[i.val]? = some (id, t))
    : alloc.vec.Vec.index_mut
        (core.slice.index.SliceIndexUsizeSlice (U64 × Spike.engine.Tx)) s.txs i
      = .ok ((id, t), alloc.vec.Vec.set s.txs i) := by
  simp [alloc.vec.Vec.index_mut_slice_index, alloc.vec.Vec.index_mut_usize, vec_index _ _ _ h]

private theorem row_update (s : Spike.engine.Store) (id : U64) (t next : Spike.engine.Tx)
    (i : Usize) (h : s.txs.val[i.val]? = some (id, t))
    : LifecycleRowUpdate s {s with txs := alloc.vec.Vec.set s.txs i (id, next)} id t
        next :=
  ⟨rfl, i.val, h, alloc.vec.Vec.set_val_eq ..⟩

private theorem restore_row (s : Spike.engine.Store) (id : U64) (t : Spike.engine.Tx)
    (i : Usize) (h : s.txs.val[i.val]? = some (id, t))
    : alloc.vec.Vec.set s.txs i (id, t) = s.txs := by
  obtain ⟨hi, hget⟩ := List.getElem?_eq_some_iff.mp h
  apply alloc.vec.Vec.ext
  rw [alloc.vec.Vec.set_val_eq, ← hget]
  exact List.set_getElem_self hi

/-- `Snapshot` freezes the actual head version and term, only on a fresh active attempt. -/
theorem execute_snapshot_lifecycle (s : Spike.engine.Store) (id : U64)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.history.activeFrames = prior ++ [head])
    (valid : BranchValid s.history.log)
    : WP.spec (Spike.engine.Store.execute s (.Snapshot id))
        (LifecycleTxPost s id
          fun t =>
            match t.phase, t.snapshot with
            | .Active, none =>
                some
                  (
                    .Snapshot head.version s.history.global s.history.term,
                    {
                      t with
                        snapshot := some {version := head.version, term := s.history.term}
                    }
                  )
            | _, _ => none) := by
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (tx_index s id)
  intro index hi
  cases index with
  | Err why =>
      obtain ⟨rfl, hmissing⟩ := hi
      simp [LifecycleTxPost, hmissing, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | Ok i =>
      obtain ⟨t, hrow, ht⟩ := hi
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
        alloc.vec.Vec.index_slice_index, vec_index _ _ _ hrow]
      cases hp : t.phase with
      | Active =>
          cases hs : t.snapshot with
          | some _ => simp [LifecycleTxPost, ht, hp, hs, core.option.Option.is_some]
          | none =>
              simp [LifecycleTxPost, ht, hp, hs, core.option.Option.is_some,
                history_head s.history prior head hframes valid, index_mut_row s i id t hrow]
              simpa [hp] using (row_update s id t
                {t with snapshot := some {version := head.version, term := s.history.term}} i hrow)
      | Committing => simp [LifecycleTxPost, ht, hp]
      | Applied _ => simp [LifecycleTxPost, ht, hp]
      | Finished => simp [LifecycleTxPost, ht, hp]

/-- `CommitBegin` moves a live active attempt to committing, with no other mutations. -/
theorem execute_commit_begin_lifecycle (s : Spike.engine.Store) (id : U64)
    : WP.spec (Spike.engine.Store.execute s (.CommitBegin id))
        (LifecycleTxPost s id
          fun t =>
            match t.phase with
            | .Active => some (.Unit, {t with phase := .Committing})
            | _ => none) := by
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (tx_index s id)
  intro index hi
  cases index with
  | Err why =>
      obtain ⟨rfl, hmissing⟩ := hi
      simp [LifecycleTxPost, hmissing, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | Ok i =>
      obtain ⟨t, hrow, ht⟩ := hi
      have hrestore (phase : Spike.engine.Phase) (hp : t.phase = phase)
          : {t with phase} = t := by rw [← hp]
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, index_mut_row s i id t hrow]
      cases hp : t.phase with
      | Active =>
          simp [LifecycleTxPost, ht, hp]
          exact row_update s id t _ i hrow
      | Committing =>
          simp [LifecycleTxPost, ht, hp, hrestore _ hp, restore_row s id t i hrow]
      | Applied _ =>
          simp [LifecycleTxPost, ht, hp, hrestore _ hp, restore_row s id t i hrow]
      | Finished =>
          simp [LifecycleTxPost, ht, hp, hrestore _ hp, restore_row s id t i hrow]

/-- Assigned commit version, or `none` when the supplied outcome is disabled. -/
def lifecycleCommitVersion (t : Spike.engine.Tx) (outcome : Spike.engine.Outcome)
    : Option U64 :=
  match t.phase, outcome with
  | .Applied _, .Conflict => none
  | .Applied v, _ => some v
  | .Committing, .Success =>
      if t.pending.val = [] ∧ t.unavailable = false then some 0#u64 else none
  | .Committing, _ => some 0#u64
  | _, _ => none

/-- Every phase/outcome combination returns its prescribed version or rejects without mutation. -/
theorem execute_commit_result_lifecycle (s : Spike.engine.Store) (id : U64)
    (outcome : Spike.engine.Outcome)
    : WP.spec (Spike.engine.Store.execute s (.CommitResult id outcome))
        (LifecycleTxPost s id
          fun t =>
            (lifecycleCommitVersion t outcome).map
              fun v =>
                (.Committed outcome v, {t with phase := .Finished})) := by
  unfold Spike.engine.Store.execute Spike.engine.Store.finish
  apply WP.spec_bind (tx_index s id)
  intro index hi
  cases index with
  | Err why =>
      obtain ⟨rfl, hmissing⟩ := hi
      simp [LifecycleTxPost, hmissing, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | Ok i =>
      obtain ⟨t, hrow, ht⟩ := hi
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, index_mut_row s i id t hrow]
      cases hp : t.phase <;> cases outcome <;>
        simp [LifecycleTxPost, ht, lifecycleCommitVersion, hp, alloc.vec.Vec.is_empty,
          restore_row s id t i hrow] <;>
        try exact row_update s id t _ i hrow
      by_cases hw : t.pending.val = []
      · cases hu : t.unavailable <;> simp_all [LifecycleTxPost]
        simpa [hu] using (row_update s id t {t with phase := .Finished} i hrow)
      · simp_all [LifecycleTxPost]

/-- Erasing one attempt preserves lookup at all other keys. -/
theorem lifecycle_find_erase {K V : Type} [DecidableEq K] (rows : Assoc K V)
    (id other : K)
    : find (erase rows id) other = if other = id then none else find rows other := by
  induction rows with
  | nil => simp [erase, find]
  | cons row rows ih =>
      obtain ⟨k, v⟩ := row
      by_cases hk : k = id <;> by_cases ho : other = id <;> by_cases hd : k = other <;>
        simp_all [erase, find]

/-- Model replacement affects only the updated key. -/
theorem lifecycle_find_set {K V : Type} [DecidableEq K] (rows : Assoc K V)
    (id other : K) (next : V)
    : find (Kv.Model.set rows id next) other
      = if other = id then some next else find rows other := by
  by_cases ho : other = id
  · subst other
    simp [Kv.Model.set, find]
  · simp [Kv.Model.set, find, Ne.symm ho, lifecycle_find_erase, ho]

/-- An in-place write and model replacement agree pointwise for unique keys. -/
theorem lifecycle_find_set_in_place {K V : Type} [DecidableEq K] (rows : Assoc K V)
    (i : Nat) (id other : K) (old next : V)
    (unique : (rows.map Prod.fst).Nodup) (hrow : rows[i]? = some (id, old))
    : find (rows.set i (id, next)) other
      = if other = id then some next else find rows other := by
  induction rows generalizing i with
  | nil => simp at hrow
  | cons row rows ih =>
      obtain ⟨k, v⟩ := row
      simp only [List.map_cons, List.nodup_cons] at unique
      cases i with
      | zero =>
          have he : k = id ∧ v = old := by simpa using hrow
          obtain ⟨rfl, rfl⟩ := he
          by_cases ho : other = k
          · subst other
            simp [find]
          · simp [find, ho, Ne.symm ho]
      | succ i =>
          have htail : rows[i]? = some (id, old) := hrow
          have hk : k ≠ id := by
            rintro rfl
            exact unique.1 (List.mem_map_of_mem (f := Prod.fst) (List.mem_of_getElem? htail))
          have he := ih i unique.2 htail
          by_cases ho : other = id
          · subst other
            simp [find, hk, he]
          · by_cases hd : k = other <;> simp [find, hd, he, ho]

/-- The phase projection retains the version of an applied attempt. -/
def lifecyclePhase : Spike.engine.Phase → Phase
  | .Active => .active
  | .Committing => .committing
  | .Applied v => .applied v.val
  | .Finished => .finished

/-- Frozen metadata represented natively, independent of the captured model frame's data. -/
def lifecycleSnapshot (snap : Option Spike.engine.Snapshot) : Option (Nat × Nat) :=
  snap.map fun s => (s.version.val, s.term.val)

/-- The outcome projection preserves all three replication outcomes. -/
def lifecycleOutcome : Spike.engine.Outcome → Outcome
  | .Success => .success
  | .Conflict => .conflict
  | .NoReplicate => .noReplicate

/-- The parts of attempt correspondence needed by lifecycle guards. -/
structure LifecycleAttempt (encode : List U8 → String) (history : Spike.engine.History)
    (archive : List Frame) (native : Spike.engine.Tx) (tx : Tx)
    : Prop where
  phase : lifecyclePhase native.phase = tx.phase
  snapshot
    : lifecycleSnapshot native.snapshot
      = tx.snapshot.map fun s => (s.current.version, s.term)
  writes : (pointWrites encode native).Perm tx.normal.writes
  unavailable : native.unavailable = tx.unavailable
  /-- Preserve the complete attempt relation across a lifecycle action. -/
  related : AttemptMatches encode tx.store history archive native tx

/-- Full attempt correspondence supplies the lifecycle guard projections. -/
theorem LifecycleAttempt.ofMatched {encode : List U8 → String} {sid : Nat}
    {history : Spike.engine.History} {archive : List Frame} {n : Spike.engine.Tx} {t : Tx}
    (h : AttemptMatches encode sid history archive n t)
    : LifecycleAttempt encode history archive n t :=
  ⟨h.phase.symm, h.snapshot.symm, h.writes, h.unavailable.symm, h.store ▸ h⟩

/-- A fresh native attempt agrees with the model's default lifecycle fields at any owner. -/
theorem lifecycle_new_attempt (encode : List U8 → String) (sid : Nat)
    (history : Spike.engine.History) (archive : List Frame)
    : LifecycleAttempt encode history archive lifecycleNewTx {store := sid} := by
  apply LifecycleAttempt.ofMatched (sid := sid)
  refine ⟨rfl, rfl, rfl, .nil, ?_, ?_, ?_, ?_, ?_, ?_, ?_, rfl, .rfl, List.Pairwise.nil, .nil, ?_, ?_⟩
  · intro _ h; cases h
  · intro _ h; cases h
  · intro _ h; cases h
  · intro _; rfl
  · intro _; exact List.Pairwise.nil
  · intro _ h; cases h
  · intro _; rfl
  · intro _ h; cases h
  · intro _ h; cases h

/-- `CommitResult` uses exactly the model's phase, outcome, and pending-write guard. -/
theorem lifecycle_commit_version_matches_model (encode : List U8 → String)
    (t : Spike.engine.Tx) (tx : Tx) (outcome : Spike.engine.Outcome)
    {history : Spike.engine.History} {archive : List Frame}
    (h : LifecycleAttempt encode history archive t tx)
    : (lifecycleCommitVersion t outcome).map (fun v => v.val)
      = match tx.phase with
        | .applied v => if lifecycleOutcome outcome == .conflict then none else some v
        | .committing =>
            if lifecycleOutcome outcome == .success
                && (!tx.normal.writes.isEmpty || tx.unavailable) then
              none
            else
              some 0
        | _ => none := by
  have hw : tx.normal.writes = [] ↔ t.pending.val = [] := by
    have hlen : tx.normal.writes.length = t.pending.val.length := by
      have hp := h.writes.length_eq.symm
      simpa [pointWrites, encodeWrites, byteWrites] using hp
    exact ⟨fun h0 => List.eq_nil_of_length_eq_zero (by rw [← hlen, h0]; rfl),
      fun h0 => List.eq_nil_of_length_eq_zero (by rw [hlen, h0]; rfl)⟩
  have hsuccess (o : Outcome) : (o == .success) = decide (o = .success) := by
    cases o <;> rfl
  have hconflict (o : Outcome) : (o == .conflict) = decide (o = .conflict) := by
    cases o <;> rfl
  rw [← h.phase, ← h.unavailable]
  cases hp : t.phase <;> cases outcome <;>
    simp [lifecyclePhase, lifecycleOutcome, lifecycleCommitVersion, hp, hsuccess, hconflict]
  by_cases he : t.pending.val = []
  · have hm := hw.mpr he
    cases hu : t.unavailable <;> simp_all
  · have hm := mt hw.mp he
    cases hu : t.unavailable <;> simp_all

/-- Project just the outputs of lifecycle actions. -/
def lifecycleOutput
    : core.result.Result Spike.engine.Output Spike.engine.Error → Option Output
  | .Ok .Unit => some .unit
  | .Ok (.Snapshot v g term) => some (.snapshot v.val g.val term.val)
  | .Ok (.Committed outcome v) => some (.committed (lifecycleOutcome outcome) v.val)
  | _ => none

/-- Model rejection means an exact native no-op; success agrees on output and state updates. -/
def LifecycleModelPost (s : Spike.engine.Store) (step : Option (State × Output))
    (post : State → Spike.engine.Store → Prop)
    (r : core.result.Result Spike.engine.Output Spike.engine.Error × Spike.engine.Store)
    : Prop :=
  match step with
  | none => r = (.Err .Disabled, s)
  | some (after, out) => lifecycleOutput r.1 = some out ∧ post after r.2

/-- For a live store, the duplicate-attempt guard and fresh attempt agree with `execute`. -/
theorem execute_begin_matches_model (encode : List U8 → String) (s : Spike.engine.Store)
    (w : State) (sid : Nat) (id : U64) (model : Store) (archive : List Frame)
    (hStore : find w.stores sid = some model)
    (hExists : (find w.txs id.val).isSome = (find s.txs.val id).isSome)
    (room : find s.txs.val id = none → s.txs.val.length < Usize.max)
    : WP.spec (Spike.engine.Store.execute s (.Begin id))
        (LifecycleModelPost s (execute w (.txCreate sid id.val))
          fun w' s' =>
            w' = {w with txs := Kv.Model.set w.txs id.val {store := sid}}
            ∧ s'.history = s.history
            ∧ s'.txs.val = Kv.Model.set s.txs.val id lifecycleNewTx
            ∧ LifecycleAttempt encode s.history archive lifecycleNewTx
                {store := sid}) := by
  apply WP.spec_mono (execute_begin_lifecycle s id room)
  rintro ⟨out, after⟩ h
  cases ht : find s.txs.val id with
  | none =>
      simp only [ht] at h
      obtain ⟨rfl, hh, hr⟩ := h
      simp [execute, hStore, hExists, ht, LifecycleModelPost, lifecycleOutput, hh, hr,
        lifecycle_new_attempt encode sid s.history archive]
  | some t =>
      simpa [execute, hStore, hExists, ht, LifecycleModelPost] using h

/-- The owned-attempt lookup and native lookup give the same `End` guard and exact erasure. -/
theorem execute_end_matches_model (s : Spike.engine.Store) (w : State) (sid : Nat)
    (id : U64) (hExists : (lookupTx w sid id.val).isSome = (find s.txs.val id).isSome)
    : WP.spec (Spike.engine.Store.execute s (.End id))
        (LifecycleModelPost s (execute w (.txEnd sid id.val))
          fun w' s' =>
            w' = {w with txs := erase w.txs id.val}
            ∧ s'.history = s.history
            ∧ s'.txs.val = erase s.txs.val id) := by
  apply WP.spec_mono (execute_end_lifecycle s id)
  rintro ⟨out, after⟩ h
  cases hm : lookupTx w sid id.val <;> cases ht : find s.txs.val id <;>
    simp only [hm, ht, Option.isSome_none, Option.isSome_some] at hExists
  · simpa [execute, hm, ht, LifecycleModelPost] using h
  · cases hExists
  · cases hExists
  · simp only [ht] at h
    obtain ⟨rfl, hh, hr⟩ := h
    simp [execute, hm, LifecycleModelPost, lifecycleOutput, hh, hr]

/-- `SetTerm` compares the same natural-number terms as the model, preserving other fields. -/
theorem execute_set_term_matches_model (s : Spike.engine.Store) (w : State) (sid : Nat)
    (term : U64) (model : Store) (hStore : find w.stores sid = some model)
    (hTerm : model.term = s.history.term.val)
    : WP.spec (Spike.engine.Store.execute s (.SetTerm term))
        (LifecycleModelPost s (execute w (.setTerm sid term.val))
          fun w' s' =>
            w'
              = {w with stores := Kv.Model.set w.stores sid {model with term := term.val}}
            ∧ s' = {s with history := {s.history with term}}) := by
  apply WP.spec_mono (execute_set_term_lifecycle s term)
  intro r h
  by_cases hlt : term.val < s.history.term.val
  · simpa [execute, hStore, hTerm, hlt, LifecycleModelPost] using h
  · simp only [hlt, ite_false] at h
    subst r
    simp [execute, hStore, hTerm, hlt, LifecycleModelPost, lifecycleOutput]

/-- The exact model row replacement and native in-place update for a matched attempt. -/
def LifecycleModelRow (encode : List U8 → String) (s : Spike.engine.Store) (w : State)
    (sid : Nat) (id : U64) (archive : List Frame) (w' : State) (s' : Spike.engine.Store)
    : Prop :=
  ∃ old next nextModel,
    find s.txs.val id = some old
    ∧ w' = {w with txs := Kv.Model.set w.txs id.val nextModel}
    ∧ LifecycleRowUpdate s s' id old next
    ∧ AttemptMatches encode sid s.history archive next nextModel

private theorem match_attempt_step (encode : List U8 → String)
    (s : Spike.engine.Store) (w : State) (sid : Nat) (id : U64) (archive : List Frame)
    (action : Spike.engine.Action) (modelAction : Action)
    (nativeStep : Spike.engine.Tx → Option (Spike.engine.Output × Spike.engine.Tx))
    (modelStep : Store → Tx → Option (Output × Tx))
    (related : Spike.engine.Tx → Store → Tx → Prop)
    (lookup
      : Option.Rel (fun t (store, tx) => related t store tx)
          (find s.txs.val id) (lookupTx w sid id.val))
    (step
      : ∀ t store tx,
          related t store tx
          → Option.Rel
              (fun n m =>
                lifecycleOutput (.Ok n.1) = some m.1
                ∧ LifecycleAttempt encode s.history archive n.2 m.2)
              (nativeStep t) (modelStep store tx))
    (owner
      : ∀ store tx out next,
          modelStep store tx = some (out, next) → next.store = tx.store)
    (hModel
      : execute w modelAction
        = (lookupTx w sid id.val).bind
            fun (store, tx) =>
              (modelStep store tx).map
                fun (out, next) =>
                  ({w with txs := Kv.Model.set w.txs id.val next}, out))
    (hNative
      : WP.spec (Spike.engine.Store.execute s action) (LifecycleTxPost s id nativeStep))
    : WP.spec (Spike.engine.Store.execute s action)
        (LifecycleModelPost s (execute w modelAction)
          (LifecycleModelRow encode s w sid id archive)) := by
  apply WP.spec_mono hNative
  intro r hr
  rw [hModel]
  cases hn : find s.txs.val id <;> cases hm : lookupTx w sid id.val
  · simpa [LifecycleTxPost, LifecycleModelPost, hn] using hr
  · rw [hn, hm] at lookup
    cases lookup
  · rw [hn, hm] at lookup
    cases lookup
  · rename_i t pair
    obtain ⟨store, tx⟩ := pair
    simp only [hn, hm, Option.rel_some_some] at lookup
    have hh := step t store tx lookup
    cases hs : nativeStep t <;> cases ht : modelStep store tx
    · simpa [LifecycleTxPost, LifecycleModelPost, hn, hs, ht] using hr
    · rw [hs, ht] at hh
      cases hh
    · rw [hs, ht] at hh
      cases hh
    · rename_i native model
      obtain ⟨out, next⟩ := native
      obtain ⟨obs, nextModel⟩ := model
      simp only [hs, ht, Option.rel_some_some] at hh
      have hpost
          : r.1 = .Ok out ∧ ∃ old, some t = some old ∧ LifecycleRowUpdate s r.2 id old next := by
        simpa only [LifecycleTxPost, hn, Option.bind_some, hs] using hr
      obtain ⟨hout, old, he, hrow⟩ := hpost
      cases he
      simp only [Option.bind_some, ht, Option.map_some, LifecycleModelPost, hout]
      have ho : nextModel.store = sid := (owner _ _ _ _ ht).trans (lookup_owner hm)
      have rel := hh.2.related
      rw [ho] at rel
      exact ⟨hh.1, t, next, nextModel, hn, rfl, hrow, rel⟩

private theorem phase_not_active (p : Phase) : (p != .active) = decide (p ≠ .active) := by
  cases p <;> rfl

private theorem lifecycle_option_bind_some {α β : Type} (a : α) (f : α → Option β)
    : (some a >>= f) = f a :=
  rfl

/-- On related lookups, `CommitBegin` agrees with the model without assuming either guard. -/
theorem execute_commit_begin_matches_model (encode : List U8 → String)
    (s : Spike.engine.Store) (w : State) (sid : Nat) (id : U64) (archive : List Frame)
    (lookup
      : Option.Rel (fun t (_, tx) => LifecycleAttempt encode s.history archive t tx)
          (find s.txs.val id) (lookupTx w sid id.val))
    : WP.spec (Spike.engine.Store.execute s (.CommitBegin id))
        (LifecycleModelPost s (execute w (.commitBegin sid id.val))
          (LifecycleModelRow encode s w sid id archive)) := by
  let nStep (t : Spike.engine.Tx) : Option (Spike.engine.Output × Spike.engine.Tx) :=
    match t.phase with
    | .Active => some (.Unit, {t with phase := .Committing})
    | _ => none
  let mStep (_ : Store) (tx : Tx) : Option (Output × Tx) :=
    if tx.phase != .active then none else some (.unit, {tx with phase := .committing})
  refine match_attempt_step encode s w sid id archive _ _ nStep mStep
    (fun t _ tx => LifecycleAttempt encode s.history archive t tx) lookup ?_ ?_ ?_
    (execute_commit_begin_lifecycle s id)
  · intro t _ tx h
    dsimp only [nStep, mStep]
    rw [phase_not_active, ← h.phase]
    cases t.phase <;> simp [lifecyclePhase]
    exact ⟨rfl, LifecycleAttempt.ofMatched (h.related.withPhase .Committing)⟩
  · intro store tx out next he
    unfold mStep at he
    split at he <;> simp_all
    rw [← he.2]
  · cases hh : lookupTx w sid id.val with
    | none => simp [execute, hh]
    | some pair =>
        obtain ⟨store, tx⟩ := pair
        simp only [execute, hh, lifecycle_option_bind_some, Option.bind_some, mStep]
        split <;> rfl

/-- On related lookups, `Snapshot` agrees with the model's fresh-active guard and frozen fields. -/
theorem execute_snapshot_matches_model (encode : List U8 → String)
    (s : Spike.engine.Store) (w : State) (sid : Nat) (id : U64) (archive : List Frame)
    (prior : List Spike.engine.Frame) (head : Spike.engine.Frame)
    (hframes : s.history.activeFrames = prior ++ [head])
    (valid : BranchValid s.history.log)
    (lookup
      : Option.Rel
          (fun t (model, tx) =>
            LifecycleAttempt encode s.history archive t tx
            ∧ model.head.version = head.version.val
            ∧ model.global = s.history.global.val
            ∧ model.term = s.history.term.val)
          (find s.txs.val id) (lookupTx w sid id.val))
    : WP.spec (Spike.engine.Store.execute s (.Snapshot id))
        (LifecycleModelPost s (execute w (.snapshot sid id.val))
          (LifecycleModelRow encode s w sid id archive)) := by
  let nStep (t : Spike.engine.Tx) : Option (Spike.engine.Output × Spike.engine.Tx) :=
    match t.phase, t.snapshot with
    | .Active, none =>
        some (.Snapshot head.version s.history.global s.history.term,
          {t with snapshot := some {version := head.version, term := s.history.term}})
    | _, _ => none
  let mStep (store : Store) (tx : Tx) : Option (Output × Tx) :=
    if tx.phase != .active || tx.snapshot.isSome then none
    else some (.snapshot store.head.version store.global store.term,
      {tx with snapshot := some {current := store.head, term := store.term}})
  refine match_attempt_step encode s w sid id archive _ _ nStep mStep
    (fun t model tx => LifecycleAttempt encode s.history archive t tx
      ∧ model.head.version = head.version.val
      ∧ model.global = s.history.global.val ∧ model.term = s.history.term.val)
    lookup ?_ ?_ ?_ (execute_snapshot_lifecycle s id prior head hframes valid)
  · intro t store tx ⟨h, hvs, hg, ht⟩
    dsimp only [nStep, mStep]
    rw [phase_not_active, ← h.phase]
    have hsome : tx.snapshot.isSome = t.snapshot.isSome := by
      have hs := congrArg Option.isSome h.snapshot
      simpa [lifecycleSnapshot] using hs.symm
    rw [hsome]
    cases hp : t.phase <;> cases t.snapshot <;> simp [lifecyclePhase]
    have hactive : tx.phase = .active := by simpa [lifecyclePhase, hp] using h.phase.symm
    exact ⟨by simp [lifecycleOutput, hvs, hg, ht],
      LifecycleAttempt.ofMatched (by
        simpa only [hp, hactive] using h.related.withSnapshot
          {version := head.version, term := s.history.term} {current := store.head, term := store.term}
          (by simp [snapshotCut, modelSnapshot, hvs, ht]))⟩
  · intro store tx out next he
    unfold mStep at he
    split at he <;> simp_all
    rw [← he.2]
  · cases hh : lookupTx w sid id.val with
    | none => simp [execute, hh]
    | some pair =>
        obtain ⟨store, tx⟩ := pair
        simp only [execute, hh, lifecycle_option_bind_some, Option.bind_some, mStep]
        split <;> rfl

/-- On related lookups, all `CommitResult` guards, versions and updates match `execute`. -/
theorem execute_commit_result_matches_model (encode : List U8 → String)
    (s : Spike.engine.Store) (w : State) (sid : Nat) (id : U64) (archive : List Frame)
    (outcome : Spike.engine.Outcome)
    (lookup
      : Option.Rel (fun t (_, tx) => LifecycleAttempt encode s.history archive t tx)
          (find s.txs.val id) (lookupTx w sid id.val))
    : WP.spec (Spike.engine.Store.execute s (.CommitResult id outcome))
        (LifecycleModelPost s
          (execute w (.commitResult sid id.val (lifecycleOutcome outcome)))
          (LifecycleModelRow encode s w sid id archive)) := by
  let nStep (t : Spike.engine.Tx) : Option (Spike.engine.Output × Spike.engine.Tx) :=
    (lifecycleCommitVersion t outcome).map fun v =>
      (.Committed outcome v, {t with phase := .Finished})
  let version (tx : Tx) : Option Nat :=
    match tx.phase with
    | .applied v => if lifecycleOutcome outcome == .conflict then none else some v
    | .committing =>
        if lifecycleOutcome outcome == .success && (!tx.normal.writes.isEmpty || tx.unavailable)
          then none else some 0
    | _ => none
  let mStep (_ : Store) (tx : Tx) : Option (Output × Tx) :=
    (version tx).map fun v => (.committed (lifecycleOutcome outcome) v, {tx with phase := .finished})
  refine match_attempt_step encode s w sid id archive _ _ nStep mStep
    (fun t _ tx => LifecycleAttempt encode s.history archive t tx) lookup ?_ ?_ ?_
    (execute_commit_result_lifecycle s id outcome)
  · intro t _ tx h
    have hv : (lifecycleCommitVersion t outcome).map (fun v => v.val) = version tx :=
      lifecycle_commit_version_matches_model encode t tx outcome h
    dsimp only [nStep, mStep]
    rw [← hv]
    cases lifecycleCommitVersion t outcome <;> simp
    exact ⟨rfl, LifecycleAttempt.ofMatched (h.related.withPhase .Finished)⟩
  · intro store tx out next he
    unfold mStep at he
    cases h : version tx <;> simp_all
    rw [← he.2]
  · cases hh : lookupTx w sid id.val with
    | none => simp [execute, hh]
    | some pair =>
        obtain ⟨store, tx⟩ := pair
        simp only [execute, hh, lifecycle_option_bind_some, Option.bind_some, mStep, version]
        cases tx.phase
        · rfl
        · by_cases h : (lifecycleOutcome outcome == .success
              && (!tx.normal.writes.isEmpty || tx.unavailable)) = true <;>
            simp [h]
        · by_cases h : (lifecycleOutcome outcome == .conflict) = true <;>
            simp [h]
        · rfl

end KvRust
