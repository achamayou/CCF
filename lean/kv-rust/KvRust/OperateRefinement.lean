-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Split native operations into the point and map-wide proof cases. -/
inductive OperationCase where
  | point (op : PointOperation)
  | whole (op : ScanOperation)

/-- Classify every extracted operation. -/
def operationCase : Spike.engine.Operation → OperationCase
  | .Get k g => .point (.get k g)
  | .Has k g => .point (.has k g)
  | .Previous k => .point (.previous k)
  | .Write k v => .point (.write k v)
  | .Scan => .whole .scan
  | .Size => .whole .size
  | .Clear => .whole .clear
  | .Range l u => .whole (.range l u)

/-- Recover the original native input. -/
def OperationCase.rust : OperationCase → Spike.engine.Operation
  | .point op => op.rust
  | .whole op => op.rust

/-- Translate the input for the reference transition system. -/
def OperationCase.model (encode : List U8 → String) (m : Spike.engine.Bytes)
    : OperationCase → Operation
  | .point op => op.model encode m
  | .whole op => op.model encode (encode (alloc.vec.Vec.val m))

/-- Resource bounds for the containers this operation can grow. -/
def OperationCase.fits (encode : List U8 → String) (n : Spike.engine.Tx)
    (tx : Tx) (m : Spike.engine.Bytes)
    : OperationCase → Prop
  | .point op => op.fits encode n m
  | .whole op =>
      let key := encode (alloc.vec.Vec.val m)
      n.deps.val.length < Usize.max
      ∧ (image tx.data key).length + n.pending.val.length ≤ Usize.max
      ∧ (op = .clear
          → n.pending.val.length + (scanAt tx.data tx.normal.writes key).length
            ≤ Usize.max)

/-- Capacity of an enabled operation, given both live attempt rows. -/
def OperationCase.indexRoom (history : Spike.engine.History) (m : Spike.engine.Bytes)
    : OperationCase → Prop
  | .point op => op.indexRoom m
  | .whole _ => HistoryScanRoom history

def FitsOperate (encode : List U8 → String) (sid : Nat) (n : Spike.engine.Store)
    (w : State) (id : U64) (m : Spike.engine.Bytes) (op : OperationCase)
    : Prop :=
  ∀ t store tx,
    find n.txs.val id = some t
    → lookupTx w sid id.val = some (store, tx)
    → op.fits encode t tx m ∧ op.indexRoom n.history m

private theorem op_map (encode : List U8 → String) (m : Spike.engine.Bytes)
    (op : OperationCase)
    : (op.model encode m).map = encode (alloc.vec.Vec.val m) := by
  cases op with
  | point op => cases op <;> rfl
  | whole op => cases op <;> rfl

private def logValid (t : Tx) : Prop :=
  ∀ op ∈ t.normal.log, (find t.globalViews op.map).isSome

private def modelKeeps (t next : Tx) : Prop :=
  {next with normal := t.normal} = t ∧ logValid next

private theorem kept_trans {a b c : Tx} (ab : modelKeeps a b) (bc : modelKeeps b c)
    : modelKeeps a c := by
  refine ⟨?_, bc.2⟩
  exact (congrArg (fun s : Tx => {s with normal := a.normal}) bc.1).trans ab.1

private theorem record_keeps (t : Tx) (op : NormalOp String String String)
    (hl : logValid t) (hm : (find t.globalViews op.map).isSome)
    : modelKeeps t {t with normal := recordOp t.data t.normal op} := by
  refine ⟨rfl, ?_⟩
  intro entry he
  change entry ∈ t.normal.log ++ [op] at he
  rcases List.mem_append.mp he with ho | hn
  · exact hl entry ho
  · have heq := List.mem_singleton.mp hn
    subst entry
    exact hm

private theorem clear_keeps (t : Tx) (m : String) (entries : Assoc String String)
    (hl : logValid t) (hm : (find t.globalViews m).isSome)
    : modelKeeps t
        (entries.foldl
          (fun (acc : Tx) (k, _) =>
            {acc with normal := recordOp acc.data acc.normal (.write (m, k) none)})
          t) := by
  induction entries generalizing t with
  | nil => exact ⟨rfl, hl⟩
  | cons row rest ih =>
      obtain ⟨key, value⟩ := row
      have h := record_keeps t (.write (m, key) none) hl hm
      exact kept_trans h (ih _ h.2 hm)

private theorem operation_keeps (t : Tx) (op : Operation)
    (hl : logValid t) (hm : (find t.globalViews op.map).isSome)
    : modelKeeps t (executeOperation t op).1 := by
  cases op with
  | get m key g =>
      cases g
      · exact record_keeps _ _ hl hm
      · exact ⟨rfl, hl⟩
  | has m key g =>
      cases g
      · exact record_keeps _ _ hl hm
      · exact ⟨rfl, hl⟩
  | previous m key => exact record_keeps _ _ hl hm
  | write m key value => exact record_keeps _ _ hl hm
  | scan m => exact record_keeps _ _ hl hm
  | size m => exact record_keeps _ _ hl hm
  | clear m =>
      have h := record_keeps t (.scan m (scanAt t.data t.normal.writes m)) hl hm
      exact kept_trans h (clear_keeps _ m _ h.2 hm)
  | range m lower upper =>
      unfold executeOperation
      by_cases he : emptyRange lower upper
      · simp only [he, ite_true]
        exact ⟨rfl, hl⟩
      · simp only [he]
        exact record_keeps _ _ hl hm

private theorem related_operated (encode : List U8 → String) (sid : Nat)
    (history : Spike.engine.History) (archive : List Frame)
    (native after : Spike.engine.Tx) (tx : Tx) (op : Operation)
    (bef : AttemptMatches encode sid history archive native tx)
    (hm : (find tx.globalViews op.map).isSome)
    (hw : (pointWrites encode after).Perm (executeOperation tx op).1.normal.writes)
    (hso : PendingSorted after.pending.val)
    (hd
      : List.Forall₂ DependencyOrderEq (pointDeps encode after)
          (executeOperation tx op).1.normal.deps)
    (hno : NativeDepsFromViews encode history after)
    (hmo : ModelDepsFromViews (executeOperation tx op).1)
    (hc : pointKeepsContext native after)
    : AttemptMatches encode sid history archive after (executeOperation tx op).1 := by
  obtain ⟨hModel, hLog⟩ := operation_keeps tx op bef.log hm
  have hStore := congrArg Tx.store hModel
  have hSnap := congrArg Tx.snapshot hModel
  have hPhase := congrArg Tx.phase hModel
  have hView := congrArg Tx.globalViews hModel
  have hData := congrArg Tx.data hModel
  have hUn := congrArg Tx.unavailable hModel
  have hns := congrArg Spike.engine.Tx.snapshot hc
  have hnp := congrArg Spike.engine.Tx.phase hc
  have hnv := congrArg Spike.engine.Tx.views hc
  have hnu := congrArg Spike.engine.Tx.unavailable hc
  change after.snapshot = native.snapshot at hns
  change after.phase = native.phase at hnp
  change after.views = native.views at hnv
  change after.unavailable = native.unavailable at hnu
  change (executeOperation tx op).1.store = tx.store at hStore
  change (executeOperation tx op).1.snapshot = tx.snapshot at hSnap
  change (executeOperation tx op).1.phase = tx.phase at hPhase
  change (executeOperation tx op).1.globalViews = tx.globalViews at hView
  change (executeOperation tx op).1.data = tx.data at hData
  change (executeOperation tx op).1.unavailable = tx.unavailable at hUn
  refine ⟨hStore.trans bef.store, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, hLog, ?_, ?_, hw, hso, hd,
    hno, hmo⟩
  · rw [hSnap, hns]; exact bef.snapshot
  · rw [hPhase, hnp]; exact bef.phase
  · rw [hView, hnv]; exact bef.views
  · rw [hnv]; exact bef.live
  · rw [hnv]; exact bef.nativeOrig
  · rw [hView]; exact bef.modelViewsIn
  · rw [hData, hView]; exact bef.data
  · rw [hData]; exact bef.dataUnique
  · rw [hns, hnv]; exact bef.noSnapshot
  · rw [hUn, hnu]; exact bef.unavailable

private def operationOutput (encode : List U8 → String)
    (r : core.result.Result Spike.engine.Output Spike.engine.Error)
    : OperationCase → Option Output
  | .point _ => pointOutput encode r
  | .whole _ => scanOutput encode r

private theorem output_projection (encode : List U8 → String) (op : OperationCase)
    (r : core.result.Result Spike.engine.Output Spike.engine.Error) (obs : Output)
    (h : operationOutput encode r op = some obs)
    : ∃ v, r = .Ok v ∧ modelOutput encode v = obs := by
  cases op
  <;> cases r with
  | Err e => cases h
  | Ok v =>
      refine ⟨v, rfl, ?_⟩
      cases v <;> cases h <;> rfl

private theorem find_mem_of_some {K V : Type} [DecidableEq K] {rows : Assoc K V} {k : K}
    {v : V} (h : find rows k = some v)
    : (k, v) ∈ rows := by
  induction rows with
  | nil => simp [find] at h
  | cons row rest ih =>
      obtain ⟨rk, rv⟩ := row
      by_cases he : rk = k
      · subst rk
        simp [find] at h
        subst rv
        exact List.mem_cons_self
      · simp [find, he] at h
        exact List.mem_cons_of_mem _ (ih h)

private theorem operate_enabled (encode : List U8 → String)
    (inj : Function.Injective encode) (order : PreservesByteOrder encode) (sid : Nat)
    (history : Spike.engine.History) (archive : List Frame) (t : Spike.engine.Tx)
    (tx : Tx) (m : Spike.engine.Bytes) (op : OperationCase)
    (h : AttemptMatches encode sid history archive t tx) (hp : t.phase = .Active)
    (v : GlobalView) (hv : find tx.globalViews (encode (alloc.vec.Vec.val m)) = some v)
    (hArchUnique : ∀ f ∈ archive, Kv.Properties.Unique f.data)
    (room : op.fits encode t tx m) (indexed : HistoryIndexValid history)
    (space : op.indexRoom history m)
    : WP.spec (Spike.engine.Tx.operate t history m op.rust)
        (fun (out, next) =>
          ∃ value,
            out = .Ok value
            ∧ OutputMatches (.operation sid 0 (op.model encode m))
                (modelOutput encode value) (executeOperation tx (op.model encode m)).2
            ∧ AttemptMatches encode sid history archive next
                (executeOperation tx (op.model encode m)).1) := by
  have hFor : (find tx.globalViews (op.model encode m).map).isSome := by rw [op_map, hv]; rfl
  have finish (r : core.result.Result Spike.engine.Output Spike.engine.Error) (after : Spike.engine.Tx)
      (obs : Output) (ho : operationOutput encode r op = some obs)
      (hm : OutputMatches (.operation sid 0 (op.model encode m)) obs
        (executeOperation tx (op.model encode m)).2)
      (hw : (pointWrites encode after).Perm (executeOperation tx (op.model encode m)).1.normal.writes)
      (hso : PendingSorted after.pending.val)
      (hd : List.Forall₂ DependencyOrderEq (pointDeps encode after)
        (executeOperation tx (op.model encode m)).1.normal.deps)
      (hno : NativeDepsFromViews encode history after)
      (hmo : ModelDepsFromViews (executeOperation tx (op.model encode m)).1)
      (hc : pointKeepsContext t after) :
      ∃ value, r = .Ok value
        ∧ OutputMatches (.operation sid 0 (op.model encode m)) (modelOutput encode value)
            (executeOperation tx (op.model encode m)).2
        ∧ AttemptMatches encode sid history archive after (executeOperation tx (op.model encode m)).1 := by
    obtain ⟨value, hr, he⟩ := output_projection encode op r _ ho
    exact ⟨value, hr, he.symm ▸ hm,
      related_operated encode sid history archive t after tx (op.model encode m) h hFor hw hso hd
        hno hmo hc⟩
  cases op with
  | point op =>
      have hGlobalUnique : Kv.Properties.Unique (image v.frame.data (encode m.val)) :=
        unique_image v.frame.data _ (hArchUnique v.frame (h.modelViewsIn _ (find_mem_of_some hv)).2)
      apply WP.spec_mono
        (operate_point_matches_model encode inj history t tx m op v hp hv h.views
          (h.localImage hv) (h.dataUnique _) hGlobalUnique h.writes h.sorted h.deps
          h.nativeDeps h.modelDeps room h.live indexed space)
      rintro ⟨out, next⟩ ⟨ho, hw, hd, hc, hso, hno, hmo⟩
      exact finish out next _ ho (OutputMatches.of_eq rfl) hw hso hd hno hmo hc
  | whole op =>
      obtain ⟨room, rows, clear⟩ := room
      apply WP.spec_mono
        (operate_scan_matches_model encode inj order history t tx m op v hp hv h.views
          (h.localImage hv) h.writes h.sorted h.deps h.nativeDeps h.modelDeps room rows
          (h.dataUnique _) clear h.live indexed space)
      rintro ⟨out, next⟩ ⟨⟨obs, ho, hmatch⟩, hw, hd, hc, hso, hno, hmo⟩
      have hmatch' : OutputMatches (.operation sid 0 (op.model encode (encode m.val))) obs
          (executeOperation tx (op.model encode (encode m.val))).2 := by
        cases op <;> cases obs <;> exact hmatch
      exact finish out next obs ho hmatch' hw hso hd hno hmo hc

/-- Disabled handle operations reject without changing the attempt. -/
theorem operate_disabled (encode : List U8 → String)
    (inj : Function.Injective encode) (history : Spike.engine.History)
    (t : Spike.engine.Tx) (m : Spike.engine.Bytes)
    (op : Spike.engine.Operation)
    (bad
      : t.phase ≠ .Active
        ∨ find (rustPinnedViews encode history t.views) (encode (alloc.vec.Vec.val m))
          = none)
    (live : ViewsLive history t.views)
    : WP.spec (Spike.engine.Tx.operate t history m op)
        (fun r => r = (.Err .Disabled, t)) := by
  cases hp : t.phase with
  | Committing =>
      have hr : {t with phase := .Committing} = t := by rw [← hp]
      simp [Spike.engine.Tx.operate, hp, hr]
  | Applied ver =>
      have hr : {t with phase := .Applied ver} = t := by rw [← hp]
      simp [Spike.engine.Tx.operate, hp, hr]
  | Finished =>
      have hr : {t with phase := .Finished} = t := by rw [← hp]
      simp [Spike.engine.Tx.operate, hp, hr]
  | Active =>
      have hf := bad.resolve_left (by simp [hp])
      have hr : {t with phase := .Active} = t := by rw [← hp]
      simp only [Spike.engine.Tx.operate, hp, bind_ok]
      apply WP.spec_bind (view_lookup encode inj history t m live)
      intro found ⟨he, _⟩
      rw [hf] at he
      cases found
      · simp [hr]
      · cases he

/-- The `Operate` dispatcher agrees on all eight operations, including rejection without mutation. -/
theorem operate_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (order : PreservesByteOrder encode) (sid : Nat) (n : Spike.engine.Store) (w : State)
    (id : U64) (m : Spike.engine.Bytes) (op : OperationCase)
    (h : StateMatches encode sid n w) (room : FitsOperate encode sid n w id m op)
    : WP.spec (Spike.engine.Store.execute n (.Operate id m op.rust))
        (StepMatches encode sid (.operation sid id.val (op.model encode m)) n
          (execute w (.operation sid id.val (op.model encode m)))) := by
  obtain ⟨store, archive, hStore, hist, hattempts⟩ := h.history
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (tx_index n id)
  intro found hf
  cases found with
  | Err e =>
      obtain ⟨rfl, hm⟩ := hf
      have hMissing : lookupTx w sid id.val = none := by
        simp [lookupTx, hStore, lookup_missing_of_attempts hattempts hm]
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, StepMatches, execute, hMissing]
  | Ok i =>
      obtain ⟨t, hrow, hfind⟩ := hf
      obtain ⟨tx, hLookup, rel⟩ := lookup_of_attempts hStore hattempts hfind
      obtain ⟨hi, hget⟩ := List.getElem?_eq_some_iff.mp hrow
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec n.txs i hi)
      rintro ⟨row, back⟩ hback
      have he : row = (id, t) := hback.1.trans hget
      subst row
      change WP.spec (do
        let (out, next) ← Spike.engine.Tx.operate t n.history m op.rust
        Result.ok (out, {n with txs := back (id, next)})) _
      let k := encode (alloc.vec.Vec.val m)
      let modelAction := Action.operation sid id.val (op.model encode m)
      have modelMap : (op.model encode m).map = k := op_map encode m op
      have hupdate (next : Spike.engine.Tx)
          : (back (id, next)).val = n.txs.val.set i.val (id, next) := by
        rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _
      have reject
          (bad : t.phase ≠ .Active ∨ find (rustPinnedViews encode n.history t.views) k = none)
          (disabled : execute w modelAction = none)
          : WP.spec
              (do
                let (out, next) ← Spike.engine.Tx.operate t n.history m op.rust
                Result.ok (out, {n with txs := back (id, next)}))
              (StepMatches encode sid modelAction n (execute w modelAction)) := by
        apply WP.spec_bind
          (operate_disabled encode inj n.history t m op.rust bad rel.live)
        intro result hr
        subst result
        have hv : back (id, t) = n.txs := by
          apply alloc.vec.Vec.ext
          rw [hupdate t, ← hget]
          exact List.set_getElem_self hi
        simp [WP.spec_ok, hv, disabled, StepMatches]
      by_cases hp : t.phase = .Active
      · cases hview : find tx.globalViews k with
        | none =>
            have hNatNone : find (rustPinnedViews encode n.history t.views) k = none := by
              have hrel := rel.views.find k
              rw [projected_view_missing _ _ hview] at hrel
              cases hn' : find (rustPinnedViews encode n.history t.views) k with
              | none => rfl
              | some _ => rw [hn'] at hrel; cases hrel
            apply reject (.inr hNatNone)
            simp [modelAction, execute, hLookup, modelMap, hview]
        | some v =>
            have hSnap : tx.snapshot.isSome := by
              cases hs : tx.snapshot with
              | some snap => rfl
              | none =>
                  have hMeta := rel.snapshot
                  rw [hs] at hMeta
                  cases hn : t.snapshot with
                  | some snap => simp [hn] at hMeta
                  | none =>
                      have hMissing := rel.noSnapshot hn
                      have hProjected := rel.views.find k
                      unfold rustPinnedViews at hProjected
                      rw [hMissing, lookup_model_view _ _ _ hview] at hProjected
                      cases hProjected
            have modelActive : tx.phase = .active := by rw [rel.phase, hp]; rfl
            let ref := executeOperation tx (op.model encode m)
            let w' := {w with txs := Kv.Model.set w.txs id.val ref.1}
            have hw : execute w modelAction = some (w', ref.2) := by
              cases hs : tx.snapshot with
              | none => simp [hs] at hSnap
              | some snap =>
                  have he : (Phase.active != Phase.active) = false := rfl
                  simp [modelAction, execute, hLookup, modelActive, modelMap, hview, hs, he, w', ref]
            apply WP.spec_bind
              (operate_enabled encode inj order sid n.history archive t tx m op rel hp v
                hview hist.modelArchive.unique (room t store tx hfind hLookup).1
                hist.indexValid (room t store tx hfind hLookup).2)
            rintro ⟨out, next⟩ ⟨nativeOut, ho, hout, hrel⟩
            have hout'
                : OutputMatches modelAction (modelOutput encode nativeOut) ref.2 := by
              cases op with
              | point pop => cases pop <;> cases nativeOut <;> exact hout
              | whole wop => cases wop <;> cases nativeOut <;> exact hout
            change WP.spec (Result.ok (out, ({n with txs := back (id,next)} : Spike.engine.Store))) _
            rw [WP.spec_ok]
            change StepMatches encode sid modelAction n (execute w modelAction) _
            rw [hw]
            exact ⟨
              nativeOut,
              ho,
              hout',
              replace_attempt h.unique hattempts hist id i.val t next ref.1 hrow
                (hupdate next) rfl hStore hist hrel (reachable_execute h.reachable hw)
                (HistoryKeeps.of_same rfl rfl) (fun _ hm => hm)
            ⟩
      · apply reject (.inl hp)
        have hf : (tx.phase != .active) = true := by
          rw [rel.phase]
          exact model_phase_inactive t.phase hp
        simp [modelAction, execute, hLookup, hf]

end KvRust
