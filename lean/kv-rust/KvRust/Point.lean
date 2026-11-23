-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Acquire

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

local instance : DecidableEq Spike.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

local instance : DecidableEq Spike.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-- Project byte values without conflating a deletion with an empty value. -/
def encodeValue (encode : List U8 → String) (value : Option Spike.engine.Bytes)
    : Option String :=
  value.map (encode ∘ alloc.vec.Vec.val)

/-- Project the extracted write overlay in model order. -/
def pointWrites (encode : List U8 → String) (t : Spike.engine.Tx) : Pending :=
  encodeWrites encode (byteWrites t.pending.val)

/-- Rust appends dependencies while the model prepends them. -/
def pointDeps (encode : List U8 → String) (t : Spike.engine.Tx)
    : List (Dependency String String String) :=
  (t.deps.val.map (encodeDependency encode ∘ byteDependency)).reverse

/-- Encode the two components of a native address. -/
def encAddr (encode : List U8 → String) (a : Spike.engine.Address) : Addr String String :=
  encodeAddr encode (byteAddr a)

/-- Encode a staged put or deletion. -/
def encWrite (encode : List U8 → String) (w : Spike.engine.Write) : Option String :=
  match w with
  | .Put value => encodeValue encode (some value)
  | .Remove => none

private theorem clone_write (w : Spike.engine.Write)
    : Spike.engine.Write.Insts.CoreCloneClone.clone w = .ok w := by
  cases w <;> simp [Spike.engine.Write.Insts.CoreCloneClone.clone, clone_bytes]

/-- Project the ordered write overlay row by row. -/
theorem pending_projection (encode : List U8 → String) (t : Spike.engine.Tx)
    : pointWrites encode t
      = t.pending.val.map fun (a, w) => (encAddr encode a, encWrite encode w) := by
  simp only [pointWrites, encodeWrites, byteWrites, List.map_map, Function.comp_def]
  apply List.map_congr_left
  rintro ⟨a, w⟩ _
  cases w <;> rfl

private theorem pending_lookup (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx) (a : Spike.engine.Address)
    : WP.spec
        (Spike.engine.Assoc.get Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Address.Insts.CoreCloneClone
          Spike.engine.Write.Insts.CoreCloneClone t.pending a)
        (fun result =>
          result.map (encWrite encode)
          = find (pointWrites encode t) (encAddr encode a)) := by
  have hk : Function.Injective (encAddr encode) :=
    (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
  apply WP.spec_mono (assoc_get Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Address.Insts.CoreCloneClone Spike.engine.Write.Insts.CoreCloneClone
    t.pending a (fun b => compare_address b a) clone_write)
  intro result hr
  rw [pending_projection, find_projected _ _ _ _ hk, hr]

private theorem image_key (db : Data) (m k : String)
    : find (image db m) k = find db (m, k) := by
  induction db with
  | nil => rfl
  | cons row db ih =>
      obtain ⟨⟨m', k'⟩, c⟩ := row
      by_cases hm : m' = m
      · subst m'
        simp [image, find] at ih ⊢
        by_cases hk : k' = k <;> simp [hk, ih]
      · simp [image, find, hm] at ih ⊢
        exact ih

private theorem read_cell (encode : List U8 → String) (inj : Function.Injective encode)
    (rows : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Cell))
    (a : Spike.engine.Address) (db : Data)
    (hImage : encodeImage encode (byteImage rows) = image db (encAddr encode a).1)
    : WP.spec
        (Spike.engine.Assoc.get Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone
          rows a.key)
        (fun result =>
          result.map (encodeCell encode ∘ byteCell) = find db (encAddr encode a)) := by
  let keyOf := encode ∘ alloc.vec.Vec.val (α := U8)
  let cellOf := encodeCell encode ∘ byteCell
  have hk : Function.Injective keyOf := inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have himage : rows.val.map (fun (k, c) => (keyOf k, cellOf c)) = image db (encAddr encode a).1 := by
    simpa only [encodeImage, byteImage, List.map_map, Function.comp_def, keyOf, cellOf]
      using hImage
  apply WP.spec_mono (assoc_get Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone
    rows a.key (fun b => key_same b a.key) clone_cell)
  intro result hr
  have he := find_projected rows.val a.key keyOf cellOf hk
  rw [himage, ← hr, image_key] at he
  exact he.symm

private theorem copy_cell_exact (c : Option Spike.engine.Cell)
    : Spike.engine.copy_cell c = .ok c := by
  cases c <;> simp [Spike.engine.copy_cell, clone_cell]

/-- Appending a native dependency prepends its model projection. -/
theorem deps_push (encode : List U8 → String) (t : Spike.engine.Tx)
    (d : Spike.engine.Dependency) (room : t.deps.val.length < Usize.max)
    : WP.spec (alloc.vec.Vec.push t.deps d)
        (fun deps =>
          pointDeps encode {t with deps}
          = encodeDependency encode (byteDependency d) :: pointDeps encode t) := by
  apply WP.spec_mono (alloc.vec.Vec.push_spec t.deps d room)
  intro deps h
  simp [pointDeps, h]

private theorem observe_global (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx) (a : Spike.engine.Address)
    (view : Spike.engine.View) (db : Data)
    (hImage
      : encodeImage encode (byteImage (view.global.getD view.local))
        = image db (encAddr encode a).1)
    : WP.spec (Spike.engine.Tx.observe t.pending t.deps a view true)
        (fun (value, deps) =>
          encodeValue encode value = (find db (encAddr encode a)).map Cell.value
          ∧ deps = t.deps) := by
  simp only [Spike.engine.Tx.observe, ite_true]
  have hGlobal : Spike.engine.View.global_image view = .ok (view.global.getD view.local) := by
    cases h : view.global <;> simp [Spike.engine.View.global_image, h]
  simp only [hGlobal, bind_ok]
  apply WP.spec_bind (read_cell encode inj (view.global.getD view.local) a db hImage)
  intro cell hc
  cases cell <;> simp [Spike.engine.cell_value, ← hc, encodeValue,
    encodeCell, byteCell, Function.comp_def]

private theorem observe_local (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx) (a : Spike.engine.Address)
    (view : Spike.engine.View) (db : Data)
    (hImage : encodeImage encode (byteImage view.local) = image db (encAddr encode a).1)
    (room
      : find (pointWrites encode t) (encAddr encode a) = none
        → t.deps.val.length < Usize.max)
    : WP.spec (Spike.engine.Tx.observe t.pending t.deps a view false)
        (fun (value, deps) =>
          encodeValue encode value = valueAt db (pointWrites encode t) (encAddr encode a)
          ∧ pointDeps encode {t with deps}
            = needs db (pointWrites encode t)
                (.read (encAddr encode a) (encodeValue encode value))
              ++ pointDeps encode t) := by
  simp only [Spike.engine.Tx.observe, Bool.false_eq_true, ite_false]
  apply WP.spec_bind (pending_lookup encode inj t a)
  intro write hw
  cases write with
  | some w => cases w <;> simp [← hw, valueAt, needs, encWrite, encodeValue]
  | none =>
      apply WP.spec_bind (read_cell encode inj view.local a db hImage)
      intro cell hc
      have hroom := room hw.symm
      have hdep (deps : alloc.vec.Vec Spike.engine.Dependency)
          (hd
            : pointDeps encode {t with deps}
              = encodeDependency encode (byteDependency (.Key a cell))
                :: pointDeps encode t)
          : pointDeps encode {t with deps}
            = .key (encAddr encode a) (find db (encAddr encode a))
              :: pointDeps encode t := by
        rw [hd]
        have he
            : (cell.map byteCell).map (encodeCell encode)
              = find db (encAddr encode a) := by
          simpa only [Option.map_map, Function.comp_def] using hc
        simp [encodeDependency, byteDependency, he, encAddr]
      cases cell <;>
        simp only [copy_cell_exact, Spike.engine.cell_value, clone_address, bind_ok] <;>
        apply WP.spec_bind (deps_push encode t _ hroom) <;>
        intro deps hd <;>
        have hh := hdep deps hd <;>
        simp [← hw, valueAt, needs, ← hc, hh, encodeValue, encodeCell, byteCell, Function.comp_def]

/-- Staging a write replaces its model binding and adds at most one entry. -/
theorem stage_write_bounded (encode : List U8 → String) (inj : Function.Injective encode)
    (t : Spike.engine.Tx) (a : Spike.engine.Address) (w : Spike.engine.Write)
    (room : t.pending.val.length < Usize.max)
    : WP.spec
        (Spike.engine.Assoc.set Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Address.Insts.CoreCloneClone
          Spike.engine.Write.Insts.CoreCloneClone t.pending a w)
        (fun pending =>
          pointWrites encode {t with pending}
            = Kv.Model.set (pointWrites encode t) (encAddr encode a) (encWrite encode w)
          ∧ pending.val.length ≤ t.pending.val.length + 1) := by
  have hi : Function.Injective (encAddr encode) :=
    (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
  apply WP.spec_mono (assoc_set Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Address.Insts.CoreCloneClone Spike.engine.Write.Insts.CoreCloneClone
    t.pending a w (fun b => compare_address b a) clone_address clone_write room)
  intro pending h
  constructor
  · simp only [pending_projection]
    rw [h]
    exact (set_projected t.pending.val a w (encAddr encode) (encWrite encode) hi).symm
  · rw [h, Kv.Model.set, List.length_cons]
    exact Nat.succ_le_succ (List.length_filter_le _ _)

/-- Staging a native write replaces its model binding. -/
theorem stage_write (encode : List U8 → String) (inj : Function.Injective encode)
    (t : Spike.engine.Tx) (a : Spike.engine.Address) (w : Spike.engine.Write)
    (room : t.pending.val.length < Usize.max)
    : WP.spec
        (Spike.engine.Assoc.set Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Address.Insts.CoreCloneClone
          Spike.engine.Write.Insts.CoreCloneClone t.pending a w)
        (fun pending =>
          pointWrites encode {t with pending}
          = Kv.Model.set (pointWrites encode t) (encAddr encode a) (encWrite encode w)) :=
  WP.spec_mono (stage_write_bounded encode inj t a w room) (fun _ h => h.1)

/-- Operations on a single key; a `none` write is a staged deletion. -/
inductive PointOperation where
  | get (key : Spike.engine.Bytes) (global : Bool)
  | has (key : Spike.engine.Bytes) (global : Bool)
  | previous (key : Spike.engine.Bytes)
  | write (key : Spike.engine.Bytes) (value : Option Spike.engine.Bytes)

/-- Embed a point operation into the extracted operation type. -/
def PointOperation.rust : PointOperation → Spike.engine.Operation
  | .get key global => .Get key global
  | .has key global => .Has key global
  | .previous key => .Previous key
  | .write key value => .Write key value

/-- Encode the map, key, and optional value for the reference model. -/
def PointOperation.model (encode : List U8 → String) (m : Spike.engine.Bytes)
    : PointOperation → Operation
  | .get key global => .get (encode m.val) (encode key.val) global
  | .has key global => .has (encode m.val) (encode key.val) global
  | .previous key => .previous (encode m.val) (encode key.val)
  | .write key value => .write (encode m.val) (encode key.val) (encodeValue encode value)

/-- Bounds for the containers a point operation may grow. -/
def PointOperation.fits (encode : List U8 → String) (t : Spike.engine.Tx)
    (m : Spike.engine.Bytes)
    : PointOperation → Prop
  | .get key global | .has key global =>
      global = false → find (pointWrites encode t) (encode m.val, encode key.val) = none
      → t.deps.val.length < Usize.max
  | .previous _ => t.deps.val.length < Usize.max
  | .write _ _ => t.pending.val.length < Usize.max

/-- Project results of point operations, leaving non-point results and errors outside the projection. -/
def pointOutput (encode : List U8 → String)
    : core.result.Result Spike.engine.Output Spike.engine.Error → Option Output
  | .Ok (.Value v) => some (.value (encodeValue encode v))
  | .Ok (.Presence b) => some (.presence b)
  | .Ok (.Previous v) => some (.previous (v.map UScalar.val))
  | .Ok .Unit => some .unit
  | _ => none

/-- A point operation may change only the staged writes and dependencies of the Rust attempt. -/
def pointKeepsContext (t next : Spike.engine.Tx) : Prop :=
  {next with pending := t.pending, deps := t.deps} = t

/-- Lookup of a native handle returns the corresponding pinned view. -/
theorem view_lookup (encode : List U8 → String) (inj : Function.Injective encode)
    (t : Spike.engine.Tx) (m : Spike.engine.Bytes)
    : WP.spec
        (Spike.engine.Assoc.get_ref Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey t.views
          m)
        (fun result =>
          result.map (rustPinnedView encode)
          = find (rustPinnedViews encode t.views) (encode m.val)) := by
  apply WP.spec_mono (assoc_get_ref Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
    t.views m (fun b => key_same b m))
  intro result he
  have hi : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  rw [he]
  exact (find_projected t.views.val m (encode ∘ alloc.vec.Vec.val) (rustPinnedView encode) hi).symm

private theorem encode_value_presence (encode : List U8 → String)
    (v : Option Spike.engine.Bytes)
    : (encodeValue encode v).isSome = v.isSome := by cases v <;> rfl

private theorem point_read (encode : List U8 → String) (inj : Function.Injective encode)
    (t : Spike.engine.Tx) (model : Tx) (m key : Spike.engine.Bytes)
    (view : Spike.engine.View) (global presence : Bool)
    (hLocal : encodeImage encode (byteImage view.local) = image model.data (encode m.val))
    (hGlobal
      : encodeImage encode (byteImage (view.global.getD view.local))
        = image ((find model.globalViews (encode m.val)).getD {frame := {}}).frame.data
            (encode m.val))
    (hWrites : pointWrites encode t = model.normal.writes)
    (hDeps : pointDeps encode t = model.normal.deps)
    (room
      : global = false
        → find (pointWrites encode t) (encode m.val, encode key.val) = none
        → t.deps.val.length < Usize.max)
    : let expected :=
        executeOperation model
          ((if presence then .has key global else .get key global : PointOperation).model
            encode m)
      WP.spec
        (do
          let (value, deps) ←
            Spike.engine.Tx.observe t.pending t.deps {map := m, key} view global
          let out :=
            if presence then Spike.engine.Output.Presence value.isSome else .Value value
          Result.ok (core.result.Result.Ok out, {t with deps}))
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ pointWrites encode after = expected.1.normal.writes
          ∧ pointDeps encode after = expected.1.normal.deps
          ∧ pointKeepsContext t after) := by
  let a : Spike.engine.Address := {map := m, key}
  have ha : encAddr encode a = (encode m.val, encode key.val) := rfl
  cases global with
  | false =>
      have hcap : find (pointWrites encode t) (encAddr encode a) = none →
          t.deps.val.length < Usize.max := by rw [ha]; exact room rfl
      apply WP.spec_bind (observe_local encode inj t a view model.data hLocal hcap)
      rintro ⟨value, deps⟩ ⟨hv, hd⟩
      rw [ha, hWrites] at hv hd
      cases presence <;>
        simp [WP.spec_ok, PointOperation.model, executeOperation, pointOutput, hv,
          hd, hDeps, pointKeepsContext, recordOp, stage, ← encode_value_presence encode value] <;>
        exact hWrites
  | true =>
      apply WP.spec_bind (observe_global encode inj t a view _ hGlobal)
      rintro ⟨value, deps⟩ ⟨hv, ht⟩
      subst deps
      rw [ha] at hv
      cases presence
      <;> simp [WP.spec_ok, PointOperation.model, executeOperation, pointOutput, hv,
            hWrites, hDeps, pointKeepsContext, ← encode_value_presence encode value]

private theorem point_previous (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx) (model : Tx)
    (m key : Spike.engine.Bytes) (view : Spike.engine.View)
    (hLocal : encodeImage encode (byteImage view.local) = image model.data (encode m.val))
    (hWrites : pointWrites encode t = model.normal.writes)
    (hDeps : pointDeps encode t = model.normal.deps)
    (room : t.deps.val.length < Usize.max)
    : let expected :=
        executeOperation model ((PointOperation.previous key).model encode m)
      WP.spec
        (do
          let cell ←
            Spike.engine.Assoc.get Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
              Spike.engine.Bytes.Insts.CoreCloneClone
              Spike.engine.Cell.Insts.CoreCloneClone view.local key
          let version ← Spike.engine.cell_version cell
          let deps ← alloc.vec.Vec.push t.deps (.Key {map := m, key} cell)
          Result.ok
            (core.result.Result.Ok (Spike.engine.Output.Previous version), {t with deps}))
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ pointWrites encode after = expected.1.normal.writes
          ∧ pointDeps encode after = expected.1.normal.deps
          ∧ pointKeepsContext t after) := by
  let addr : Spike.engine.Address := {map := m, key}
  apply WP.spec_bind (read_cell encode inj view.local addr model.data hLocal)
  intro cell hc
  have he : find model.data (encode m.val, encode key.val) =
      (cell.map byteCell).map (encodeCell encode) := by
    change cell.map (encodeCell encode ∘ byteCell) =
      find model.data (encode m.val, encode key.val) at hc
    simpa only [Option.map_map, Function.comp_def] using hc.symm
  cases cell <;>
    simp only [Spike.engine.cell_version, bind_ok] <;>
    apply WP.spec_bind (deps_push encode t _ room) <;>
    intro deps hd <;>
    simp [WP.spec_ok, PointOperation.model, executeOperation, pointOutput, previousAt,
      recordOp, needs, stage, he, hd, hDeps, pointKeepsContext, encodeDependency,
      byteDependency, encodeCell, byteCell, encodeAddr, byteAddr] <;>
    exact hWrites

private theorem point_write (encode : List U8 → String) (inj : Function.Injective encode)
    (t : Spike.engine.Tx) (model : Tx) (m key : Spike.engine.Bytes)
    (value : Option Spike.engine.Bytes)
    (hWrites : pointWrites encode t = model.normal.writes)
    (hDeps : pointDeps encode t = model.normal.deps)
    (room : t.pending.val.length < Usize.max)
    : let expected :=
        executeOperation model ((PointOperation.write key value).model encode m)
      WP.spec
        (do
          let w ← Spike.engine.Write.from_option value
          let pending ←
            Spike.engine.Assoc.set Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
              Spike.engine.Address.Insts.CoreCloneClone
              Spike.engine.Write.Insts.CoreCloneClone t.pending {map := m, key} w
          Result.ok (core.result.Result.Ok Spike.engine.Output.Unit, {t with pending}))
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ pointWrites encode after = expected.1.normal.writes
          ∧ pointDeps encode after = expected.1.normal.deps
          ∧ pointKeepsContext t after) := by
  cases value <;>
    simp only [Spike.engine.Write.from_option, bind_ok] <;>
    apply WP.spec_bind (stage_write encode inj t {map := m, key} _ room) <;>
    intro pending hp <;>
    simp [WP.spec_ok, pointOutput, PointOperation.model, executeOperation, recordOp, needs, stage,
      hp, hWrites, pointKeepsContext, encAddr, encWrite, encodeValue, encodeAddr, byteAddr] <;>
    exact hDeps

/-- An active point operation observes the model result and preserves the related writes and dependencies. -/
theorem operate_point_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx) (model : Tx)
    (m : Spike.engine.Bytes) (op : PointOperation) (view : GlobalView)
    (hPhase : t.phase = .Active)
    (hView : find model.globalViews (encode m.val) = some view)
    (hPinned : rustPinnedViews encode t.views = modelPinnedViews model.globalViews)
    (hLocal : image view.current.data (encode m.val) = image model.data (encode m.val))
    (hWrites : pointWrites encode t = model.normal.writes)
    (hDeps : pointDeps encode t = model.normal.deps) (room : op.fits encode t m)
    : let expected := executeOperation model (op.model encode m)
      WP.spec (Spike.engine.Tx.operate t m op.rust)
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ pointWrites encode after = expected.1.normal.writes
          ∧ pointDeps encode after = expected.1.normal.deps
          ∧ pointKeepsContext t after) := by
  have hFound : find (rustPinnedViews encode t.views) (encode m.val) =
      some (modelPinnedView (encode m.val) view) := by
    rw [hPinned]
    generalize hm : encode m.val = needle at hView ⊢
    generalize model.globalViews = rows at hView ⊢
    induction rows with
    | nil => simp [find] at hView
    | cons row rest ih =>
        obtain ⟨k, v⟩ := row
        by_cases hk : k = needle
        · subst k
          simp [find] at hView
          subst v
          simp [modelPinnedViews, find]
        · simp [modelPinnedViews, find, hk] at hView ⊢
          exact ih hView
  have hActive : {t with phase := .Active} = t := by rw [← hPhase]
  simp only [Spike.engine.Tx.operate, hPhase, bind_ok]
  apply WP.spec_bind (view_lookup encode inj t m)
  intro found hf
  rw [hFound] at hf
  cases found with
  | none => cases hf
  | some native =>
      have hv : rustPinnedView encode native = modelPinnedView (encode m.val) view :=
        Option.some.inj hf
      have hl
          : encodeImage encode (byteImage native.local)
            = image model.data (encode m.val) :=
        (congrArg PinnedView.localImage hv).trans hLocal
      have hg : encodeImage encode (byteImage (native.global.getD native.local)) =
          image ((find model.globalViews (encode m.val)).getD {frame := {}}).frame.data (encode m.val) := by
        rw [hView]
        exact congrArg PinnedView.globalImage hv
      cases op with
      | get key global =>
          simp only [PointOperation.rust]
          rw [← hPhase]
          simpa only [Bool.false_eq_true, ite_false]
            using (point_read encode inj t model m key native global false hl hg hWrites
                    hDeps room)
      | has key global =>
          simp only [PointOperation.rust]
          rw [← hPhase]
          simpa only [core.option.Option.is_some, Bool.true_eq, ite_true]
            using (point_read encode inj t model m key native global true hl hg hWrites
                    hDeps room)
      | previous key =>
          rw [← hPhase]
          exact point_previous encode inj t model m key native hl hWrites hDeps room
      | write key value =>
          simpa only [PointOperation.rust, hPhase]
            using (point_write encode inj t model m key value hWrites hDeps room)

private theorem reference_point_step (encode : List U8 → String) (m : Spike.engine.Bytes)
    (op : PointOperation) (w : State) (sid tid : Nat) (model : Store) (t : Tx)
    (hLookup : lookupTx w sid tid = some (model, t))
    (hPhase : t.phase = .active) (hSnap : t.snapshot.isSome)
    (hView : (find t.globalViews (encode m.val)).isSome)
    : let expected := executeOperation t (op.model encode m)
      execute w (.operation sid tid (op.model encode m))
      = some ({w with txs := Kv.Model.set w.txs tid expected.1}, expected.2) := by
  have hm : (op.model encode m).map = encode m.val := by cases op <;> rfl
  have hp : (Phase.active != Phase.active) = false := rfl
  have hs : t.snapshot.isNone = false := by cases e : t.snapshot <;> simp_all
  have hv : (find t.globalViews (encode m.val)).isNone = false := by
    cases e : find t.globalViews (encode m.val) <;> simp_all
  have bind_some {α β : Type} (x : α) (f : α → Option β) : (some x >>= f) = f x := rfl
  simp only [execute, hLookup, bind_some, hPhase, hp, hm, hs, hv,
    Bool.false_or, Bool.false_eq_true, ite_false]

/-- The `Operate` dispatcher agrees with `Kv.Model.execute` for enabled point operations. -/
theorem execute_point_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (s : Spike.engine.Store) (id : U64)
    (t : Spike.engine.Tx) (w : State) (sid : Nat) (model : Store) (tx : Tx)
    (m : Spike.engine.Bytes) (op : PointOperation) (view : GlobalView)
    (hNative : find s.txs.val id = some t)
    (hLookup : lookupTx w sid id.val = some (model, tx))
    (hNativePhase : t.phase = .Active) (hModelPhase : tx.phase = .active)
    (hSnap : tx.snapshot.isSome) (hView : find tx.globalViews (encode m.val) = some view)
    (hPinned : rustPinnedViews encode t.views = modelPinnedViews tx.globalViews)
    (hLocal : image view.current.data (encode m.val) = image tx.data (encode m.val))
    (hWrites : pointWrites encode t = tx.normal.writes)
    (hDeps : pointDeps encode t = tx.normal.deps) (room : op.fits encode t m)
    : WP.spec (Spike.engine.Store.execute s (.Operate id m op.rust))
        (fun (output, after) =>
          ∃ modelAfter txAfter tAfter obs index,
            execute w (.operation sid id.val (op.model encode m)) = some (modelAfter, obs)
            ∧ pointOutput encode output = some obs
            ∧ modelAfter = {w with txs := Kv.Model.set w.txs id.val txAfter}
            ∧ pointWrites encode tAfter = txAfter.normal.writes
            ∧ pointDeps encode tAfter = txAfter.normal.deps
            ∧ pointKeepsContext t tAfter
            ∧ after.history = s.history
            ∧ s.txs.val[index]? = some (id, t)
            ∧ after.txs.val = s.txs.val.set index (id, tAfter)) := by
  have hStep := reference_point_step encode m op w sid id.val model tx hLookup hModelPhase hSnap
    (by simp [hView])
  unfold Spike.engine.Store.execute
  apply WP.spec_bind (tx_index s id)
  intro outcome hi
  cases outcome with
  | Err _ => simp [hNative] at hi
  | Ok i =>
      obtain ⟨old, hrow, ht⟩ := hi
      rw [hNative] at ht
      cases ht
      obtain ⟨idx, hget⟩ := List.getElem?_eq_some_iff.mp hrow
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec s.txs i idx)
      rintro ⟨row, back⟩ hback
      have he : row = (id, t) := hback.1.trans hget
      subst row
      change WP.spec (do
        let (out, next) ← Spike.engine.Tx.operate t m op.rust
        Result.ok (out, {s with txs := back (id, next)})) _
      apply WP.spec_bind
        (operate_point_matches_model encode inj t tx m op view hNativePhase
          hView hPinned hLocal hWrites hDeps room)
      rintro ⟨out, next⟩ ⟨ho, hw, hd, hkeep⟩
      have hupdate : (back (id, next)).val = s.txs.val.set i.val (id, next) := by
        rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _
      change WP.spec (Result.ok (out, ({s with txs := back (id, next)} : Spike.engine.Store))) _
      rw [WP.spec_ok]
      let expected := executeOperation tx (op.model encode m)
      exact ⟨{w with txs := Kv.Model.set w.txs id.val expected.1}, expected.1, next,
        expected.2, i.val, hStep, ho, rfl, hw, hd, hkeep, rfl, hrow, hupdate⟩

end KvRust
