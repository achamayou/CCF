-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Acquire
public import KvRust.OrderEquivalence
public import KvRust.PendingWrites

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

local instance : DecidableEq CcfKv.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

local instance : DecidableEq CcfKv.engine.Address :=
  fun a b => decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

/-- Project byte values without conflating a deletion with an empty value. -/
def encodeValue (encode : List U8 → String) (value : Option CcfKv.engine.Bytes)
    : Option String :=
  value.map (encode ∘ alloc.vec.Vec.val)

/-- Project the extracted write overlay in model order. -/
def pointWrites (encode : List U8 → String) (t : CcfKv.engine.Tx) : Pending :=
  encodeWrites encode (byteWrites t.pending.val)

/-- Encode the two components of a native address. -/
def encAddr (encode : List U8 → String) (a : CcfKv.engine.Address) : Addr String String :=
  encodeAddr encode (byteAddr a)

/-- Encode a staged put or deletion. -/
def encWrite (encode : List U8 → String) (w : CcfKv.engine.Write) : Option String :=
  match w with
  | .Put value => encodeValue encode (some value)
  | .Remove => none

private theorem clone_write (w : CcfKv.engine.Write)
    : CcfKv.engine.Write.Insts.CoreCloneClone.clone w = .ok w := by
  cases w <;> simp [CcfKv.engine.Write.Insts.CoreCloneClone.clone, clone_bytes]

/-- Project the ordered write overlay row by row. -/
theorem pending_projection (encode : List U8 → String) (t : CcfKv.engine.Tx)
    : pointWrites encode t
      = t.pending.val.map fun (a, w) => (encAddr encode a, encWrite encode w) := by
  simp only [pointWrites, encodeWrites, byteWrites, List.map_map, Function.comp_def]
  apply List.map_congr_left
  rintro ⟨a, w⟩ _
  cases w <;> rfl

theorem sorted_pending_unique (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx)
    (sorted : PendingSorted t.pending.val)
    : Kv.Properties.Unique (pointWrites encode t) := by
  have injective : Function.Injective (encAddr encode) :=
    (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
  unfold Kv.Properties.Unique
  rw [pending_projection, List.map_map]
  have unique := sorted.unique.map injective
  rw [List.map_map] at unique
  exact unique

private theorem pending_lookup (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address)
    : WP.spec
        (CcfKv.engine.Assoc.get CcfKv.engine.Address.Insts.Ccf_kvEngineKey
          CcfKv.engine.Address.Insts.CoreCloneClone
          CcfKv.engine.Write.Insts.CoreCloneClone t.pending a)
        (fun result =>
          result.map (encWrite encode)
          = find (pointWrites encode t) (encAddr encode a)) := by
  have hk : Function.Injective (encAddr encode) :=
    (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
  apply WP.spec_mono (assoc_get CcfKv.engine.Address.Insts.Ccf_kvEngineKey
    CcfKv.engine.Address.Insts.CoreCloneClone CcfKv.engine.Write.Insts.CoreCloneClone
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

private theorem read_cell_with_lookup (encode : List U8 → String)
    (inj : Function.Injective encode) (history : CcfKv.engine.History)
    (pin : CcfKv.engine.PinnedImage) (a : CcfKv.engine.Address) (db : Data)
    (same
      : find (encodeImage encode (pinImage history.index a.map pin)) (encAddr encode a).2
        = find db (encAddr encode a))
    (live : PinLive history.index pin)
    (space : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.PinnedImage.point pin history a)
        (fun result =>
          result.map (encodeCell encode ∘ byteCell) = find db (encAddr encode a)) := by
  apply WP.spec_mono (pin_point_refines history a pin live space)
  intro result hr
  have he := find_projected (pinImage history.index a.map pin) a.key.val encode (encodeCell encode) inj
  change find (encodeImage encode (pinImage history.index a.map pin)) (encAddr encode a).2 = _ at he
  rw [← hr, Option.map_map] at he
  exact he.symm.trans same

private theorem read_cell (encode : List U8 → String) (inj : Function.Injective encode)
    (history : CcfKv.engine.History) (pin : CcfKv.engine.PinnedImage)
    (a : CcfKv.engine.Address) (db : Data)
    (hImage
      : encodeImage encode (pinImage history.index a.map pin)
        = image db (encAddr encode a).1)
    (live : PinLive history.index pin)
    (space : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.PinnedImage.point pin history a)
        (fun result =>
          result.map (encodeCell encode ∘ byteCell) = find db (encAddr encode a)) := by
  apply read_cell_with_lookup encode inj history pin a db _ live space
  rw [hImage, image_key]

private theorem copy_cell_exact (c : Option CcfKv.engine.Cell)
    : CcfKv.engine.copy_cell c = .ok c := by
  cases c <;> simp [CcfKv.engine.copy_cell, clone_cell]

/-- Appending a native dependency prepends its model projection. -/
theorem deps_push (encode : List U8 → String) (index : CellIndex) (t : CcfKv.engine.Tx)
    (d : CcfKv.engine.Dependency) (room : t.deps.val.length < Usize.max)
    : WP.spec (alloc.vec.Vec.push t.deps d)
        (fun deps =>
          deps.val = t.deps.val ++ [d]
          ∧ pointDeps encode index {t with deps}
            = encodeDependency encode (byteDependency index d)
              :: pointDeps encode index t) := by
  apply WP.spec_mono (alloc.vec.Vec.push_spec t.deps d room)
  intro deps h
  exact ⟨h, by simp [pointDeps, h]⟩

private theorem observe_global_with_lookup (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address)
    (history : CcfKv.engine.History) (view : CcfKv.engine.View) (db : Data)
    (same
      : find
          (encodeImage encode
            (pinImage history.index a.map (view.global.getD view.local)))
          (encAddr encode a).2
        = find db (encAddr encode a))
    (live : ViewLive history.index view)
    (space : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.Tx.observe history t.pending t.deps a view true)
        (fun (value, deps) =>
          encodeValue encode value = (find db (encAddr encode a)).map Cell.value
          ∧ deps = t.deps) := by
  simp only [CcfKv.engine.Tx.observe, ite_true]
  have hGlobal : CcfKv.engine.View.global_image view = .ok (view.global.getD view.local) := by
    cases h : view.global <;> simp [CcfKv.engine.View.global_image, h]
  simp only [hGlobal, bind_ok]
  apply WP.spec_bind
    (read_cell_with_lookup encode inj history (view.global.getD view.local) a db same
      live.2 space)
  intro cell hc
  cases cell <;> simp [CcfKv.engine.cell_value, ← hc, encodeValue,
    encodeCell, byteCell, Function.comp_def]

private theorem observe_global (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address)
    (history : CcfKv.engine.History) (view : CcfKv.engine.View) (db : Data)
    (hImage
      : encodeImage encode (pinImage history.index a.map (view.global.getD view.local))
        = image db (encAddr encode a).1)
    (live : ViewLive history.index view)
    (space : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.Tx.observe history t.pending t.deps a view true)
        (fun (value, deps) =>
          encodeValue encode value = (find db (encAddr encode a)).map Cell.value
          ∧ deps = t.deps) := by
  apply observe_global_with_lookup encode inj t a history view db _ live space
  rw [hImage, image_key]

/-- Every whole-map dependency's pinned image belongs to a view retained by `t`. -/
def DepsPinsInViews (t : CcfKv.engine.Tx) : Prop :=
  ∀ m pin,
    CcfKv.engine.Dependency.Map m pin ∈ t.deps.val
    → ∃ row ∈ t.views.val, row.1 = m ∧ pin = row.2.local

/-- Every whole-map dependency recorded on a Rust attempt matches the pinned
local image of an already acquired view on that attempt. -/
def NativeDepsFromViews (encode : List U8 → String) (index : CellIndex)
    (t : CcfKv.engine.Tx)
    : Prop :=
  ∀ d ∈ pointDeps encode index t,
    match d with
    | .key _ _ => True
    | .map m expected =>
        ∃ view,
          find (rustPinnedViews encode index t.views) m = some view
          ∧ expected = view.localImage

/-- Every whole-map dependency recorded on a model attempt matches the captured
local frame of an already acquired view on that attempt. -/
def ModelDepsFromViews (tx : Tx) : Prop :=
  ∀ d ∈ tx.normal.deps,
    match d with
    | .key _ _ => True
    | .map m expected =>
        ∃ gv, find tx.globalViews m = some gv ∧ expected = image gv.current.data m

private theorem observe_local_with_lookup (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address)
    (history : CcfKv.engine.History) (view : CcfKv.engine.View) (db : Data)
    (same
      : find (encodeImage encode (pinImage history.index a.map view.local))
          (encAddr encode a).2
        = find db (encAddr encode a))
    (live : ViewLive history.index view)
    (space : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    (room
      : find (pointWrites encode t) (encAddr encode a) = none
        → t.deps.val.length < Usize.max)
    : WP.spec (CcfKv.engine.Tx.observe history t.pending t.deps a view false)
        (fun (value, deps) =>
          encodeValue encode value = valueAt db (pointWrites encode t) (encAddr encode a)
          ∧ pointDeps encode history.index {t with deps}
            = needs db (pointWrites encode t)
                (.read (encAddr encode a) (encodeValue encode value))
              ++ pointDeps encode history.index t
          ∧ (DepsPinsInViews t → DepsPinsInViews {t with deps})) := by
  simp only [CcfKv.engine.Tx.observe, Bool.false_eq_true, ite_false]
  apply WP.spec_bind (pending_lookup encode inj t a)
  intro write hw
  cases write with
  | some w => cases w <;> simp [← hw, valueAt, needs, encWrite, encodeValue]
  | none =>
      apply WP.spec_bind
        (read_cell_with_lookup encode inj history view.local a db same live.1
          space)
      intro cell hc
      have hroom := room hw.symm
      have hdep (deps : alloc.vec.Vec CcfKv.engine.Dependency)
          (hd
            : pointDeps encode history.index {t with deps}
              = encodeDependency encode (byteDependency history.index (.Key a cell))
                :: pointDeps encode history.index t)
          : pointDeps encode history.index {t with deps}
            = .key (encAddr encode a) (find db (encAddr encode a))
              :: pointDeps encode history.index t := by
        rw [hd]
        have he
            : (cell.map byteCell).map (encodeCell encode)
              = find db (encAddr encode a) := by
          simpa only [Option.map_map, Function.comp_def] using hc
        simp [encodeDependency, byteDependency, he, encAddr]
      have hpins (deps : alloc.vec.Vec CcfKv.engine.Dependency)
          (hval : deps.val = t.deps.val ++ [.Key a cell])
          : DepsPinsInViews t → DepsPinsInViews {t with deps} := by
        intro hp m pin hmem
        change CcfKv.engine.Dependency.Map m pin ∈ deps.val at hmem
        rw [hval, List.mem_append, List.mem_singleton] at hmem
        rcases hmem with hold | hnew
        · exact hp m pin hold
        · cases hnew
      cases cell <;>
        (simp only [copy_cell_exact, CcfKv.engine.cell_value, clone_address, bind_ok];
          apply WP.spec_bind (deps_push encode history.index t _ hroom);
          rintro deps ⟨hval, hd⟩;
          have hh := hdep deps hd;
          have hp := hpins deps hval;
          rw [WP.spec_ok];
          refine ⟨?_, ?_, hp⟩ <;>
            simp [← hw, valueAt, needs, ← hc, hh, encodeValue, encodeCell, byteCell, Function.comp_def])

private theorem observe_local (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address)
    (history : CcfKv.engine.History) (view : CcfKv.engine.View) (db : Data)
    (hImage
      : encodeImage encode (pinImage history.index a.map view.local)
        = image db (encAddr encode a).1)
    (live : ViewLive history.index view)
    (space : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    (room
      : find (pointWrites encode t) (encAddr encode a) = none
        → t.deps.val.length < Usize.max)
    : WP.spec (CcfKv.engine.Tx.observe history t.pending t.deps a view false)
        (fun (value, deps) =>
          encodeValue encode value = valueAt db (pointWrites encode t) (encAddr encode a)
          ∧ pointDeps encode history.index {t with deps}
            = needs db (pointWrites encode t)
                (.read (encAddr encode a) (encodeValue encode value))
              ++ pointDeps encode history.index t) := by
  apply WP.spec_mono
    (observe_local_with_lookup encode inj t a history view db
      (by rw [hImage, image_key]) live space room)
  rintro ⟨v, d⟩ ⟨h1, h2, _⟩
  exact ⟨h1, h2⟩

/-- Local point reads are unchanged by reordering pending writes or the pinned
image; overlay hits, including tombstones, still add no read dependency. -/
theorem observe_local_by_contents (encode : List U8 → String)
    (inj : Function.Injective encode) (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address)
    (history : CcfKv.engine.History) (view : CcfKv.engine.View) (db : Data)
    (reference : Pending)
    (localImage
      : (encodeImage encode (pinImage history.index a.map view.local)).Perm
          (image db (encAddr encode a).1))
    (imageUnique : Kv.Properties.Unique (image db (encAddr encode a).1))
    (writes : (pointWrites encode t).Perm reference)
    (sorted : PendingSorted t.pending.val)
    (referenceDeps : List (Dependency String String String))
    (relatedDeps
      : List.Forall₂ DependencyOrderEq (pointDeps encode history.index t) referenceDeps)
    (live : ViewLive history.index view)
    (space : 8 + a.map.val.length + a.key.val.length ≤ Usize.max)
    (room
      : find (pointWrites encode t) (encAddr encode a) = none
        → t.deps.val.length < Usize.max)
    : WP.spec (CcfKv.engine.Tx.observe history t.pending t.deps a view false)
        (fun (value, deps) =>
          encodeValue encode value = valueAt db reference (encAddr encode a)
          ∧ List.Forall₂ DependencyOrderEq (pointDeps encode history.index {t with deps})
              (needs db reference (.read (encAddr encode a) (encodeValue encode value))
                ++ referenceDeps)) := by
  have cell : find (encodeImage encode (pinImage history.index a.map view.local)) (encAddr encode a).2 =
      find db (encAddr encode a) := by
    rw [lookup_perm localImage (unique_of_perm localImage.symm imageUnique), image_key]
  have pending := lookup_perm writes (sorted_pending_unique encode inj t sorted) (encAddr encode a)
  apply WP.spec_mono
    (observe_local_with_lookup encode inj t a history view db cell live space
      room)
  rintro ⟨value, deps⟩ ⟨observed, recorded, _⟩
  refine ⟨?_, ?_⟩
  · simpa only [valueAt, pending] using observed
  · rw [recorded]
    cases h : find reference (encAddr encode a) with
    | none =>
        simp only [needs, pending, h, Option.isSome_none, Bool.false_eq_true, ite_false, List.cons_append,
          List.nil_append]
        exact .cons (.key _ _) relatedDeps
    | some write =>
        simp only [needs, pending, h, Option.isSome_some, ite_true, List.nil_append]
        exact relatedDeps

/-- Staging a write replaces its model binding and adds at most one entry. -/
theorem stage_write_bounded (encode : List U8 → String) (inj : Function.Injective encode)
    (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address) (w : CcfKv.engine.Write)
    (room : t.pending.val.length < Usize.max)
    : WP.spec
        (CcfKv.engine.Assoc.set CcfKv.engine.Address.Insts.Ccf_kvEngineKey
          CcfKv.engine.Address.Insts.CoreCloneClone
          CcfKv.engine.Write.Insts.CoreCloneClone t.pending a w)
        (fun pending =>
          pointWrites encode {t with pending}
            = Kv.Model.set (pointWrites encode t) (encAddr encode a) (encWrite encode w)
          ∧ pending.val.length ≤ t.pending.val.length + 1) := by
  have hi : Function.Injective (encAddr encode) :=
    (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
  apply WP.spec_mono (assoc_set CcfKv.engine.Address.Insts.Ccf_kvEngineKey
    CcfKv.engine.Address.Insts.CoreCloneClone CcfKv.engine.Write.Insts.CoreCloneClone
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
    (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address) (w : CcfKv.engine.Write)
    (room : t.pending.val.length < Usize.max)
    : WP.spec
        (CcfKv.engine.Assoc.set CcfKv.engine.Address.Insts.Ccf_kvEngineKey
          CcfKv.engine.Address.Insts.CoreCloneClone
          CcfKv.engine.Write.Insts.CoreCloneClone t.pending a w)
        (fun pending =>
          pointWrites encode {t with pending}
          = Kv.Model.set (pointWrites encode t) (encAddr encode a) (encWrite encode w)) :=
  WP.spec_mono (stage_write_bounded encode inj t a w room) (fun _ h => h.1)

/-- The native fast path respects the write set modulo order, even when the
reference and native input lists already differ in order. -/
theorem stage_key_write (encode : List U8 → String) (inj : Function.Injective encode)
    (t : CcfKv.engine.Tx) (a : CcfKv.engine.Address) (w : CcfKv.engine.Write)
    (reference : Pending) (related : (pointWrites encode t).Perm reference)
    (sorted : PendingSorted t.pending.val) (room : t.pending.val.length < Usize.max)
    : WP.spec (CcfKv.engine.stage_write t.pending a w)
        (fun pending =>
          (pointWrites encode {t with pending}).Perm
            (Kv.Model.set reference (encAddr encode a) (encWrite encode w))
          ∧ PendingSorted pending.val
          ∧ pending.val.length ≤ t.pending.val.length + 1) := by
  have injective : Function.Injective (encAddr encode) :=
    (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
  apply WP.spec_mono (stage_write_by_key_refines t.pending a w sorted room)
  intro pending ⟨ordered, exactWrites⟩
  refine ⟨?_, ordered, ?_⟩
  · have projected :=
      exactWrites.map fun (a, w) => (encAddr encode a, encWrite encode w)
    rw [← set_projected t.pending.val a w (encAddr encode) (encWrite encode) injective]
      at projected
    simp only [pending_projection] at related ⊢
    exact projected.trans (set_perm related _ _)
  · rw [exactWrites.length_eq, Kv.Model.set, List.length_cons]
    exact Nat.succ_le_succ (List.length_filter_le _ _)

/-- Operations on a single key; a `none` write is a staged deletion. -/
inductive PointOperation where
  | get (key : CcfKv.engine.Bytes) (global : Bool)
  | has (key : CcfKv.engine.Bytes) (global : Bool)
  | previous (key : CcfKv.engine.Bytes)
  | write (key : CcfKv.engine.Bytes) (value : Option CcfKv.engine.Bytes)

/-- Embed a point operation into the extracted operation type. -/
def PointOperation.rust : PointOperation → CcfKv.engine.Operation
  | .get key global => .Get key global
  | .has key global => .Has key global
  | .previous key => .Previous key
  | .write key value => .Write key value

/-- Encode the map, key, and optional value for the reference model. -/
def PointOperation.model (encode : List U8 → String) (m : CcfKv.engine.Bytes)
    : PointOperation → Operation
  | .get key global => .get (encode m.val) (encode key.val) global
  | .has key global => .has (encode m.val) (encode key.val) global
  | .previous key => .previous (encode m.val) (encode key.val)
  | .write key value => .write (encode m.val) (encode key.val) (encodeValue encode value)

/-- Bounds for the containers a point operation may grow. -/
def PointOperation.fits (encode : List U8 → String) (t : CcfKv.engine.Tx)
    (m : CcfKv.engine.Bytes)
    : PointOperation → Prop
  | .get key global | .has key global =>
      global = false → find (pointWrites encode t) (encode m.val, encode key.val) = none
      → t.deps.val.length < Usize.max
  | .previous _ => t.deps.val.length < Usize.max
  | .write _ _ => t.pending.val.length < Usize.max

def PointOperation.indexRoom (m : CcfKv.engine.Bytes) : PointOperation → Prop
  | .get key _ | .has key _ | .previous key =>
      8 + m.val.length + key.val.length ≤ Usize.max
  | .write _ _ => True

/-- Project results of point operations, leaving non-point results and errors outside the projection. -/
def pointOutput (encode : List U8 → String)
    : core.result.Result CcfKv.engine.Output CcfKv.engine.Error → Option Output
  | .Ok (.Value v) => some (.value (encodeValue encode v))
  | .Ok (.Presence b) => some (.presence b)
  | .Ok (.Previous v) => some (.previous (v.map UScalar.val))
  | .Ok .Unit => some .unit
  | _ => none

/-- A point operation may change only the staged writes and dependencies of the Rust attempt. -/
def pointKeepsContext (t next : CcfKv.engine.Tx) : Prop :=
  {next with pending := t.pending, deps := t.deps} = t

/-- Lookup of a native handle returns the corresponding pinned view. -/
theorem view_lookup (encode : List U8 → String) (inj : Function.Injective encode)
    (index : CellIndex) (t : CcfKv.engine.Tx) (m : CcfKv.engine.Bytes)
    (live : ViewsLive index t.views)
    : WP.spec
        (CcfKv.engine.Assoc.get_ref CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey t.views
          m)
        (fun result =>
          result.map (rustPinnedView encode index m)
            = find (rustPinnedViews encode index t.views) (encode m.val)
          ∧ ∀ v, result = some v → (m, v) ∈ t.views.val ∧ ViewLive index v) := by
  apply WP.spec_mono (assoc_get_ref CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
    t.views m (fun b => key_same b m))
  intro result he
  have hi : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  constructor
  · rw [he]
    exact (find_projected_with_key t.views.val m (encode ∘ alloc.vec.Vec.val)
      (rustPinnedView encode index) hi).symm
  · intro v found
    have hmem : (m, v) ∈ t.views.val := by
      have present : ∀ rows : List (CcfKv.engine.Bytes × CcfKv.engine.View),
          find rows m = some v → (m, v) ∈ rows := by
        intro rows
        induction rows with
        | nil => simp [find]
        | cons row rest ih =>
            obtain ⟨k, value⟩ := row
            by_cases eq : k = m
            · subst k
              intro eq
              have same : value = v := by simpa [find] using eq
              simp [same]
            · intro found
              have next : find rest m = some v := by simpa [find, eq] using found
              exact List.mem_cons_of_mem _ (ih next)
      exact present _ (he.symm.trans found)
    exact ⟨hmem, live (m, v) hmem⟩

private theorem encode_value_presence (encode : List U8 → String)
    (v : Option CcfKv.engine.Bytes)
    : (encodeValue encode v).isSome = v.isSome := by cases v <;> rfl

private theorem point_read (encode : List U8 → String) (inj : Function.Injective encode)
    (history : CcfKv.engine.History) (t : CcfKv.engine.Tx) (model : Tx)
    (m key : CcfKv.engine.Bytes) (view : CcfKv.engine.View) (global presence : Bool)
    (hLocal
      : (encodeImage encode (pinImage history.index m view.local)).Perm
          (image model.data (encode m.val)))
    (hLocalUnique : Kv.Properties.Unique (image model.data (encode m.val)))
    (hGlobal
      : (encodeImage encode (pinImage history.index m (view.global.getD view.local))).Perm
          (image ((find model.globalViews (encode m.val)).getD {frame := {}}).frame.data
            (encode m.val)))
    (hGlobalUnique
      : Kv.Properties.Unique
          (image ((find model.globalViews (encode m.val)).getD {frame := {}}).frame.data
            (encode m.val)))
    (hWrites : (pointWrites encode t).Perm model.normal.writes)
    (hSorted : PendingSorted t.pending.val)
    (hDeps
      : List.Forall₂ DependencyOrderEq (pointDeps encode history.index t)
          model.normal.deps)
    (hNativeOrig : NativeDepsFromViews encode history.index t)
    (hDepsPins : DepsPinsInViews t)
    (hModelOrig : ModelDepsFromViews model)
    (live : ViewLive history.index view)
    (space : 8 + m.val.length + key.val.length ≤ Usize.max)
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
            CcfKv.engine.Tx.observe history t.pending t.deps {map := m, key} view global
          let out :=
            if presence then CcfKv.engine.Output.Presence value.isSome else .Value value
          Result.ok (core.result.Result.Ok out, {t with deps}))
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ (pointWrites encode after).Perm expected.1.normal.writes
          ∧ List.Forall₂ DependencyOrderEq (pointDeps encode history.index after)
              expected.1.normal.deps
          ∧ pointKeepsContext t after
          ∧ PendingSorted after.pending.val
          ∧ NativeDepsFromViews encode history.index after
          ∧ DepsPinsInViews after
          ∧ ModelDepsFromViews expected.1) := by
  let a : CcfKv.engine.Address := {map := m, key}
  have ha : encAddr encode a = (encode m.val, encode key.val) := rfl
  cases global with
  | false =>
      have hcap : find (pointWrites encode t) (encAddr encode a) = none →
          t.deps.val.length < Usize.max := by rw [ha]; exact room rfl
      have hLocalCell : find (encodeImage encode (pinImage history.index a.map view.local))
          (encAddr encode a).2 = find model.data (encAddr encode a) := by
        rw [lookup_perm hLocal (unique_of_perm hLocal.symm hLocalUnique), image_key]; rfl
      have hPending : find (pointWrites encode t) (encode m.val, encode key.val) =
          find model.normal.writes (encode m.val, encode key.val) :=
        lookup_perm hWrites (sorted_pending_unique encode inj t hSorted) (encode m.val, encode key.val)
      apply WP.spec_bind
        (observe_local_with_lookup encode inj t a history view model.data hLocalCell live
          space hcap)
      rintro ⟨value, deps⟩ ⟨hv, hd, hdp⟩
      rw [ha] at hv hd
      have hv' : encodeValue encode value = valueAt model.data model.normal.writes (encode m.val, encode key.val) := by
        simpa only [valueAt, hPending] using hv
      have hDepsNext : List.Forall₂ DependencyOrderEq (pointDeps encode history.index {t with deps})
          (needs model.data model.normal.writes (.read (encode m.val, encode key.val) (encodeValue encode value)) ++ model.normal.deps) := by
        rw [hd]
        cases h : find model.normal.writes (encode m.val, encode key.val) with
        | none =>
            simp only [needs, hPending, h, Option.isSome_none, Bool.false_eq_true, ite_false,
              List.cons_append, List.nil_append]
            exact .cons (.key _ _) hDeps
        | some w =>
            simp only [needs, hPending, h, Option.isSome_some, ite_true, List.nil_append]
            exact hDeps
      have hNatOrigNext : NativeDepsFromViews encode history.index {t with deps} := by
        intro d hm
        rw [hd] at hm
        cases h : find (pointWrites encode t) (encode m.val, encode key.val) with
        | none =>
            simp only [needs, h, Option.isSome_none, Bool.false_eq_true, ite_false,
              List.cons_append, List.nil_append] at hm
            rcases List.mem_cons.mp hm with rfl | old
            · trivial
            · exact hNativeOrig d old
        | some w =>
            simp only [needs, h, Option.isSome_some, ite_true, List.nil_append] at hm
            exact hNativeOrig d hm
      have hModOrigNext : ModelDepsFromViews {model with normal := recordOp model.data model.normal (.read (encode m.val, encode key.val) (valueAt model.data model.normal.writes (encode m.val, encode key.val)))} := by
        intro d hm
        change d ∈ needs model.data model.normal.writes _ ++ model.normal.deps at hm
        cases h : find model.normal.writes (encode m.val, encode key.val) with
        | none =>
            simp only [needs, h, Option.isSome_none, Bool.false_eq_true, ite_false,
              List.cons_append, List.nil_append] at hm
            rcases List.mem_cons.mp hm with rfl | old
            · trivial
            · exact hModelOrig d old
        | some w =>
            simp only [needs, h, Option.isSome_some, ite_true, List.nil_append] at hm
            exact hModelOrig d hm
      cases presence <;>
        (change WP.spec (Result.ok _) _; rw [WP.spec_ok];
          refine ⟨?_, hWrites, ?_, rfl, hSorted, hNatOrigNext, hdp hDepsPins, hModOrigNext⟩)
      · simp [pointOutput, PointOperation.model, executeOperation, hv']
      · rw [hv'] at hDepsNext; exact hDepsNext
      · simp [pointOutput, PointOperation.model, executeOperation, ← encode_value_presence encode value, hv']
      · rw [hv'] at hDepsNext; exact hDepsNext
  | true =>
      have hGlobCell : find (encodeImage encode (pinImage history.index a.map (view.global.getD view.local)))
          (encAddr encode a).2 =
          find ((find model.globalViews (encode m.val)).getD {frame := {}}).frame.data (encAddr encode a) := by
        rw [lookup_perm hGlobal (unique_of_perm hGlobal.symm hGlobalUnique), image_key]; rfl
      apply WP.spec_bind
        (observe_global_with_lookup encode inj t a history view _ hGlobCell live
          space)
      rintro ⟨value, deps⟩ ⟨hv, ht⟩
      subst deps
      rw [ha] at hv
      cases presence
      <;> simp [WP.spec_ok, PointOperation.model, executeOperation, pointOutput, hv,
            hWrites, hDeps, hSorted, hNativeOrig, hDepsPins, hModelOrig, pointKeepsContext,
            ← encode_value_presence encode value]

private theorem point_previous (encode : List U8 → String)
    (inj : Function.Injective encode) (history : CcfKv.engine.History)
    (t : CcfKv.engine.Tx) (model : Tx) (m key : CcfKv.engine.Bytes)
    (view : CcfKv.engine.View)
    (hLocal
      : (encodeImage encode (pinImage history.index m view.local)).Perm
          (image model.data (encode m.val)))
    (hLocalUnique : Kv.Properties.Unique (image model.data (encode m.val)))
    (hWrites : (pointWrites encode t).Perm model.normal.writes)
    (hSorted : PendingSorted t.pending.val)
    (hDeps
      : List.Forall₂ DependencyOrderEq (pointDeps encode history.index t)
          model.normal.deps)
    (hNativeOrig : NativeDepsFromViews encode history.index t)
    (hDepsPins : DepsPinsInViews t)
    (hModelOrig : ModelDepsFromViews model)
    (live : ViewLive history.index view)
    (space : 8 + m.val.length + key.val.length ≤ Usize.max)
    (room : t.deps.val.length < Usize.max)
    : let expected :=
        executeOperation model ((PointOperation.previous key).model encode m)
      WP.spec
        (do
          let cell ← CcfKv.engine.PinnedImage.point view.local history {map := m, key}
          let version ← CcfKv.engine.cell_version cell
          let deps ← alloc.vec.Vec.push t.deps (.Key {map := m, key} cell)
          Result.ok
            (core.result.Result.Ok (CcfKv.engine.Output.Previous version), {t with deps}))
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ (pointWrites encode after).Perm expected.1.normal.writes
          ∧ List.Forall₂ DependencyOrderEq (pointDeps encode history.index after)
              expected.1.normal.deps
          ∧ pointKeepsContext t after
          ∧ PendingSorted after.pending.val
          ∧ NativeDepsFromViews encode history.index after
          ∧ DepsPinsInViews after
          ∧ ModelDepsFromViews expected.1) := by
  let addr : CcfKv.engine.Address := {map := m, key}
  have hLocalCell : find (encodeImage encode (pinImage history.index addr.map view.local))
      (encAddr encode addr).2 = find model.data (encAddr encode addr) := by
    rw [lookup_perm hLocal (unique_of_perm hLocal.symm hLocalUnique), image_key]; rfl
  apply WP.spec_bind
    (read_cell_with_lookup encode inj history view.local addr model.data hLocalCell live.1
      space)
  intro cell hc
  have he : find model.data (encode m.val, encode key.val) =
      (cell.map byteCell).map (encodeCell encode) := by
    change cell.map (encodeCell encode ∘ byteCell) =
      find model.data (encode m.val, encode key.val) at hc
    simpa only [Option.map_map, Function.comp_def] using hc.symm
  have finish (deps : alloc.vec.Vec CcfKv.engine.Dependency)
      (hval : deps.val = t.deps.val ++ [.Key addr cell])
      (hd : pointDeps encode history.index {t with deps} = encodeDependency encode (byteDependency history.index (.Key addr cell)) :: pointDeps encode history.index t) :
      List.Forall₂ DependencyOrderEq (pointDeps encode history.index {t with deps})
        (.key (encode m.val, encode key.val) (find model.data (encode m.val, encode key.val)) :: model.normal.deps)
      ∧ NativeDepsFromViews encode history.index {t with deps}
      ∧ DepsPinsInViews {t with deps}
      ∧ ModelDepsFromViews {model with normal := recordOp model.data model.normal (.previous (encode m.val, encode key.val) (previousAt model.data (encode m.val, encode key.val)))} := by
    refine ⟨?_, ?_, ?_, ?_⟩
    · rw [hd, he]
      exact .cons (.key _ _) hDeps
    · intro d hm
      rw [hd] at hm
      rcases List.mem_cons.mp hm with rfl | old
      · trivial
      · exact hNativeOrig d old
    · intro mp pin hmem
      change CcfKv.engine.Dependency.Map mp pin ∈ deps.val at hmem
      rw [hval, List.mem_append, List.mem_singleton] at hmem
      rcases hmem with hold | hnew
      · exact hDepsPins mp pin hold
      · cases hnew
    · intro d hm
      change d ∈ _ :: model.normal.deps at hm
      rcases List.mem_cons.mp hm with rfl | old
      · trivial
      · exact hModelOrig d old
  cases cell <;>
    (simp only [CcfKv.engine.cell_version, bind_ok];
      apply WP.spec_bind (deps_push encode history.index t _ room);
      intro deps ⟨hval, hd⟩;
      have hf := finish deps hval hd;
      rw [WP.spec_ok];
      refine ⟨?_, hWrites, hf.1, rfl, hSorted, hf.2.1, hf.2.2.1, hf.2.2.2⟩;
      simp [pointOutput, PointOperation.model, executeOperation, previousAt, he, encodeCell, byteCell])

private theorem point_write (encode : List U8 → String) (inj : Function.Injective encode)
    (index : CellIndex)
    (t : CcfKv.engine.Tx) (model : Tx) (m key : CcfKv.engine.Bytes)
    (value : Option CcfKv.engine.Bytes)
    (hWrites : (pointWrites encode t).Perm model.normal.writes)
    (hSorted : PendingSorted t.pending.val)
    (hDeps : List.Forall₂ DependencyOrderEq (pointDeps encode index t) model.normal.deps)
    (hNativeOrig : NativeDepsFromViews encode index t)
    (hDepsPins : DepsPinsInViews t)
    (hModelOrig : ModelDepsFromViews model)
    (room : t.pending.val.length < Usize.max)
    : let expected :=
        executeOperation model ((PointOperation.write key value).model encode m)
      WP.spec
        (do
          let w ← CcfKv.engine.Write.from_option value
          let pending ← CcfKv.engine.stage_write t.pending {map := m, key} w
          Result.ok (core.result.Result.Ok CcfKv.engine.Output.Unit, {t with pending}))
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ (pointWrites encode after).Perm expected.1.normal.writes
          ∧ List.Forall₂ DependencyOrderEq (pointDeps encode index after)
              expected.1.normal.deps
          ∧ pointKeepsContext t after
          ∧ PendingSorted after.pending.val
          ∧ NativeDepsFromViews encode index after
          ∧ DepsPinsInViews after
          ∧ ModelDepsFromViews expected.1) := by
  cases value <;>
    (simp only [CcfKv.engine.Write.from_option, bind_ok];
      apply WP.spec_bind (stage_key_write encode inj t {map := m, key} _
        model.normal.writes hWrites hSorted room);
      intro pending hp;
      rw [WP.spec_ok];
      exact ⟨rfl, hp.1, hDeps, rfl, hp.2.1, hNativeOrig, hDepsPins, hModelOrig⟩)

/-- An active point operation observes the model result and preserves the related writes and dependencies. -/
theorem operate_point_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (history : CcfKv.engine.History)
    (t : CcfKv.engine.Tx) (model : Tx) (m : CcfKv.engine.Bytes) (op : PointOperation)
    (view : GlobalView) (hPhase : t.phase = .Active)
    (hView : find model.globalViews (encode m.val) = some view)
    (hPinned
      : ViewsOrderEq (modelPinnedViews model.globalViews)
          (rustPinnedViews encode history.index t.views))
    (hLocal : image view.current.data (encode m.val) = image model.data (encode m.val))
    (hLocalUnique : Kv.Properties.Unique (image model.data (encode m.val)))
    (hGlobalUnique : Kv.Properties.Unique (image view.frame.data (encode m.val)))
    (hWrites : (pointWrites encode t).Perm model.normal.writes)
    (hSorted : PendingSorted t.pending.val)
    (hDeps
      : List.Forall₂ DependencyOrderEq (pointDeps encode history.index t)
          model.normal.deps)
    (hNativeOrig : NativeDepsFromViews encode history.index t)
    (hDepsPins : DepsPinsInViews t)
    (hModelOrig : ModelDepsFromViews model)
    (room : op.fits encode t m)
    (live : ViewsLive history.index t.views)
    (space : op.indexRoom m)
    : let expected := executeOperation model (op.model encode m)
      WP.spec (CcfKv.engine.Tx.operate t history m op.rust)
        (fun (output, after) =>
          pointOutput encode output = some expected.2
          ∧ (pointWrites encode after).Perm expected.1.normal.writes
          ∧ List.Forall₂ DependencyOrderEq (pointDeps encode history.index after)
              expected.1.normal.deps
          ∧ pointKeepsContext t after
          ∧ PendingSorted after.pending.val
          ∧ NativeDepsFromViews encode history.index after
          ∧ DepsPinsInViews after
          ∧ ModelDepsFromViews expected.1) := by
  have hModelFound : find (modelPinnedViews model.globalViews) (encode m.val) =
      some (modelPinnedView (encode m.val) view) := by
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
  have hRelFound := hPinned.find (encode m.val)
  rw [hModelFound] at hRelFound
  have hActive : {t with phase := .Active} = t := by rw [← hPhase]
  simp only [CcfKv.engine.Tx.operate, hPhase, bind_ok]
  apply WP.spec_bind (view_lookup encode inj history.index t m live)
  intro found ⟨hf, alive⟩
  rw [← hf] at hRelFound
  cases found with
  | none => cases hRelFound
  | some native =>
      have hv : PinnedViewOrderEq (modelPinnedView (encode m.val) view)
          (rustPinnedView encode history.index m native) :=
        Option.rel_some_some.mp hRelFound
      have localLive := (alive native rfl).2
      have hl
          : (encodeImage encode (pinImage history.index m native.local)).Perm
              (image model.data (encode m.val)) :=
        hv.localImage.symm.trans (hLocal ▸ .rfl)
      have hg
          : (encodeImage encode (pinImage history.index m (native.global.getD native.local))).Perm
              (image ((find model.globalViews (encode m.val)).getD {frame := {}}).frame.data
                (encode m.val)) := by
        rw [hView]
        exact hv.globalImage.symm
      have hgU : Kv.Properties.Unique
          (image ((find model.globalViews (encode m.val)).getD {frame := {}}).frame.data
            (encode m.val)) := by
        rw [hView]
        exact hGlobalUnique
      cases op with
      | get key global =>
          simp only [PointOperation.rust]
          rw [← hPhase]
          simpa only [Bool.false_eq_true, ite_false]
            using (point_read encode inj history t model m key native global false hl
                    hLocalUnique hg hgU hWrites hSorted hDeps hNativeOrig hDepsPins
                    hModelOrig localLive space room)
      | has key global =>
          simp only [PointOperation.rust]
          rw [← hPhase]
          simpa only [core.option.Option.is_some, Bool.true_eq, ite_true]
            using (point_read encode inj history t model m key native global true hl
                    hLocalUnique hg hgU hWrites hSorted hDeps hNativeOrig hDepsPins
                    hModelOrig localLive space room)
      | previous key =>
          rw [← hPhase]
          exact point_previous encode inj history t model m key native hl hLocalUnique
            hWrites hSorted hDeps hNativeOrig hDepsPins hModelOrig localLive space room
      | write key value =>
          simpa only [PointOperation.rust, hPhase]
            using (point_write encode inj history.index t model m key value hWrites
                    hSorted hDeps hNativeOrig hDepsPins hModelOrig room)

private theorem reference_point_step (encode : List U8 → String) (m : CcfKv.engine.Bytes)
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
    (inj : Function.Injective encode) (s : CcfKv.engine.Store) (id : U64)
    (t : CcfKv.engine.Tx) (w : State) (sid : Nat) (model : Store) (tx : Tx)
    (m : CcfKv.engine.Bytes) (op : PointOperation) (view : GlobalView)
    (hNative : find s.txs.val id = some t)
    (hLookup : lookupTx w sid id.val = some (model, tx))
    (hNativePhase : t.phase = .Active) (hModelPhase : tx.phase = .active)
    (hSnap : tx.snapshot.isSome) (hView : find tx.globalViews (encode m.val) = some view)
    (hPinned
      : ViewsOrderEq (modelPinnedViews tx.globalViews)
          (rustPinnedViews encode s.history.index t.views))
    (hLocal : image view.current.data (encode m.val) = image tx.data (encode m.val))
    (hLocalUnique : Kv.Properties.Unique (image tx.data (encode m.val)))
    (hGlobalUnique : Kv.Properties.Unique (image view.frame.data (encode m.val)))
    (hWrites : (pointWrites encode t).Perm tx.normal.writes)
    (hSorted : PendingSorted t.pending.val)
    (hDeps
      : List.Forall₂ DependencyOrderEq (pointDeps encode s.history.index t)
          tx.normal.deps)
    (hNativeOrig : NativeDepsFromViews encode s.history.index t)
    (hDepsPins : DepsPinsInViews t)
    (hModelOrig : ModelDepsFromViews tx)
    (room : op.fits encode t m)
    (live : ViewsLive s.history.index t.views)
    (space : op.indexRoom m)
    : WP.spec (CcfKv.engine.Store.execute s (.Operate id m op.rust))
        (fun (output, after) =>
          ∃ modelAfter txAfter tAfter obs index,
            execute w (.operation sid id.val (op.model encode m)) = some (modelAfter, obs)
            ∧ pointOutput encode output = some obs
            ∧ modelAfter = {w with txs := Kv.Model.set w.txs id.val txAfter}
            ∧ (pointWrites encode tAfter).Perm txAfter.normal.writes
            ∧ List.Forall₂ DependencyOrderEq (pointDeps encode s.history.index tAfter)
                txAfter.normal.deps
            ∧ pointKeepsContext t tAfter
            ∧ PendingSorted tAfter.pending.val
            ∧ NativeDepsFromViews encode s.history.index tAfter
            ∧ DepsPinsInViews tAfter
            ∧ ModelDepsFromViews txAfter
            ∧ after.history = s.history
            ∧ s.txs.val[index]? = some (id, t)
            ∧ after.txs.val = s.txs.val.set index (id, tAfter)) := by
  have hStep := reference_point_step encode m op w sid id.val model tx hLookup hModelPhase hSnap
    (by simp [hView])
  unfold CcfKv.engine.Store.execute
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
        let (out, next) ← CcfKv.engine.Tx.operate t s.history m op.rust
        Result.ok (out, {s with txs := back (id, next)})) _
      apply WP.spec_bind
        (operate_point_matches_model encode inj s.history t tx m op view hNativePhase
          hView hPinned hLocal hLocalUnique hGlobalUnique hWrites hSorted hDeps
          hNativeOrig hDepsPins hModelOrig room live space)
      rintro ⟨out, next⟩ ⟨ho, hw, hd, hkeep, hso, hno, hdp, hmo⟩
      have hupdate : (back (id, next)).val = s.txs.val.set i.val (id, next) := by
        rw [hback.2]
        exact alloc.vec.Vec.set_val_eq _ _ _
      change WP.spec (Result.ok (out, ({s with txs := back (id, next)} : CcfKv.engine.Store))) _
      rw [WP.spec_ok]
      let expected := executeOperation tx (op.model encode m)
      exact ⟨
        {w with txs := Kv.Model.set w.txs id.val expected.1},
        expected.1,
        next,
        expected.2,
        i.val,
        hStep,
        ho,
        rfl,
        hw,
        hd,
        hkeep,
        hso,
        hno,
        hdp,
        hmo,
        rfl,
        hrow,
        hupdate
      ⟩

end KvRust
