-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.OrderEquivalence
public import KvRust.Point
public import KvRust.Range

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private abbrev Bytes := Spike.engine.Bytes
private abbrev Entries := Spike.engine.Assoc Bytes Bytes
private abbrev WriteRow := Spike.engine.Address × Spike.engine.Write

local instance : DecidableEq Spike.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

/-- Read the encoded keys and values of an extracted scan or range. -/
def modelEntries (encode : List U8 → String)
    (rows : alloc.vec.Vec (Spike.engine.Bytes × Spike.engine.Bytes))
    : Assoc String String :=
  rows.val.map fun (k, v) => (encode (alloc.vec.Vec.val k), encode (alloc.vec.Vec.val v))

private def mapWrites (encode : List U8 → String) (m : Bytes) (rows : List WriteRow)
    : Assoc String (Option String) :=
  rows.filterMap
    fun (a, w) =>
      if a.map = m then
        some (encode (alloc.vec.Vec.val a.key), encWrite encode w)
      else
        none

private theorem map_writes_append (encode : List U8 → String) (m : Bytes)
    (a b : List WriteRow)
    : mapWrites encode m (a ++ b) = mapWrites encode m a ++ mapWrites encode m b := by
  simp [mapWrites]

private theorem map_writes_proj (encode : List U8 → String)
    (inj : Function.Injective encode) (m : Bytes) (t : Spike.engine.Tx)
    : mapWrites encode m t.pending.val
      = (pointWrites encode t).filterMap
          fun (a, v) =>
            if a.1 = encode (alloc.vec.Vec.val m) then some (a.2, v) else none := by
  rw [pending_projection]
  simp only [mapWrites, List.filterMap_map]
  apply List.filterMap_congr
  rintro ⟨a, w⟩ _
  have he : encode (alloc.vec.Vec.val a.map) = encode (alloc.vec.Vec.val m) ↔ a.map = m :=
    ⟨fun h => alloc.vec.Vec.ext _ _ (inj h), fun h => congrArg (encode ∘ alloc.vec.Vec.val) h⟩
  simp [encAddr, encodeAddr, byteAddr, he]

private theorem scan_put (encode : List U8 → String) (inj : Function.Injective encode)
    (rows : Entries) (key value : Bytes) (room : rows.val.length < Usize.max)
    : WP.spec
        (Spike.engine.Assoc.set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Bytes.Insts.CoreCloneClone
          rows key value)
        (fun out =>
          modelEntries encode out
            = Kv.Model.set (modelEntries encode rows) (encode (alloc.vec.Vec.val key))
                (encode (alloc.vec.Vec.val value))
          ∧ out.val.length ≤ rows.val.length + 1) := by
  apply WP.spec_mono (assoc_set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Bytes.Insts.CoreCloneClone rows key value
    (fun a => key_same a key) clone_bytes clone_bytes room)
  intro out h
  have hi : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  constructor
  · unfold modelEntries
    rw [h]
    exact (set_projected rows.val key value _ (encode ∘ alloc.vec.Vec.val) hi).symm
  · rw [h, Kv.Model.set, List.length_cons]
    exact Nat.succ_le_succ (List.length_filter_le _ _)

private theorem scan_remove (encode : List U8 → String) (inj : Function.Injective encode)
    (rows : Entries) (key : Bytes)
    : WP.spec
        (Spike.engine.Assoc.erase Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Bytes.Insts.CoreCloneClone
          rows key)
        (fun out =>
          modelEntries encode out
            = erase (modelEntries encode rows) (encode (alloc.vec.Vec.val key))
          ∧ out.val.length ≤ rows.val.length) := by
  apply WP.spec_mono (assoc_erase Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Bytes.Insts.CoreCloneClone rows key
    (fun a => key_same a key) clone_bytes clone_bytes)
  intro out h
  have hi : Function.Injective (encode ∘ alloc.vec.Vec.val (α := U8)) :=
    inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  constructor
  · unfold modelEntries
    rw [h]
    exact (erase_projected rows.val key _ (encode ∘ alloc.vec.Vec.val) hi).symm
  · rw [h, erase]
    exact List.length_filter_le _ _

private theorem scan_overlay (encode : List U8 → String) (inj : Function.Injective encode)
    (m : Bytes) (pending : alloc.vec.Vec WriteRow) (base : Entries)
    (room : base.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Tx.scan_loop pending m base (alloc.vec.Vec.len pending))
        (fun r =>
          modelEntries encode r
            = writeValues (modelEntries encode base) (mapWrites encode m pending.val)
          ∧ r.val.length ≤ base.val.length + pending.val.length) := by
  let expected := writeValues (modelEntries encode base) (mapWrites encode m pending.val)
  let cap := base.val.length + pending.val.length
  unfold Spike.engine.Tx.scan_loop
  apply loop.spec_decr_nat (fun (p : Entries × Usize) => p.2.val)
    (fun (rows, i) =>
      i.val ≤ pending.val.length
      ∧ rows.val.length + i.val ≤ cap
      ∧ writeValues (modelEntries encode rows)
          (mapWrites encode m (pending.val.take i.val))
        = expected) _ _ _
  · rintro ⟨rows, i⟩ ⟨hi, hcap, hrows⟩
    dsimp only at hi hcap hrows ⊢
    unfold Spike.engine.Tx.scan_loop.body
    have hzero : (0#usize : Usize).val = 0 := rfl
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : (0#usize : Usize) < i
    · rw [ite_eq_left h]
      have hpos : 0 < i.val := h
      have hroom : rows.val.length < Usize.max := by omega
      apply WP.spec_bind (Usize.sub_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have hj' : i.val = j.val + 1 := by omega
      have hb : j.val < pending.val.length := by omega
      rw [alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending j hb)
      rintro ⟨a, w⟩ har
      have hfold : writeValues
          (writeValues (modelEntries encode rows) (mapWrites encode m [(a, w)]))
          (mapWrites encode m (pending.val.take j.val)) = expected := by
        have hs : pending.val.take i.val = pending.val.take j.val ++ [(a, w)] := by
          rw [hj', List.take_succ_eq_append_getElem hb, ← har]
        simpa only [hs, map_writes_append, writeValues, List.foldr_append] using hrows
      have hcont (out : Entries)
          (ho : modelEntries encode out =
            writeValues (modelEntries encode rows) (mapWrites encode m [(a, w)]))
          (hn : out.val.length ≤ rows.val.length + 1) :
          j.val ≤ pending.val.length ∧ out.val.length + j.val ≤ cap ∧
            writeValues (modelEntries encode out)
              (mapWrites encode m (pending.val.take j.val)) = expected ∧ j.val < i.val :=
        ⟨by omega, by omega, ho ▸ hfold, by omega⟩
      by_cases hm : a.map = m
      · cases w with
        | Put v =>
            simp [key_same, hm, clone_bytes]
            apply WP.spec_bind (scan_put encode inj rows a.key v hroom)
            intro out ho
            rw [WP.spec_ok]
            exact hcont out
              (by simpa [mapWrites, hm, writeValues, encWrite, encodeValue] using ho.1)
              ho.2
        | Remove =>
            simp [key_same, hm]
            apply WP.spec_bind (scan_remove encode inj rows a.key)
            intro out ho
            rw [WP.spec_ok]
            exact hcont out
              (by simpa [mapWrites, hm, writeValues, encWrite] using ho.1)
              (by have := ho.2; omega)
      · have he := hcont rows (by simp [mapWrites, hm, writeValues]) (by omega)
        cases w <;> simpa [key_same, hm] using he
    · rw [ite_eq_right h, WP.spec_ok]
      have hz : i.val = 0 := by have hn : ¬0 < i.val := h; omega
      exact ⟨by simpa [hz, mapWrites, writeValues, expected] using hrows, by omega⟩
  · simp [cap, expected]

/-- The native scan includes this map's overlay and records the committed image as a dependency. -/
theorem scan_matches_model (encode : List U8 → String) (inj : Function.Injective encode)
    (history : Spike.engine.History)
    (t : Spike.engine.Tx) (m : Spike.engine.Bytes) (view : Spike.engine.View) (tx : Tx)
    (hLocal
      : encodeImage encode (pinImage history.index m view.local)
        = image tx.data (encode (alloc.vec.Vec.val m)))
    (live : PinLive history.index view.local)
    (valid : IndexValid history.index)
    (mapRoom : 2 * (8 + m.val.length) ≤ Usize.max)
    (space : PinScanRoom history.index view.local)
    (hWrites : pointWrites encode t = tx.normal.writes)
    (hDeps : pointDeps encode history.index t = tx.normal.deps)
    (room : t.deps.val.length < Usize.max)
    (rowsRoom
      : (pinImage history.index m view.local).length + t.pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Tx.scan history t.pending t.deps m view)
        (fun (rows, deps) =>
          let next := {t with deps}
          deps.val = t.deps.val ++ [.Map m view.local]
          ∧ modelEntries encode rows
            = scanAt tx.data tx.normal.writes (encode (alloc.vec.Vec.val m))
          ∧ pointWrites encode next = tx.normal.writes
          ∧ pointDeps encode history.index next
            = .map (encode (alloc.vec.Vec.val m))
                (image tx.data (encode (alloc.vec.Vec.val m)))
              :: tx.normal.deps
          ∧ rows.val.length
            ≤ (pinImage history.index m view.local).length + t.pending.val.length) := by
  simp only [Spike.engine.Tx.scan, clone_bytes, clone_pin, bind_ok]
  apply WP.spec_bind (deps_push encode history.index t (.Map m view.local) room)
  intro deps ⟨hdepsVal, hd⟩
  apply WP.spec_bind
    (pin_entries_refines history m view.local live valid mapRoom space)
  intro base hBase
  have hlen : base.val.length = (pinImage history.index m view.local).length := by
    have h1 := congrArg List.length hBase
    simpa [List.length_map] using h1
  apply WP.spec_bind
    (scan_overlay encode inj m t.pending base (by simpa [hlen] using rowsRoom))
  intro out ho
  have hbase : modelEntries encode base =
      (image tx.data (encode (alloc.vec.Vec.val m))).map fun (k, c) => (k, c.value) := by
    rw [← hLocal]
    unfold modelEntries
    have hmap : base.val.map (fun (k, v) => (encode k.val, encode v.val)) =
        (base.val.map (fun (k, v) => (k.val, v.val))).map (fun (k, v) => (encode k, encode v)) := by
      simp [List.map_map, Function.comp_def]
    rw [hmap, hBase]
    simp [encodeImage, encodeCell, List.map_map, Function.comp_def]
  have hdep : pointDeps encode history.index {t with deps} = .map (encode (alloc.vec.Vec.val m))
      (image tx.data (encode (alloc.vec.Vec.val m))) :: tx.normal.deps := by
    simpa [byteDependency, encodeDependency, hLocal, hDeps] using hd
  rw [WP.spec_ok]
  exact ⟨
    hdepsVal,
    by simpa [scanAt, hbase, map_writes_proj encode inj m t, hWrites] using ho.1,
    hWrites,
    hdep,
    by simpa [hlen] using ho.2
  ⟩

/-- The extracted scan accepts a different pinned-row and staged-write order.
The new map dependency still binds the complete pinned cells. -/
theorem scan_by_contents_matches (encode : List U8 → String)
    (inj : Function.Injective encode) (history : Spike.engine.History)
    (t : Spike.engine.Tx) (m : Spike.engine.Bytes) (view : Spike.engine.View) (tx : Tx)
    (localImage
      : (encodeImage encode (pinImage history.index m view.local)).Perm
          (image tx.data (encode m.val)))
    (writes : (pointWrites encode t).Perm tx.normal.writes)
    (unique : Kv.Properties.Unique (image tx.data (encode m.val)))
    (sorted : PendingSorted t.pending.val) (live : PinLive history.index view.local)
    (valid : IndexValid history.index)
    (mapRoom : 2 * (8 + m.val.length) ≤ Usize.max)
    (space : PinScanRoom history.index view.local)
    (room : t.deps.val.length < Usize.max)
    (rowsRoom
      : (pinImage history.index m view.local).length + t.pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Tx.scan history t.pending t.deps m view)
        (fun (rows, deps) =>
          deps.val = t.deps.val ++ [.Map m view.local]
          ∧ (modelEntries encode rows).Perm
              (scanAt tx.data tx.normal.writes (encode m.val))
          ∧ pointDeps encode history.index {t with deps}
            = .map (encode m.val)
                (encodeImage encode (pinImage history.index m view.local))
              :: pointDeps encode history.index t
          ∧ rows.val.length
            ≤ (pinImage history.index m view.local).length + t.pending.val.length) := by
  let table := encode m.val
  let pinned := encodeImage encode (pinImage history.index m view.local)
  let representative : Tx := {tx with
    data := pinned.map (fun (key, cell) => ((table, key), cell))
    normal := {tx.normal with writes := pointWrites encode t, deps := pointDeps encode history.index t}}
  have same : image representative.data table = pinned := by
    change image (pinned.map (fun (key, cell) => ((table, key), cell))) table = pinned
    simp [image, List.filterMap_map]
  have projected : (image representative.data table).Perm (image tx.data table) :=
    same.symm ▸ localImage
  have validImage := unique_of_perm projected.symm unique
  have observed := scan_perm table projected writes validImage (sorted_pending_unique encode inj t sorted)
  apply WP.spec_mono
    (scan_matches_model encode inj history t m view representative same.symm
      live valid mapRoom space rfl rfl room rowsRoom)
  rintro ⟨rows, deps⟩ ⟨hdepsVal, read, _, dependency, bound⟩
  refine ⟨hdepsVal, ?_, ?_, bound⟩
  · rw [read]
    exact observed
  · change pointDeps encode history.index {t with deps} =
      .map table (image representative.data table) :: pointDeps encode history.index t at dependency
    rw [same] at dependency
    exact dependency

private theorem clear_writes_fold (m : String)
    (entries : Assoc String String) {a b : Pending} (related : a.Perm b)
    : (entries.foldl (removeEntry m) a).Perm (entries.foldl (removeEntry m) b) := by
  induction entries generalizing a b with
  | nil => exact related
  | cons row rest ih => exact ih (set_perm related (m, row.1) none)

private theorem clear_rows (encode : List U8 → String)
    (inj : Function.Injective encode) (t : Spike.engine.Tx) (m : Bytes)
    (entries : Entries) (sorted : PendingSorted t.pending.val)
    (room : t.pending.val.length + entries.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Tx.operate_loop t.pending m entries 0#usize)
        (fun next =>
          (pointWrites encode {t with pending := next}).Perm
            ((modelEntries encode entries).foldl (removeEntry (encode m.val))
              (pointWrites encode t))
          ∧ PendingSorted next.val) := by
  let project := fun (p : Bytes × Bytes) =>
    (encode (alloc.vec.Vec.val p.1), encode (alloc.vec.Vec.val p.2))
  let table := encode m.val
  let remaining := fun (p : alloc.vec.Vec (Spike.engine.Address × Spike.engine.Write)) (i : Nat) =>
    ((entries.val.drop i).map project).foldl (removeEntry table)
      (pointWrites encode {t with pending := p})
  unfold Spike.engine.Tx.operate_loop
  apply loop.spec_decr_nat
    (fun (p : alloc.vec.Vec (Spike.engine.Address × Spike.engine.Write) × Usize) =>
      entries.val.length - p.2.val)
    (fun (s, i) =>
      i.val ≤ entries.val.length
      ∧ s.val.length + (entries.val.length - i.val) ≤ Usize.max
      ∧ (remaining s i.val).Perm (remaining t.pending 0)
      ∧ PendingSorted s.val)
    _ _ _
  · rintro ⟨s, i⟩ ⟨hi, hsize, hs, hsOrder⟩
    dsimp only at hi hsize hs hsOrder ⊢
    unfold Spike.engine.Tx.operate_loop.body
    have hlen : (alloc.vec.Vec.len entries).val = entries.val.length := alloc.vec.Vec.len_val _
    have hcap := alloc.vec.Vec.len_ineq entries
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len entries
    · have hb : i.val < entries.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, clone_bytes, bind_ok, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec entries i hb)
      rintro ⟨key, value⟩ hr
      change WP.spec (do
        let key' ← Spike.engine.Bytes.Insts.CoreCloneClone.clone key
        let pending ← Spike.engine.stage_write s {map := m, key := key'} .Remove
        let j ← i + 1#usize
        Result.ok (ControlFlow.cont (pending, j))) _
      simp only [clone_bytes, bind_ok]
      have hroom : s.val.length < Usize.max := by omega
      let updated := removeEntry table (pointWrites encode {t with pending := s}) (project (key, value))
      apply WP.spec_bind (stage_key_write encode inj {t with pending := s}
        {map := m, key} .Remove _ .rfl hsOrder hroom)
      intro pending ⟨related, hpOrder, hpBound⟩
      dsimp only at hpBound
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have hj' : j.val = i.val + 1 := by omega
      have hdrop : entries.val.drop i.val = (key, value) :: entries.val.drop j.val := by
        rw [hj', List.drop_eq_getElem_cons hb, ← hr]
      rw [WP.spec_ok]
      have same := clear_writes_fold table ((entries.val.drop j.val).map project) related
      have hFold : (remaining pending j.val).Perm (remaining t.pending 0) := by
        change (remaining pending j.val).Perm
          (((entries.val.drop j.val).map project).foldl (removeEntry table) updated) at same
        simp only [remaining, hdrop, List.map_cons, List.foldl_cons] at hs
        exact List.Perm.trans same hs
      exact ⟨⟨show j.val ≤ entries.val.length by omega,
        show pending.val.length + (entries.val.length - j.val) ≤ Usize.max by omega,
        hFold, hpOrder⟩, show entries.val.length - j.val < entries.val.length - i.val by omega⟩
    · have hb : entries.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      refine ⟨?_, hsOrder⟩
      simpa only [remaining, modelEntries, project, List.drop_zero, List.drop_eq_nil_of_le hb,
        List.map_nil, List.foldl_nil] using hs
  · change 0 ≤ entries.val.length ∧
      t.pending.val.length + (entries.val.length - 0) ≤ Usize.max ∧
      (remaining t.pending 0).Perm (remaining t.pending 0) ∧
      PendingSorted t.pending.val
    exact ⟨Nat.zero_le _, room, .rfl, sorted⟩

private theorem clear_reference (entries : Assoc String String) (t : Tx) (m : String)
    : let clear :=
        entries.foldl
          (fun (acc : Tx) (k, _) =>
            {acc with normal := recordOp acc.data acc.normal (.write (m, k) none)}) t
      clear.normal.writes = entries.foldl (removeEntry m) t.normal.writes
      ∧ clear.normal.deps = t.normal.deps := by
  induction entries generalizing t with
  | nil => simp
  | cons a rest ih =>
      obtain ⟨key, value⟩ := a
      simpa [recordOp, needs, stage, removeEntry]
        using ih {t with normal := recordOp t.data t.normal (.write (m, key) none)}

/-- Operations whose result or effect is determined by the whole visible map. -/
inductive ScanOperation where
  | scan
  | size
  | clear
  | range (lower upper : Option Spike.engine.Bytes)

/-- Map-level output observations of the native engine. -/
def scanOutput (encode : List U8 → String)
    : core.result.Result Spike.engine.Output Spike.engine.Error → Option Output
  | .Ok (.Entries entries) => some (.entries (modelEntries encode entries))
  | .Ok (.Size size) => some (.size size.val)
  | .Ok .Unit => some .unit
  | _ => none

/-- Embed a map-level operation into an extracted action. -/
def ScanOperation.rust : ScanOperation → Spike.engine.Operation
  | .scan => .Scan
  | .size => .Size
  | .clear => .Clear
  | .range lower upper => .Range lower upper

/-- Embed a map-level operation into the reference model. -/
def ScanOperation.model (encode : List U8 → String) (m : String)
    : ScanOperation → Operation
  | .scan => .scan m
  | .size => .size m
  | .clear => .clear m
  | .range lower upper => .range m (encodeBound encode lower) (encodeBound encode upper)

/-- Lookup commutes with the map-dependent projection of model views. -/
theorem lookup_model_view (rows : Assoc String GlobalView) (m : String) (v : GlobalView)
    (h : find rows m = some v)
    : find (modelPinnedViews rows) m = some (modelPinnedView m v) := by
  induction rows with
  | nil => simp [find] at h
  | cons row rest ih =>
      obtain ⟨key, view⟩ := row
      by_cases hk : key = m
      · subst key
        simp [find] at h
        subst view
        simp [modelPinnedViews, find]
      · simp [find, hk, modelPinnedViews] at h ⊢
        exact ih h

private theorem compare_le_zero_iff {encode : List U8 → String}
    (order : PreservesByteOrder encode) (a b : Bytes)
    : decide (byteOrder a.val b.val ≤ 0#i8) = decide (encode a.val ≤ encode b.val) :=
  decide_eq_decide.mpr (byteOrder_le_encoded order a.val b.val)

private theorem compare_lt_zero_iff {encode : List U8 → String}
    (order : PreservesByteOrder encode) (a b : Bytes)
    : decide (byteOrder a.val b.val < 0#i8) = decide (encode a.val < encode b.val) :=
  decide_eq_decide.mpr (byteOrder_lt_encoded order a.val b.val)

private theorem bytes_compare_ok (a b : Bytes)
    : Spike.engine.Bytes.compare a b = .ok (byteOrder a.val b.val) := by
  have h := bytes_compare a b
  cases heq : Spike.engine.Bytes.compare a b using Result.cases with
  | ret cmp => simpa [heq] using h
  | vis _ _ => simp [heq] at h
  | div => simp [heq] at h

private theorem pin_range_refines {encode : List U8 → String}
    (inj : Function.Injective encode) (order : PreservesByteOrder encode)
    (history : Spike.engine.History) (m : Bytes) (pin : Spike.engine.PinnedImage)
    (visible : Assoc String String) (lower upper : Option Bytes)
    (unique : Kv.Properties.Unique visible)
    (related
      : ((encodeImage encode (pinImage history.index m pin)).map
          (fun (k, c) => (k, c.value))).Perm
          visible)
    (live : PinLive history.index pin) (valid : IndexValid history.index)
    (mapRoom : 2 * (8 + m.val.length) ≤ Usize.max)
    (space : PinScanRoom history.index pin)
    : WP.spec (Spike.engine.PinnedImage.range pin history m lower upper)
        (fun out =>
          modelEntries encode out
          = (visible.filter
              (fun row =>
                inRange (encodeBound encode lower) (encodeBound encode upper)
                  row.1)).mergeSort
              (fun a b => decide (a.1 ≤ b.1))) := by
  unfold Spike.engine.PinnedImage.range
  cases pin with
  | Empty =>
      have hnil : visible = [] := by
        have := related.length_eq
        simp only [pinImage, encodeImage, List.map_nil, List.length_nil] at this
        exact List.eq_nil_of_length_eq_zero this.symm
      simp [alloc.vec.Vec.new, modelEntries, hnil]
  | Recovered rows =>
      have hrel : (encodeRangeEntries encode Spike.engine.Cell.value rows.val).Perm visible := by
        have heq : encodeRangeEntries encode Spike.engine.Cell.value rows.val =
            (encodeImage encode (pinImage history.index m (.Recovered rows))).map
              (fun (k, c) => (k, c.value)) := by
          simp [encodeRangeEntries, encodeImage, pinImage, byteImage, List.map_map,
            Function.comp_def, encodeCell, byteCell]
        rwa [heq]
      apply WP.spec_mono (ordered_range_by_contents order
        Spike.engine.Cell.Insts.Ccf_kv_spikeEngineRangeValue Spike.engine.Cell.value
        (fun _ => rfl) rows visible lower upper unique hrel)
      intro out hout
      simpa [modelEntries, encodeEntries] using hout
  | Root root =>
      unfold Spike.engine.indexed_range
      apply WP.spec_bind
        (index_scan_map_refines history.index root (indexRows history.index root) m
          live valid mapRoom space)
      intro links ⟨hlen, hload⟩
      let selected := (indexRows history.index root).filter fun r => decide (r.1.map.val = m.val)
      let encSel : Assoc String String :=
        selected.map fun (a, c) => (encode a.key.val, encode c.value.val)
      let pred : String × String → Bool :=
        fun row => inRange (encodeBound encode lower) (encodeBound encode upper) row.1
      change links.val.length = selected.length at hlen
      change ∀ (i : Nat) link, links.val[i]? = some link →
        ∃ entry, selected[i]? = some entry ∧
          WP.spec (Spike.kv_index.AddressIndex.scan_row history.index link) (· = entry) at hload
      unfold Spike.engine.indexed_range_loop
      have hcap := alloc.vec.Vec.len_ineq links
      have hlenV : (alloc.vec.Vec.len links).val = links.val.length := alloc.vec.Vec.len_val links
      have hone : (1#usize : Usize).val = 1 := rfl
      apply WP.spec_mono (P₀ := fun out =>
        modelEntries encode out = encSel.filter pred)
      · apply loop.spec_decr_nat
          (fun (_, i) => selected.length - (i : Usize).val)
          (fun (out, i) =>
            i.val ≤ selected.length
            ∧ out.val.length ≤ i.val
            ∧ modelEntries encode out = (encSel.take i.val).filter pred)
          _ _ _
        · rintro ⟨out, i⟩ ⟨hi, houtLen, hinv⟩
          dsimp only at hi houtLen hinv ⊢
          unfold Spike.engine.indexed_range_loop.body
          by_cases run : i < alloc.vec.Vec.len links
          · have hlt : i.val < links.val.length := by rwa [← hlenV]
            have his : i.val < selected.length := by omega
            rw [ite_eq_left run, alloc.vec.Vec.index_slice_index]
            apply WP.spec_bind (alloc.vec.Vec.index_usize_spec links i hlt)
            intro link hlink
            obtain ⟨⟨a, c⟩, hat, hread⟩ := hload i.val link
              ((List.getElem?_eq_getElem hlt).trans (congrArg some hlink.symm))
            apply WP.spec_bind hread
            rintro ⟨a', c'⟩ heq
            obtain ⟨ha', hc'⟩ : a' = a ∧ c' = c := Prod.mk.inj heq
            subst ha' hc'
            have hOnMap : a'.map.val = m.val := by
              have hmem : (a', c') ∈ selected := List.mem_of_getElem? hat
              exact of_decide_eq_true (List.mem_filter.mp hmem).2
            change WP.spec (do
              let out1 ← Spike.engine.append_range_row out a' c' m lower upper
              let i1 ← i + 1#usize
              Result.ok (ControlFlow.cont (out1, i1))) _
            have happend : WP.spec (Spike.engine.append_range_row out a' c' m lower upper)
                (fun out1 =>
                  out1.val.length ≤ out.val.length + 1
                  ∧ modelEntries encode out1 =
                      modelEntries encode out ++
                      ([(encode a'.key.val, encode c'.value.val)].filter pred)) := by
              unfold Spike.engine.append_range_row
              simp only [bytes_same, hOnMap, decide_true, bind_ok, ite_true]
              have hlo : WP.spec (match lower with
                  | none => Result.ok true
                  | some l => do
                      let i1 ← Spike.engine.Bytes.compare l a'.key
                      Result.ok (decide (i1 ≤ 0#i8)))
                  (fun b => b = (encodeBound encode lower).all (fun l => decide (l ≤ encode a'.key.val))) := by
                cases lower with
                | none => simp [encodeBound]
                | some l =>
                    simp only [bytes_compare_ok, bind_ok, WP.spec_ok, encodeBound]
                    exact compare_le_zero_iff order l a'.key
              have hhi : WP.spec (match upper with
                  | none => Result.ok true
                  | some u => do
                      let i1 ← Spike.engine.Bytes.compare a'.key u
                      Result.ok (decide (i1 < 0#i8)))
                  (fun b => b = (encodeBound encode upper).all (fun u => decide (encode a'.key.val < u))) := by
                cases upper with
                | none => simp [encodeBound]
                | some u =>
                    simp only [bytes_compare_ok, bind_ok, WP.spec_ok, encodeBound]
                    exact compare_lt_zero_iff order a'.key u
              apply WP.spec_bind hlo
              intro bLo hbLo
              apply WP.spec_bind hhi
              intro bHi hbHi
              have hpred : (bLo && bHi) = pred (encode a'.key.val, encode c'.value.val) := by
                rw [hbLo, hbHi]
                unfold pred inRange
                cases lower <;> cases upper <;> simp [encodeBound]
              cases bLo with
              | false =>
                  have hp : pred (encode a'.key.val, encode c'.value.val) = false := by
                    simpa using hpred.symm
                  simp [hp]
              | true =>
                  cases bHi with
                  | false =>
                      have hp : pred (encode a'.key.val, encode c'.value.val) = false := by
                        simpa using hpred.symm
                      simp [hp]
                  | true =>
                      have hp : pred (encode a'.key.val, encode c'.value.val) = true := by
                        simpa using hpred.symm
                      simp only [ite_true, clone_bytes, bind_ok]
                      apply WP.spec_mono
                        (alloc.vec.Vec.push_spec out (a'.key, c'.value) (by omega))
                      intro out1 hout1
                      refine ⟨
                        by rw [hout1, List.length_append, List.length_singleton],
                        ?_
                      ⟩
                      simp [modelEntries, hout1, hp]
            apply WP.spec_bind happend
            intro out1 ⟨hout1Len, hout1Eq⟩
            apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
            intro i1 hi1
            have hi1Val : i1.val = i.val + 1 := by omega
            have htake : encSel.take (i.val + 1) =
                encSel.take i.val ++ [(encode a'.key.val, encode c'.value.val)] := by
              unfold encSel
              rw [← List.map_take, List.take_add_one, hat]
              simp
            rw [WP.spec_ok]
            dsimp only
            refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
            rw [hout1Eq, hinv, hi1Val, htake, List.filter_append]
          · have hge : selected.length ≤ i.val := by rw [← hlen, ← hlenV]; exact Nat.le_of_not_gt run
            rw [ite_eq_right run, WP.spec_ok]
            have hgeEnc : encSel.length ≤ i.val := by simpa [encSel] using hge
            simpa [List.take_of_length_le hgeEnc] using hinv
        · simp [alloc.vec.Vec.new, modelEntries]
      · intro out hout
        rw [hout]
        have hencSelEq : encSel = (encodeImage encode (pinImage history.index m (.Root root))).map
            (fun (k, c) => (k, c.value)) := by
          unfold encSel selected pinImage
          have hproj : ∀ rows : CellRows,
              (rows.filter fun r => decide (r.1.map.val = m.val)).map
                (fun (a, c) => (encode a.key.val, encode c.value.val))
              = (encodeImage encode (image (indexedCellData rows) m.val)).map
                  (fun (k, c) => (k, c.value)) := by
            intro rows
            induction rows with
            | nil => rfl
            | cons row rest ih =>
                obtain ⟨a, c⟩ := row
                by_cases hm : a.map.val = m.val
                · simp [hm, indexedCellData, image, byteAddr, byteCell, encodeImage, encodeCell, ih]
                · simp [hm, indexedCellData, image, byteAddr, ih]
          exact hproj (indexRows history.index root)
        have hperm : (encSel.filter pred).Perm (visible.filter pred) := by
          rw [hencSelEq]
          exact related.filter pred
        have hsorted : (encSel.filter pred).Pairwise (fun a b => a.1 ≤ b.1) := by
          let dummyFrame : Spike.engine.Frame := {
            version := 0#u64
            data := root
            revisions := alloc.vec.Vec.new _
            births := alloc.vec.Vec.new _
            meta_live := true
          }
          have hms := modelFrame_image_sorted inj history.index dummyFrame live (encode m.val)
          have himgEq : image (modelFrame encode history.index dummyFrame).data (encode m.val) =
              encodeImage encode (pinImage history.index m (.Root root)) := by
            unfold modelFrame pinImage
            rw [← image_encoding encode inj]
          rw [himgEq] at hms
          have hselSort : encSel.Pairwise (fun a b => a.1 ≤ b.1) := by
            rw [hencSelEq]
            refine hms.map (fun (k, c) => (k, c.value)) ?_
            intro x y hxy
            obtain ⟨ka, kb, hka, hkb, hlt⟩ := hxy
            exact _root_.Std.le_of_lt (hka ▸ hkb ▸ (order ka kb).mp hlt)
          exact hselSort.filter pred
        let cmp : (String × String) → (String × String) → Bool := fun a b => decide (a.1 ≤ b.1)
        have hsort' : ((visible.filter pred).mergeSort cmp).Pairwise (fun a b => a.1 ≤ b.1) := by
          have hpw := List.pairwise_mergeSort (le := cmp)
            (fun a b c hab hbc =>
              decide_eq_true (_root_.Std.le_trans (of_decide_eq_true hab) (of_decide_eq_true hbc)))
            (fun a b => by
              rcases _root_.Std.le_total (a := a.1) (b := b.1) with h | h
              · simp [cmp, h]
              · simp [cmp, h])
            (visible.filter pred)
          exact hpw.imp fun h => of_decide_eq_true h
        have hm := List.mergeSort_perm (visible.filter pred) cmp
        apply List.Perm.eq_of_pairwise _ hsorted hsort' (hperm.trans hm.symm)
        intro a b ha hb hab hba
        have haV : a ∈ visible := List.mem_of_mem_filter (hperm.subset ha)
        have hbV : b ∈ visible := List.mem_of_mem_filter (hm.subset hb)
        have heqK : a.1 = b.1 := _root_.Std.le_antisymm hab hba
        have hnodup : (visible.map Prod.fst).Nodup := unique
        obtain ⟨ia, hia, haAt⟩ := List.getElem_of_mem haV
        obtain ⟨ib, hib, hbAt⟩ := List.getElem_of_mem hbV
        have hfin : (⟨ia, by simpa using hia⟩ : Fin (visible.map Prod.fst).length) =
            ⟨ib, by simpa using hib⟩ := by
          apply List.nodup_iff_injective_getElem.mp hnodup
          simp [haAt, hbAt, heqK]
        have hiEq : ia = ib := congrArg Fin.val hfin
        subst hiEq
        exact haAt.symm.trans hbAt

/-- An enabled scan, size, clear, or range agrees with the relaxed reference contract. -/
theorem operate_scan_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (order : PreservesByteOrder encode)
    (history : Spike.engine.History)
    (t : Spike.engine.Tx) (tx : Tx) (m : Spike.engine.Bytes) (op : ScanOperation)
    (view : GlobalView) (hPhase : t.phase = .Active)
    (hView : find tx.globalViews (encode (alloc.vec.Vec.val m)) = some view)
    (hPinned
      : ViewsOrderEq (modelPinnedViews tx.globalViews)
          (rustPinnedViews encode history.index t.views))
    (hLocal
      : image view.current.data (encode (alloc.vec.Vec.val m))
        = image tx.data (encode (alloc.vec.Vec.val m)))
    (hWrites : (pointWrites encode t).Perm tx.normal.writes)
    (hSorted : PendingSorted t.pending.val)
    (hDeps
      : List.Forall₂ DependencyOrderEq (pointDeps encode history.index t) tx.normal.deps)
    (hNativeOrig : NativeDepsFromViews encode history.index t)
    (hDepsPins : DepsPinsInViews t)
    (hModelOrig : ModelDepsFromViews tx)
    (room : t.deps.val.length < Usize.max)
    (rowsRoom
      : (image tx.data (encode (alloc.vec.Vec.val m))).length + t.pending.val.length
        ≤ Usize.max)
    (unique : Kv.Properties.Unique (image tx.data (encode (alloc.vec.Vec.val m))))
    (clearRoom
      : op = .clear
        → t.pending.val.length
            + (scanAt tx.data tx.normal.writes (encode (alloc.vec.Vec.val m))).length
          ≤ Usize.max)
    (live : ViewsLive history.index t.views)
    (valid : IndexValid history.index)
    (mapRoom : 2 * (8 + m.val.length) ≤ Usize.max)
    (space : ViewsScanRoom history.index t.views)
    : let expected := executeOperation tx (op.model encode (encode (alloc.vec.Vec.val m)))
      WP.spec (Spike.engine.Tx.operate t history m op.rust)
        (fun (output, after) =>
          (∃ obs,
            scanOutput encode output = some obs
            ∧ OutputMatches
                (.operation 0 0 (op.model encode (encode (alloc.vec.Vec.val m)))) obs
                expected.2)
          ∧ (pointWrites encode after).Perm expected.1.normal.writes
          ∧ List.Forall₂ DependencyOrderEq (pointDeps encode history.index after)
              expected.1.normal.deps
          ∧ pointKeepsContext t after
          ∧ PendingSorted after.pending.val
          ∧ NativeDepsFromViews encode history.index after
          ∧ DepsPinsInViews after
          ∧ ModelDepsFromViews expected.1) := by
  let mapName := encode (alloc.vec.Vec.val m)
  let visible := scanAt tx.data tx.normal.writes mapName
  have he := lookup_model_view tx.globalViews mapName view hView
  have hRelFound := hPinned.find mapName
  rw [he] at hRelFound
  have hActive : {t with phase := .Active} = t := by rw [← hPhase]
  simp only [Spike.engine.Tx.operate, hPhase, bind_ok]
  apply WP.spec_bind (view_lookup encode inj history.index t m live)
  intro found ⟨hf, alive⟩
  rw [← hf] at hRelFound
  cases found with
  | none => cases hRelFound
  | some native =>
      have hv : PinnedViewOrderEq (modelPinnedView mapName view)
          (rustPinnedView encode history.index m native) :=
        Option.rel_some_some.mp hRelFound
      have hl : (encodeImage encode (pinImage history.index m native.local)).Perm (image tx.data mapName) :=
        hv.localImage.symm.trans (hLocal ▸ .rfl)
      have hlen : (pinImage history.index m native.local).length = (image tx.data mapName).length := by
        simpa [encodeImage] using hl.length_eq
      have hNativeFound : find (rustPinnedViews encode history.index t.views) mapName =
          some (rustPinnedView encode history.index m native) := by
        simpa [mapName] using hf.symm
      have addNativeOrig (deps : alloc.vec.Vec Spike.engine.Dependency)
          (hd : pointDeps encode history.index {t with deps} =
            .map mapName (encodeImage encode (pinImage history.index m native.local)) :: pointDeps encode history.index t) :
          NativeDepsFromViews encode history.index {t with deps} := by
        intro d hm
        rw [hd] at hm
        rcases List.mem_cons.mp hm with rfl | old
        · exact ⟨rustPinnedView encode history.index m native, hNativeFound, rfl⟩
        · exact hNativeOrig d old
      have addDepsPins (deps : alloc.vec.Vec Spike.engine.Dependency)
          (hval : deps.val = t.deps.val ++ [.Map m native.local]) :
          DepsPinsInViews {t with deps} := by
        intro mp pin hmem
        change Spike.engine.Dependency.Map mp pin ∈ deps.val at hmem
        rw [hval, List.mem_append, List.mem_singleton] at hmem
        rcases hmem with hold | hnew
        · exact hDepsPins mp pin hold
        · injection hnew with hmEq hpEq
          exact ⟨(m, native), (alive native rfl).1, hmEq.symm, hpEq⟩
      have addModelOrig (deps : List (Dependency String String String))
          (hd : deps = .map mapName (image tx.data mapName) :: tx.normal.deps) :
          ∀ d ∈ deps, match d with
            | .key _ _ => True
            | .map k expected => ∃ gv, find tx.globalViews k = some gv ∧ expected = image gv.current.data k := by
        intro d hm
        rw [hd] at hm
        rcases List.mem_cons.mp hm with rfl | old
        · exact ⟨view, hView, hLocal.symm⟩
        · exact hModelOrig d old
      have hscan :=
        scan_by_contents_matches encode inj history t m native tx hl hWrites unique hSorted
          (alive native rfl).2.1 valid mapRoom (space (m, native) (alive native rfl).1).1 room
          (by simpa [hlen] using rowsRoom)
      have emptyTest : alloc.vec.Vec.is_empty t.pending
          = .ok (decide (t.pending.val = [])) := by
        change Result.ok (decide (t.pending.val.length = 0)) = _
        exact congrArg Result.ok (decide_eq_decide.mpr List.length_eq_zero_iff)
      cases op with
      | scan =>
          simp only [ScanOperation.rust]
          apply WP.spec_bind hscan
          rintro ⟨rows, deps⟩ ⟨hdepsVal, hr, hd, _⟩
          change WP.spec (Result.ok _) _
          rw [← hPhase, WP.spec_ok]
          refine ⟨⟨.entries (modelEntries encode rows), rfl, hr⟩, hWrites, ?_, rfl, hSorted,
            addNativeOrig deps hd, addDepsPins deps hdepsVal, addModelOrig _ rfl⟩
          change List.Forall₂ DependencyOrderEq (pointDeps encode history.index {t with deps})
            (.map mapName (image tx.data mapName) :: tx.normal.deps)
          rw [hd]
          exact .cons (.map mapName hl) hDeps
      | size =>
          simp only [ScanOperation.rust]
          change WP.spec (do
            let b1 ← alloc.vec.Vec.is_empty t.pending
            if b1 then
              let count ← Spike.engine.PinnedImage.size native.local history m
              let pi ← Spike.engine.PinnedImage.Insts.CoreCloneClone.clone native.local
              let v1 ← alloc.vec.Vec.push t.deps (.Map m pi)
              Result.ok (core.result.Result.Ok (Spike.engine.Output.Size count),
                {t with deps := v1, phase := .Active})
            else
              let (v1, v2) ← Spike.engine.Tx.scan history t.pending t.deps m native
              let i := alloc.vec.Vec.len v1
              Result.ok (core.result.Result.Ok (Spike.engine.Output.Size i),
                {t with deps := v2, phase := .Active})) _
          simp only [emptyTest, bind_ok]
          by_cases clean : t.pending.val = []
          · have noWrites : tx.normal.writes = [] := by
              have hlen0 : (pointWrites encode t).length = 0 := by
                simp [pointWrites, encodeWrites, byteWrites, clean]
              exact List.eq_nil_of_length_eq_zero (hWrites.length_eq.symm.trans hlen0)
            have hVisLen : visible.length = (pinImage history.index m native.local).length := by
              have hvEq : visible = (image tx.data mapName).map (fun (k, c) => (k, c.value)) := by
                simp [visible, scanAt, noWrites, writeValues]
              rw [hvEq, List.length_map, hlen]
            simp only [clean, decide_true, ite_true]
            apply WP.spec_bind
              (pin_size_refines history m native.local (alive native rfl).2.1 valid
                mapRoom (space (m, native) (alive native rfl).1).1)
            intro count hcount
            simp only [clone_pin, bind_ok]
            apply WP.spec_bind
              (deps_push encode history.index t (.Map m native.local) room)
            intro deps ⟨hdepsVal, updated⟩
            have hd : pointDeps encode history.index {t with deps} =
                .map mapName (encodeImage encode (pinImage history.index m native.local))
                :: pointDeps encode history.index t := by
              simpa [byteDependency, encodeDependency, mapName] using updated
            rw [← hPhase, WP.spec_ok]
            refine ⟨
              ⟨
                .size count.val,
                rfl,
                by
                  simp [OutputMatches, executeOperation, ScanOperation.model, hcount, ← hVisLen,
                    visible, mapName]
              ⟩,
              hWrites,
              ?_,
              rfl,
              hSorted,
              addNativeOrig deps hd,
              addDepsPins deps hdepsVal,
              addModelOrig _ rfl
            ⟩
            change List.Forall₂ DependencyOrderEq (pointDeps encode history.index {t with deps})
              (.map mapName (image tx.data mapName) :: tx.normal.deps)
            rw [hd]
            exact .cons (.map mapName hl) hDeps
          · simp only [clean, decide_false, Bool.false_eq_true, ite_false]
            apply WP.spec_bind hscan
            rintro ⟨rows, deps⟩ ⟨hdepsVal, hr, hd, _⟩
            have hcount : rows.val.length = visible.length := by
              simpa [modelEntries] using hr.length_eq
            change WP.spec (Result.ok _) _
            rw [← hPhase, WP.spec_ok]
            refine ⟨
              ⟨
                .size rows.val.length,
                rfl,
                by
                  simp [OutputMatches, executeOperation, ScanOperation.model, hcount, visible, mapName]
              ⟩,
              hWrites,
              ?_,
              rfl,
              hSorted,
              addNativeOrig deps hd,
              addDepsPins deps hdepsVal,
              addModelOrig _ rfl
            ⟩
            change List.Forall₂ DependencyOrderEq (pointDeps encode history.index {t with deps})
              (.map mapName (image tx.data mapName) :: tx.normal.deps)
            rw [hd]
            exact .cons (.map mapName hl) hDeps
      | clear =>
          simp only [ScanOperation.rust]
          apply WP.spec_bind hscan
          rintro ⟨rows, deps⟩ ⟨hdepsVal, hr, hd, _⟩
          have hcount : rows.val.length = visible.length := by
            simpa [modelEntries] using hr.length_eq
          have hspace : t.pending.val.length + rows.val.length ≤ Usize.max := by
            rw [hcount]
            exact clearRoom rfl
          change WP.spec (do
            let pending ← Spike.engine.Tx.operate_loop t.pending m rows 0#usize
            Result.ok (core.result.Result.Ok Spike.engine.Output.Unit,
              {t with pending, deps, phase := .Active})) _
          apply WP.spec_bind (clear_rows encode inj t m rows hSorted hspace)
          intro pending ⟨ho, hpOrder⟩
          let out : Spike.engine.Tx := {t with pending, deps, phase := .Active}
          have hcontext : pointKeepsContext t out := by
            simp [out, pointKeepsContext, ← hPhase]
          have hclear := clear_reference visible
            {tx with normal := recordOp tx.data tx.normal (.scan mapName visible)} mapName
          have hw'
              : (pointWrites encode out).Perm
                  (visible.foldl (removeEntry mapName) tx.normal.writes) :=
            List.Perm.trans ho
              (clear_entries_perm mapName hr hWrites (sorted_pending_unique encode inj t hSorted))
          have hDepEq : List.Forall₂ DependencyOrderEq (pointDeps encode history.index out)
              (.map mapName (image tx.data mapName) :: tx.normal.deps) := by
            change List.Forall₂ DependencyOrderEq (pointDeps encode history.index {t with deps}) _
            rw [hd]
            exact .cons (.map mapName hl) hDeps
          have hClearViews : (executeOperation tx (.clear mapName)).1.globalViews = tx.globalViews := by
            have foldViews (rows : Assoc String String) (acc : Tx) (ha : acc.globalViews = tx.globalViews) :
                (rows.foldl (fun (acc : Tx) (k, _) =>
                  {acc with normal := recordOp acc.data acc.normal (.write (mapName, k) none)})
                  acc).globalViews = tx.globalViews := by
              induction rows generalizing acc with
              | nil => exact ha
              | cons row rest ih => exact ih _ ha
            exact foldViews visible _ rfl
          rw [WP.spec_ok]
          refine ⟨⟨.unit, rfl, rfl⟩, ?_, ?_, hcontext, hpOrder, addNativeOrig deps hd,
            addDepsPins deps hdepsVal, ?_⟩
          · exact hw'.trans (hclear.1.symm ▸ .rfl)
          · exact hclear.2.symm ▸ hDepEq
          · intro d hm
            change d ∈ (executeOperation tx (.clear mapName)).1.normal.deps at hm
            simp only [ScanOperation.model]
            rw [hClearViews]
            exact addModelOrig _ hclear.2 d hm
      | range lower upper =>
          let outRef := executeOperation tx (Operation.range mapName
            (encodeBound encode lower) (encodeBound encode upper))
          let post := fun (out, after) =>
            (∃ obs, scanOutput encode out = some obs ∧
              OutputMatches (.operation 0 0 (Operation.range mapName
                (encodeBound encode lower) (encodeBound encode upper))) obs outRef.2) ∧
            (pointWrites encode after).Perm outRef.1.normal.writes ∧
            List.Forall₂ DependencyOrderEq (pointDeps encode history.index after) outRef.1.normal.deps ∧
            pointKeepsContext t after ∧ PendingSorted after.pending.val ∧
            NativeDepsFromViews encode history.index after ∧ DepsPinsInViews after ∧
            ModelDepsFromViews outRef.1
          let fullScan
              : Result
                  (core.result.Result Spike.engine.Output Spike.engine.Error
                    × Spike.engine.Tx) := do
            let (rows, deps) ← Spike.engine.Tx.scan history t.pending t.deps m native
            let filtered ← Spike.engine.ordered_range
              Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineRangeValue rows lower upper
            Result.ok (core.result.Result.Ok (Spike.engine.Output.Entries filtered),
              {t with deps, phase := .Active})
          let committedRange
              : Result
                  (core.result.Result Spike.engine.Output Spike.engine.Error
                    × Spike.engine.Tx) := do
            let rows ← Spike.engine.PinnedImage.range native.local history m lower upper
            let pin ← Spike.engine.PinnedImage.Insts.CoreCloneClone.clone native.local
            let deps ← alloc.vec.Vec.push t.deps (.Map m pin)
            Result.ok (core.result.Result.Ok (Spike.engine.Output.Entries rows),
              {t with deps, phase := .Active})
          let nonemptyScan := do
            let empty ← alloc.vec.Vec.is_empty t.pending
            if empty then committedRange else fullScan
          have withOverlay
              (hEmpty
                : ¬emptyRange (encodeBound encode lower) (encodeBound encode upper)
                    = true)
              : WP.spec fullScan post := by
            unfold fullScan
            apply WP.spec_bind hscan
            rintro ⟨rows, deps⟩ ⟨hdepsVal, hr, hd, _⟩
            have hVisUnique : Kv.Properties.Unique visible :=
              unique_scan tx.data tx.normal.writes mapName unique
            have hEntriesPerm : (encodeRangeEntries encode id rows.val).Perm visible := by
              simpa [encodeRangeEntries, modelEntries] using hr
            change WP.spec (do
              let filtered ← Spike.engine.ordered_range
                Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineRangeValue rows lower upper
              Result.ok (core.result.Result.Ok (Spike.engine.Output.Entries filtered),
                {t with deps, phase := .Active})) post
            apply WP.spec_bind
              (ordered_range_by_contents order
                Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineRangeValue id (fun _ => rfl)
                rows visible lower upper hVisUnique hEntriesPerm)
            intro filtered hfiltered
            change modelEntries encode filtered = _ at hfiltered
            rw [← hPhase, WP.spec_ok]
            have hNotEmpty : emptyRange (encodeBound encode lower) (encodeBound encode upper) = false :=
              Bool.eq_false_of_not_eq_true hEmpty
            refine ⟨
              ⟨.entries (modelEntries encode filtered), rfl, ?_⟩,
              ?_,
              ?_,
              rfl,
              hSorted,
              addNativeOrig deps hd,
              addDepsPins deps hdepsVal,
              ?_
            ⟩
            · simp only [OutputMatches, outRef, executeOperation, hNotEmpty, Bool.false_eq_true,
                ite_false, hfiltered]
              rfl
            · simp only [outRef, executeOperation, hNotEmpty, Bool.false_eq_true, ite_false,
                recordOp, stage]
              exact hWrites
            · simp only [outRef, executeOperation, hNotEmpty, Bool.false_eq_true, ite_false,
                recordOp, needs, List.cons_append, List.nil_append]
              rw [hd]
              exact .cons (.map mapName hl) hDeps
            · simp only [outRef, executeOperation, hNotEmpty, Bool.false_eq_true, ite_false]
              exact addModelOrig _ rfl
          have go
              (hEmpty
                : ¬emptyRange (encodeBound encode lower) (encodeBound encode upper)
                    = true)
              : WP.spec nonemptyScan post := by
            by_cases clean : t.pending.val = []
            · have noWrites : tx.normal.writes = [] := by
                have hlen0 : (pointWrites encode t).length = 0 := by
                  simp [pointWrites, encodeWrites, byteWrites, clean]
                exact List.eq_nil_of_length_eq_zero (hWrites.length_eq.symm.trans hlen0)
              have visibleEq : visible = (image tx.data mapName).map (fun (k, c) => (k, c.value)) := by
                simp [visible, scanAt, noWrites, writeValues]
              have hVisUnique : Kv.Properties.Unique visible :=
                unique_scan tx.data tx.normal.writes mapName unique
              have hRelPin : ((encodeImage encode (pinImage history.index m native.local)).map
                  (fun (k, c) => (k, c.value))).Perm visible := by
                rw [visibleEq]
                exact hl.map _
              simp only [nonemptyScan, emptyTest, clean, decide_true, bind_tc_ok, ite_true,
                committedRange]
              apply WP.spec_bind
                (pin_range_refines inj order history m native.local visible lower upper
                  hVisUnique hRelPin (alive native rfl).2.1 valid mapRoom
                  (space (m, native) (alive native rfl).1).1)
              intro rows output
              simp only [clone_pin, bind_ok]
              apply WP.spec_bind
                (deps_push encode history.index t (.Map m native.local) room)
              intro deps ⟨hdepsVal, updated⟩
              have dep : pointDeps encode history.index {t with deps} =
                  .map mapName (encodeImage encode (pinImage history.index m native.local))
                  :: pointDeps encode history.index t := by
                simpa [byteDependency, encodeDependency, mapName] using updated
              rw [← hPhase, WP.spec_ok]
              have hNotEmpty : emptyRange (encodeBound encode lower) (encodeBound encode upper) = false :=
                Bool.eq_false_of_not_eq_true hEmpty
              refine ⟨
                ⟨.entries (modelEntries encode rows), rfl, ?_⟩,
                ?_,
                ?_,
                rfl,
                hSorted,
                addNativeOrig deps dep,
                addDepsPins deps hdepsVal,
                ?_
              ⟩
              · simp only [OutputMatches, outRef, executeOperation, hNotEmpty, Bool.false_eq_true,
                  ite_false, output]
                rfl
              · simp only [outRef, executeOperation, hNotEmpty, Bool.false_eq_true, ite_false,
                  recordOp, stage]
                exact hWrites
              · simp only [outRef, executeOperation, hNotEmpty, Bool.false_eq_true, ite_false,
                  recordOp, needs, List.cons_append, List.nil_append]
                rw [dep]
                exact .cons (.map mapName hl) hDeps
              · simp only [outRef, executeOperation, hNotEmpty, Bool.false_eq_true, ite_false]
                exact addModelOrig _ rfl
            · simpa [nonemptyScan, emptyTest, clean] using withOverlay hEmpty
          change WP.spec _ post
          simp only [ScanOperation.rust]
          cases lower with
          | none =>
              exact go (by simp [encodeBound, emptyRange])
          | some lo =>
              cases upper with
              | none => exact go (by simp [encodeBound, emptyRange])
              | some hi =>
                  apply WP.spec_bind (range_empty_guard order lo hi)
                  intro cmp hcmp
                  by_cases he :
                    emptyRange (encodeBound encode (some lo))
                      (encodeBound encode (some hi))
                    = true
                  · have hp : cmp ≥ 0#i8 := of_decide_eq_true (hcmp.trans he)
                    rw [← hPhase]
                    simp only [hp, ite_true, WP.spec_ok, post, outRef, executeOperation, he]
                    exact ⟨⟨.entries [], rfl, rfl⟩, hWrites, hDeps, rfl, hSorted,
                      hNativeOrig, hDepsPins, hModelOrig⟩
                  · have hp : ¬cmp ≥ 0#i8 :=
                      fun h => he (hcmp.symm.trans (decide_eq_true h))
                    rw [ite_eq_right hp]
                    exact go he

end KvRust
