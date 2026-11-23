-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

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

private theorem scan_committed (cells : Spike.engine.Assoc Bytes Spike.engine.Cell)
    : WP.spec (Spike.engine.Tx.scan_loop0 cells (alloc.vec.Vec.new _) 0#usize)
        (fun (retained, rows) =>
          retained = cells ∧ rows.val = cells.val.map (fun (k, c) => (k, c.value))) := by
  let project := fun (p : Bytes × Spike.engine.Cell) => (p.1, p.2.value)
  unfold Spike.engine.Tx.scan_loop0
  apply loop.spec_decr_nat
    (fun (p : _ × Entries × Usize) => cells.val.length - p.2.2.val)
    (fun (c, rows, i) => c = cells ∧ rows.val.length = i.val ∧
      rows.val ++ (cells.val.drop i.val).map project = cells.val.map project) _ _ _
  · rintro ⟨c, rows, i⟩ ⟨hc, hi, hrows⟩
    dsimp only at hc hi hrows ⊢
    subst c
    unfold Spike.engine.Tx.scan_loop0.body
    have hlen : (alloc.vec.Vec.len cells).val = cells.val.length := alloc.vec.Vec.len_val _
    have hcap := alloc.vec.Vec.len_ineq cells
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len cells
    · have hb : i.val < cells.val.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec cells i hb)
      rintro ⟨k, c⟩ hrow
      change WP.spec (do
        let a ← Spike.engine.Bytes.Insts.CoreCloneClone.clone k
        let b ← Spike.engine.Bytes.Insts.CoreCloneClone.clone c.value
        let rs ← alloc.vec.Vec.push rows (a, b)
        let j ← i + 1#usize
        Result.ok (ControlFlow.cont (cells, rs, j))) _
      simp only [clone_bytes, bind_ok]
      apply WP.spec_bind (alloc.vec.Vec.push_spec rows (k, c.value) (by omega))
      intro next hn
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have hj' : j.val = i.val + 1 := by omega
      have hsplit : cells.val.drop i.val = (k, c) :: cells.val.drop j.val := by
        rw [hj', List.drop_eq_getElem_cons hb, ← hrow]
      rw [WP.spec_ok]
      exact ⟨⟨rfl, by simp [hn, hi, hj'], by simpa [hn, hsplit, project] using hrows⟩,
        show cells.val.length - j.val < cells.val.length - i.val by omega⟩
    · have hb : cells.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      exact ⟨rfl, by simpa [List.drop_eq_nil_of_le hb, project] using hrows⟩
  · simp

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
    : WP.spec (Spike.engine.Tx.scan_loop1 pending m base (alloc.vec.Vec.len pending))
        (fun r =>
          modelEntries encode r
            = writeValues (modelEntries encode base) (mapWrites encode m pending.val)
          ∧ r.val.length ≤ base.val.length + pending.val.length) := by
  let expected := writeValues (modelEntries encode base) (mapWrites encode m pending.val)
  let cap := base.val.length + pending.val.length
  unfold Spike.engine.Tx.scan_loop1
  apply loop.spec_decr_nat (fun (p : Entries × Usize) => p.2.val)
    (fun (rows, i) =>
      i.val ≤ pending.val.length
      ∧ rows.val.length + i.val ≤ cap
      ∧ writeValues (modelEntries encode rows)
          (mapWrites encode m (pending.val.take i.val))
        = expected) _ _ _
  · rintro ⟨rows, i⟩ ⟨hi, hcap, hrows⟩
    dsimp only at hi hcap hrows ⊢
    unfold Spike.engine.Tx.scan_loop1.body
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
      : encodeImage encode (pinImage history m view.local)
        = image tx.data (encode (alloc.vec.Vec.val m)))
    (live : PinLive history view.local)
    (indexed : HistoryIndexValid history) (space : PinScanRoom history view.local)
    (hWrites : pointWrites encode t = tx.normal.writes)
    (hDeps : pointDeps encode t = tx.normal.deps)
    (room : t.deps.val.length < Usize.max)
    (rowsRoom : (pinImage history m view.local).length + t.pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Tx.scan history t.pending t.deps m view)
        (fun (rows, deps) =>
          let next := {t with deps}
          modelEntries encode rows
            = scanAt tx.data tx.normal.writes (encode (alloc.vec.Vec.val m))
          ∧ pointWrites encode next = tx.normal.writes
          ∧ pointDeps encode next
            = .map (encode (alloc.vec.Vec.val m))
                (image tx.data (encode (alloc.vec.Vec.val m)))
              :: tx.normal.deps
          ∧ rows.val.length
            ≤ (pinImage history m view.local).length + t.pending.val.length) := by
  simp only [Spike.engine.Tx.scan, clone_bytes, Spike.engine.Assoc.new, bind_ok]
  apply WP.spec_bind (pin_materialize_refines history m view.local live indexed space)
  intro cells hCells
  have localEq : encodeImage encode (byteImage cells) = image tx.data (encode m.val) :=
    (congrArg (encodeImage encode) hCells).trans hLocal
  apply WP.spec_bind (scan_committed cells)
  rintro ⟨retained, base⟩ ⟨kept, hb⟩
  subst retained
  apply WP.spec_bind (deps_push encode t (.Map m cells) room)
  intro deps hd
  have hlen : base.val.length = (pinImage history m view.local).length := by
    rw [← hCells]
    simp [hb, byteImage]
  apply WP.spec_bind
    (scan_overlay encode inj m t.pending base (by simpa [hlen] using rowsRoom))
  intro out ho
  have hbase : modelEntries encode base =
      (image tx.data (encode (alloc.vec.Vec.val m))).map fun (k, c) => (k, c.value) := by
    rw [← localEq]
    simp [modelEntries, hb, encodeImage, byteImage, List.map_map, Function.comp_def,
      encodeCell, byteCell]
  have hdep : pointDeps encode {t with deps} = .map (encode (alloc.vec.Vec.val m))
      (image tx.data (encode (alloc.vec.Vec.val m))) :: tx.normal.deps := by
    simpa [byteDependency, encodeDependency, localEq, hDeps] using hd
  rw [WP.spec_ok]
  exact ⟨
    by simpa [scanAt, hbase, map_writes_proj encode inj m t, hWrites] using ho.1,
    hWrites,
    hdep,
    by simpa [hlen] using ho.2
  ⟩

private def removeEntry (m : String) (ws : Pending) (row : String × String) : Pending :=
  Kv.Model.set ws (m, row.1) none

private theorem clear_rows (encode : List U8 → String) (inj : Function.Injective encode)
    (t : Spike.engine.Tx) (m : Bytes) (entries : Entries)
    (room : t.pending.val.length + entries.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Tx.operate_loop t.pending m entries 0#usize)
        (fun next =>
          pointWrites encode {t with pending := next}
          = (modelEntries encode entries).foldl
              (removeEntry (encode (alloc.vec.Vec.val m))) (pointWrites encode t)) := by
  let project := fun (p : Bytes × Bytes) =>
    (encode (alloc.vec.Vec.val p.1), encode (alloc.vec.Vec.val p.2))
  let remaining := fun (p : alloc.vec.Vec (Spike.engine.Address × Spike.engine.Write)) (i : Nat) =>
    ((entries.val.drop i).map project).foldl (removeEntry (encode (alloc.vec.Vec.val m)))
      (pointWrites encode {t with pending := p})
  unfold Spike.engine.Tx.operate_loop
  apply loop.spec_decr_nat
    (fun (p : alloc.vec.Vec (Spike.engine.Address × Spike.engine.Write) × Usize) =>
      entries.val.length - p.2.val)
    (fun (s, i) =>
      i.val ≤ entries.val.length
      ∧ s.val.length + (entries.val.length - i.val) ≤ Usize.max
      ∧ remaining s i.val = remaining t.pending 0)
    _ _ _
  · rintro ⟨s, i⟩ ⟨hi, hsize, hs⟩
    dsimp only at hi hsize hs ⊢
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
        let pending ← Spike.engine.Assoc.set Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Address.Insts.CoreCloneClone Spike.engine.Write.Insts.CoreCloneClone
          s {map := m, key := key'} .Remove
        let j ← i + 1#usize
        Result.ok (ControlFlow.cont (pending, j))) _
      simp only [clone_bytes, bind_ok]
      have hroom : s.val.length < Usize.max := by omega
      apply WP.spec_bind
        (stage_write_bounded encode inj {t with pending := s} {map := m, key} .Remove hroom)
      intro pending hp
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      have hj' : j.val = i.val + 1 := by omega
      have hdrop : entries.val.drop i.val = (key, value) :: entries.val.drop j.val := by
        rw [hj', List.drop_eq_getElem_cons hb, ← hr]
      have hpBound : pending.val.length ≤ s.val.length + 1 := hp.2
      rw [WP.spec_ok]
      have hFold : remaining pending j.val = remaining t.pending 0 := by
        simp only [remaining, hdrop, List.map_cons, List.foldl_cons] at hs
        unfold remaining
        rw [show ({t with pending} : Spike.engine.Tx) =
          {({t with pending := s} : Spike.engine.Tx) with pending} from rfl, hp.1]
        exact hs
      exact ⟨⟨show j.val ≤ entries.val.length by omega,
        show pending.val.length + (entries.val.length - j.val) ≤ Usize.max by omega,
        hFold⟩, show entries.val.length - j.val < entries.val.length - i.val by omega⟩
    · have hb : entries.val.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simpa only [remaining, modelEntries, project, List.drop_zero, List.drop_eq_nil_of_le hb,
        List.map_nil, List.foldl_nil] using hs
  · simp [room]

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

/-- Filtering a unique database by map leaves unique keys in that map. -/
theorem unique_image (db : Data) (m : String) (h : Kv.Properties.Unique db)
    : Kv.Properties.Unique (image db m) := by
  unfold Kv.Properties.Unique at h ⊢
  induction db with
  | nil => simp [image]
  | cons row rest ih =>
      obtain ⟨⟨k, key⟩, value⟩ := row
      have hn := List.nodup_cons.mp h
      by_cases he : k = m
      · subst k
        simp only [image, List.filterMap_cons, ite_true, List.map_cons, List.nodup_cons]
        refine ⟨?_, ih hn.2⟩
        intro hm
        obtain ⟨⟨a, c⟩, hmem, hkey⟩ := List.mem_map.mp hm
        simp only at hkey
        subst a
        rw [List.mem_filterMap] at hmem
        obtain ⟨⟨⟨k, b⟩, v⟩, hrow, hfilter⟩ := hmem
        by_cases hk : k = m
        · subst k
          simp at hfilter
          obtain ⟨rfl, _⟩ := hfilter
          exact hn.1 (List.mem_map.mpr ⟨_, hrow, rfl⟩)
        · simp [hk] at hfilter
      · have hrest := ih hn.2
        simpa only [image, List.filterMap_cons, he, ite_false] using hrest

private theorem unique_overlay (base : Assoc String String)
    (writes : Assoc String (Option String)) (h : Kv.Properties.Unique base)
    : Kv.Properties.Unique (writeValues base writes) := by
  have eraseUnique (rows : Assoc String String) (k : String) (hu : Kv.Properties.Unique rows) :
      Kv.Properties.Unique (erase rows k) :=
    (List.Sublist.map Prod.fst List.filter_sublist).nodup hu
  induction writes with
  | nil => exact h
  | cons row rest ih =>
      obtain ⟨k, v⟩ := row
      cases v with
      | none => exact eraseUnique (writeValues base rest) k ih
      | some v =>
          apply List.nodup_cons.mpr
          refine ⟨?_, eraseUnique (writeValues base rest) k ih⟩
          intro hm
          obtain ⟨⟨a, value⟩, hrow, eq⟩ := List.mem_map.mp hm
          simp only at eq
          subst a
          have he := (List.mem_filter.mp hrow).2
          simp at he

/-- The staged overlay cannot introduce duplicate keys into a scan. -/
theorem unique_scan (db : Data) (ws : Pending) (m : String)
    (h : Kv.Properties.Unique (image db m))
    : Kv.Properties.Unique (scanAt db ws m) := by
  unfold scanAt
  apply unique_overlay
  unfold Kv.Properties.Unique at h ⊢
  rw [List.map_map]
  change ((image db m).map Prod.fst).Nodup
  exact h

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

/-- An enabled scan, size, or clear agrees with the reference action and dependency updates. -/
theorem operate_scan_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (order : PreservesByteOrder encode)
    (history : Spike.engine.History)
    (t : Spike.engine.Tx) (tx : Tx) (m : Spike.engine.Bytes) (op : ScanOperation)
    (view : GlobalView) (hPhase : t.phase = .Active)
    (hView : find tx.globalViews (encode (alloc.vec.Vec.val m)) = some view)
    (hPinned : rustPinnedViews encode history t.views = modelPinnedViews tx.globalViews)
    (hLocal
      : image view.current.data (encode (alloc.vec.Vec.val m))
        = image tx.data (encode (alloc.vec.Vec.val m)))
    (hWrites : pointWrites encode t = tx.normal.writes)
    (hDeps : pointDeps encode t = tx.normal.deps) (room : t.deps.val.length < Usize.max)
    (rowsRoom
      : (image tx.data (encode (alloc.vec.Vec.val m))).length + t.pending.val.length
        ≤ Usize.max)
    (unique : Kv.Properties.Unique (image tx.data (encode (alloc.vec.Vec.val m))))
    (clearRoom
      : op = .clear
        → t.pending.val.length
            + (scanAt tx.data tx.normal.writes (encode (alloc.vec.Vec.val m))).length
          ≤ Usize.max)
    (live : ViewsLive history t.views)
    (indexed : HistoryIndexValid history) (space : HistoryScanRoom history)
    : let expected := executeOperation tx (op.model encode (encode (alloc.vec.Vec.val m)))
      WP.spec (Spike.engine.Tx.operate t history m op.rust)
        (fun (output, after) =>
          scanOutput encode output = some expected.2
          ∧ pointWrites encode after = expected.1.normal.writes
          ∧ pointDeps encode after = expected.1.normal.deps
          ∧ pointKeepsContext t after) := by
  let mapName := encode (alloc.vec.Vec.val m)
  let visible := scanAt tx.data tx.normal.writes mapName
  have he := lookup_model_view tx.globalViews mapName view hView
  have hActive : {t with phase := .Active} = t := by rw [← hPhase]
  simp only [Spike.engine.Tx.operate, hPhase, bind_ok]
  apply WP.spec_bind (view_lookup encode inj history t m live)
  intro found ⟨hf, alive⟩
  rw [hPinned, he] at hf
  cases found with
  | none => cases hf
  | some native =>
      have hl : encodeImage encode (pinImage history m native.local) = image tx.data mapName :=
        (congrArg PinnedView.localImage (Option.some.inj hf)).trans hLocal
      have hlen : (pinImage history m native.local).length = (image tx.data mapName).length := by
        simpa [encodeImage] using congrArg List.length hl
      have hscan :=
        scan_matches_model encode inj history t m native tx hl (alive native rfl).1 indexed
          (space.pin native.local) hWrites hDeps room
          (by simpa [hlen] using rowsRoom)
      cases op with
      | scan =>
          simp only [ScanOperation.rust]
          apply WP.spec_bind hscan
          rintro ⟨rows, deps⟩ ⟨hr, hw, hd, _⟩
          rw [← hPhase]
          simp [executeOperation, ScanOperation.model, recordOp, stage, needs, scanOutput,
            hr, hw, hd, pointKeepsContext]
      | size =>
          simp only [ScanOperation.rust]
          apply WP.spec_bind hscan
          rintro ⟨rows, deps⟩ ⟨hr, hw, hd, _⟩
          have hcount : rows.val.length = visible.length := by
            simpa [modelEntries] using congrArg List.length hr
          rw [← hPhase]
          simp [executeOperation, ScanOperation.model, recordOp, stage, needs, scanOutput, hcount,
            visible, mapName, hw, hd, pointKeepsContext]
      | clear =>
          simp only [ScanOperation.rust]
          apply WP.spec_bind hscan
          rintro ⟨rows, deps⟩ ⟨hr, hw, hd, _⟩
          have hcount : rows.val.length = visible.length := by
            simpa [modelEntries] using congrArg List.length hr
          have hspace : t.pending.val.length + rows.val.length ≤ Usize.max := by
            rw [hcount]
            exact clearRoom rfl
          change WP.spec (do
            let pending ← Spike.engine.Tx.operate_loop t.pending m rows 0#usize
            Result.ok (core.result.Result.Ok Spike.engine.Output.Unit,
              {t with pending, deps, phase := .Active})) _
          apply WP.spec_bind (clear_rows encode inj t m rows hspace)
          intro pending ho
          let out : Spike.engine.Tx := {t with pending, deps, phase := .Active}
          have hcontext : pointKeepsContext t out := by
            simp [out, pointKeepsContext, ← hPhase]
          have hclear := clear_reference visible
            {tx with normal := recordOp tx.data tx.normal (.scan mapName visible)} mapName
          have hw'
              : pointWrites encode out
                = visible.foldl (removeEntry mapName) tx.normal.writes := by
            change pointWrites encode {t with pending} = _
            rw [ho, show pointWrites encode t = tx.normal.writes from hw]
            exact congrArg
              (fun entries => entries.foldl (removeEntry mapName) tx.normal.writes) hr
          have hd' : pointDeps encode out = _ := hd
          rw [WP.spec_ok]
          exact ⟨rfl, hw'.trans hclear.1.symm, hd'.trans hclear.2.symm, hcontext⟩
      | range lower upper =>
          let outRef := executeOperation tx (Operation.range mapName
            (encodeBound encode lower) (encodeBound encode upper))
          let post := fun (out, after) => scanOutput encode out = some outRef.2 ∧
            pointWrites encode after = outRef.1.normal.writes ∧
            pointDeps encode after = outRef.1.normal.deps ∧ pointKeepsContext t after
          let nonemptyScan
              : Result
                  (core.result.Result Spike.engine.Output Spike.engine.Error
                    × Spike.engine.Tx) := do
            let (rows, deps) ← Spike.engine.Tx.scan history t.pending t.deps m native
            let filtered ← Spike.engine.ordered_range rows lower upper
            Result.ok (core.result.Result.Ok (Spike.engine.Output.Entries filtered),
              {t with deps, phase := .Active})
          have go
              (hEmpty
                : ¬emptyRange (encodeBound encode lower) (encodeBound encode upper)
                    = true)
              : WP.spec nonemptyScan post := by
            unfold nonemptyScan
            apply WP.spec_bind hscan
            rintro ⟨rows, deps⟩ ⟨hr, hw, hd, _⟩
            have hUnique : Kv.Properties.Unique (encodeEntries encode rows) := by
              change Kv.Properties.Unique (modelEntries encode rows)
              rw [hr]
              exact unique_scan tx.data tx.normal.writes mapName unique
            change WP.spec (do
              let filtered ← Spike.engine.ordered_range rows lower upper
              Result.ok (core.result.Result.Ok (Spike.engine.Output.Entries filtered),
                {t with deps, phase := .Active})) post
            apply WP.spec_bind (ordered_range order rows lower upper hUnique)
            intro filtered hfiltered
            change modelEntries encode filtered = _ at hfiltered
            have hf : encodeEntries encode rows = visible := hr
            rw [hf] at hfiltered
            rw [← hPhase]
            simp [post, outRef, executeOperation, hEmpty, scanOutput, hfiltered, recordOp,
              stage, needs, hw, hd, pointKeepsContext,
              visible, mapName]
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
                    simp [hp, post, outRef, executeOperation, he, scanOutput, modelEntries, hWrites,
                      hDeps, pointKeepsContext]
                  · have hp : ¬cmp ≥ 0#i8 :=
                      fun h => he (hcmp.symm.trans (decide_eq_true h))
                    rw [ite_eq_right hp]
                    exact go he

end KvRust
