-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.IndexedHistory

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Non-empty radix roots retained directly by a pinned image handle. -/
def pinPins : Spike.engine.PinnedImage → List U32
  | .Root root => if root = 0#u32 then [] else [root]
  | _ => []

def PinLive (index : CellIndex) : Spike.engine.PinnedImage → Prop
  | .Root root => IndexView index root (indexRows index root)
  | _ => True

noncomputable def pinImage (index : CellIndex) (map : Spike.engine.Bytes)
    : Spike.engine.PinnedImage → Assoc (List U8) (Cell (List U8))
  | .Empty => []
  | .Root root => image (indexedCellData (indexRows index root)) map.val
  | .Recovered rows => byteImage rows

theorem pin_preserved_of_pins {before after : CellIndex} {pins : List U32}
    (preserved : IndexPreservesPins before after pins)
    (map : Spike.engine.Bytes) (pin : Spike.engine.PinnedImage)
    (inPins : ∀ r ∈ pinPins pin, r ∈ pins) (live : PinLive before pin)
    : PinLive after pin ∧ pinImage after map pin = pinImage before map pin := by
  cases pin with
  | Empty => exact ⟨trivial, rfl⟩
  | Recovered rows => exact ⟨trivial, rfl⟩
  | Root root =>
      have hpin : root = 0#u32 ∨ root ∈ pins := by
        by_cases hz : root = 0#u32
        · exact Or.inl hz
        · exact Or.inr (inPins root (by simp [pinPins, hz]))
      have hv := index_preserves_pins_view preserved root _ hpin live
      have hrows : indexRows after root = indexRows before root := index_rows_eq hv
      exact ⟨
        by show IndexView after root (indexRows after root); rwa [hrows],
        by simp [pinImage, hrows]
      ⟩

theorem pin_preserved {before after : CellIndex}
    (preserved : IndexKeeps before after)
    (map : Spike.engine.Bytes) (pin : Spike.engine.PinnedImage)
    (live : PinLive before pin)
    : PinLive after pin ∧ pinImage after map pin = pinImage before map pin := by
  cases pin with
  | Empty => exact ⟨trivial, rfl⟩
  | Recovered rows => exact ⟨trivial, rfl⟩
  | Root root =>
      have hv := index_keeps_view preserved root _ live
      have hrows : indexRows after root = indexRows before root := index_rows_eq hv
      exact ⟨
        by show IndexView after root (indexRows after root); rwa [hrows],
        by simp [pinImage, hrows]
      ⟩

theorem clone_pin (pin : Spike.engine.PinnedImage)
    : Spike.engine.PinnedImage.Insts.CoreCloneClone.clone pin = .ok pin := by
  cases pin <;> simp [Spike.engine.PinnedImage.Insts.CoreCloneClone.clone, clone_assoc,
    Spike.radix.RadixRoot.Insts.CoreCloneClone.clone]

def PinScanRoom (index : CellIndex) : Spike.engine.PinnedImage → Prop
  | .Root root => 18 * (indexRows index root).length ≤ Usize.max
  | _ => True

def HistoryScanRoom (history : Spike.engine.History) : Prop :=
  ∀ (i : Nat) (frame : Spike.engine.Frame),
    history.log.frames.val[i]? = some frame
    → 18 * (indexRows history.index frame.data).length ≤ Usize.max

theorem release_pin_refines (index : CellIndex) (restPins : List U32)
    (pin : Spike.engine.PinnedImage)
    (live : IndexLiveness index (pinPins pin ++ restPins))
    (queueRoom
      : 2 * (index.values.dirs.val.length + index.values.rows.val.length) + 1 ≤ Usize.max)
    : WP.spec (Spike.engine.release_pin index pin)
        (fun after =>
          after.values = index.values ∧ IndexLiveness after restPins) := by
  unfold Spike.engine.release_pin
  cases pin with
  | Empty =>
      rw [WP.spec_ok]
      exact ⟨rfl, by simpa [pinPins] using live⟩
  | Recovered _ =>
      rw [WP.spec_ok]
      exact ⟨rfl, by simpa [pinPins] using live⟩
  | Root root =>
      have hlive : IndexLiveness index (if root = 0#u32 then restPins else root :: restPins) := by
        by_cases hz : root = 0#u32 <;> simpa [pinPins, hz] using live
      exact index_release_root_refines index restPins root hlive queueRoom

/-- Materializing a pinned root handle copies precisely its selected ordered map. -/
theorem pin_materialize_refines (history : Spike.engine.History)
    (map : Spike.engine.Bytes) (pin : Spike.engine.PinnedImage)
    (live : PinLive history.index pin) (valid : IndexValid history.index)
    (mapRoom : 2 * (8 + map.val.length) ≤ Usize.max)
    (space : PinScanRoom history.index pin)
    : WP.spec (Spike.engine.PinnedImage.materialize pin history map)
        (fun rows => byteImage rows = pinImage history.index map pin) := by
  unfold Spike.engine.PinnedImage.materialize
  cases pin with
  | Empty => simp [Spike.engine.Assoc.new, byteImage, pinImage]
  | Recovered rows => simp [clone_assoc, pinImage]
  | Root root =>
      apply WP.spec_mono (indexed_image_refines history.index root _ map live valid mapRoom space)
      intro rows h
      simp only [byteImage, h, pinImage]
      exact indexed_image_projects _ _

private theorem find_in_image {M K V : Type} [DecidableEq M] [DecidableEq K]
    (db : DB M K V) (map : M) (key : K)
    : find (image db map) key = find db (map, key) := by
  induction db with
  | nil => rfl
  | cons row rest ih =>
      obtain ⟨⟨m, k⟩, v⟩ := row
      by_cases onMap : m = map
      · subst m
        simp [image, find] at ih ⊢
        by_cases onKey : k = key <;> simp [onKey, ih]
      · have diff : (m, k) ≠ (map, key) := fun h => onMap (congrArg Prod.fst h)
        simpa [image, find, onMap, diff] using ih

local instance pinDecidableEqBytes : DecidableEq Spike.engine.Bytes :=
  fun a b =>
    decidable_of_iff (a.val = b.val) ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

/-- A borrowed point read agrees with a lookup after exact map materialization. -/
theorem pin_point_refines (history : Spike.engine.History)
    (address : Spike.engine.Address) (pin : Spike.engine.PinnedImage)
    (live : PinLive history.index pin)
    (space : 8 + address.map.val.length + address.key.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.PinnedImage.point pin history address)
        (fun cell =>
          cell.map byteCell
          = find (pinImage history.index address.map pin) address.key.val) := by
  unfold Spike.engine.PinnedImage.point
  cases pin with
  | Empty => simp [pinImage, find]
  | Recovered rows =>
      apply WP.spec_mono (assoc_get Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
        Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Cell.Insts.CoreCloneClone
        rows address.key (fun k => key_same k address.key) clone_cell)
      intro found he
      rw [pinImage, byteImage, find_projected _ _ _ _ (fun _ _ => alloc.vec.Vec.ext _ _), he]
  | Root root =>
      apply WP.spec_bind (index_data_lookup history.index root _ live address space)
      intro found he
      cases found <;> simp [clone_cell, pinImage, find_in_image, byteAddr] at he ⊢ <;>
        exact he

def viewPins (view : Spike.engine.View) : List U32 :=
  pinPins view.local
  ++ (match view.global with
      | none => []
      | some g => pinPins g)

def txPins (t : Spike.engine.Tx) : List U32 :=
  t.views.val.flatMap fun (_, v) => viewPins v

def txsPins (txs : List (U64 × Spike.engine.Tx)) : List U32 :=
  txs.flatMap fun (_, t) => txPins t

def storePins (s : Spike.engine.Store) : List U32 :=
  framePins s.history.log.frames.val ++ txsPins s.txs.val

theorem txsPins_set_same_views (txs : List (U64 × Spike.engine.Tx)) (i : Nat)
    (id : U64) (t t' : Spike.engine.Tx)
    (hget : txs[i]? = some (id, t)) (hviews : t'.views = t.views)
    : txsPins (txs.set i (id, t')) = txsPins txs := by
  induction txs generalizing i with
  | nil => simp at hget
  | cons hd tl ih =>
      cases i with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at hget
          rcases hd with ⟨hdId, hdT⟩
          obtain ⟨rfl, rfl⟩ := Prod.mk.inj hget
          simp [txsPins, txPins, hviews]
      | succ j =>
          simp only [List.getElem?_cons_succ] at hget
          have hsub := ih j hget
          simp only [List.set_cons_succ, txsPins, List.flatMap_cons] at hsub ⊢
          rw [hsub]

theorem txsPins_set_add_view (txs : List (U64 × Spike.engine.Tx)) (i : Nat)
    (id : U64) (t t' : Spike.engine.Tx) (m : Spike.engine.Bytes) (v : Spike.engine.View)
    (hget : txs[i]? = some (id, t)) (hviews : t'.views.val = (m, v) :: t.views.val)
    : (txsPins (txs.set i (id, t'))).Perm (viewPins v ++ txsPins txs) := by
  induction txs generalizing i with
  | nil => simp at hget
  | cons hd tl ih =>
      cases i with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at hget
          subst hget
          simp only [List.set_cons_zero, txsPins, txPins, List.flatMap_cons, hviews, List.append_assoc]
          exact .rfl
      | succ j =>
          simp only [List.getElem?_cons_succ] at hget
          have hsub := ih j hget
          simp only [List.set_cons_succ, txsPins, List.flatMap_cons]
          have h1 : (txPins hd.2 ++ txsPins (tl.set j (id, t'))).Perm
              (txPins hd.2 ++ (viewPins v ++ txsPins tl)) := hsub.append_left _
          have h2 : (txPins hd.2 ++ (viewPins v ++ txsPins tl)).Perm
              ((txPins hd.2 ++ viewPins v) ++ txsPins tl) := by rw [List.append_assoc]
          have h3 : ((txPins hd.2 ++ viewPins v) ++ txsPins tl).Perm
              ((viewPins v ++ txPins hd.2) ++ txsPins tl) := List.perm_append_comm.append_right _
          have h4 : ((viewPins v ++ txPins hd.2) ++ txsPins tl).Perm
              (viewPins v ++ (txPins hd.2 ++ txsPins tl)) := by rw [List.append_assoc]
          exact h1.trans (h2.trans (h3.trans h4))

theorem txsPins_split_at (txs : List (U64 × Spike.engine.Tx)) (i : Nat)
    (id : U64) (t : Spike.engine.Tx) (hget : txs[i]? = some (id, t))
    : (txsPins txs).Perm (txPins t ++ txsPins (txs.eraseIdx i)) := by
  induction txs generalizing i with
  | nil => simp at hget
  | cons hd tl ih =>
      cases i with
      | zero =>
          simp only [List.getElem?_cons_zero, Option.some.injEq] at hget
          subst hget
          simp [txsPins]
      | succ j =>
          simp only [List.getElem?_cons_succ] at hget
          have hsub := ih j hget
          simp only [List.eraseIdx_cons_succ, txsPins, List.flatMap_cons]
          have h1 : (txPins hd.2 ++ txsPins tl).Perm
              (txPins hd.2 ++ (txPins t ++ txsPins (tl.eraseIdx j))) := hsub.append_left _
          have h2 : (txPins hd.2 ++ (txPins t ++ txsPins (tl.eraseIdx j))).Perm
              ((txPins hd.2 ++ txPins t) ++ txsPins (tl.eraseIdx j)) := by rw [List.append_assoc]
          have h3 : ((txPins hd.2 ++ txPins t) ++ txsPins (tl.eraseIdx j)).Perm
              ((txPins t ++ txPins hd.2) ++ txsPins (tl.eraseIdx j)) :=
            List.perm_append_comm.append_right _
          have h4 : ((txPins t ++ txPins hd.2) ++ txsPins (tl.eraseIdx j)).Perm
              (txPins t ++ (txPins hd.2 ++ txsPins (tl.eraseIdx j))) := by rw [List.append_assoc]
          exact h1.trans (h2.trans (h3.trans h4))

theorem release_tx_pins_refines (index : CellIndex) (tx : Spike.engine.Tx)
    (restPins : List U32)
    (live : IndexLiveness index (txPins tx ++ restPins))
    (queueRoom
      : 2 * (index.values.dirs.val.length + index.values.rows.val.length) + 1 ≤ Usize.max)
    : WP.spec (Spike.engine.release_tx_pins index tx)
        (fun after =>
          after.values = index.values ∧ IndexLiveness after restPins) := by
  unfold Spike.engine.release_tx_pins Spike.engine.release_tx_pins_loop
  let total := tx.views.val.length
  let tailPins (k : Nat) : List U32 :=
    (tx.views.val.drop k).flatMap fun (_, v) => viewPins v
  apply loop.spec_decr_nat (fun (_, i) => total - i.val)
    (fun (cur, i) =>
      i.val ≤ total
      ∧ cur.values = index.values
      ∧ IndexLiveness cur (tailPins i.val ++ restPins))
    _ _ _
  · rintro ⟨cur, i⟩ ⟨hi, hvals, hlive⟩
    dsimp only at hi hvals hlive ⊢
    unfold Spike.engine.release_tx_pins_loop.body
    have hlen : (alloc.vec.Vec.len tx.views).val = total := alloc.vec.Vec.len_val _
    have hcap := alloc.vec.Vec.len_ineq tx.views
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases hlt : i < alloc.vec.Vec.len tx.views
    · have hilt : i.val < total := by rwa [← hlen]
      rw [ite_eq_left hlt, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec tx.views i hilt)
      rintro ⟨m, view⟩ hrow
      have hdrop : tx.views.val.drop i.val = (m, view) :: tx.views.val.drop (i.val + 1) := by
        rw [List.drop_eq_getElem_cons hilt, ← hrow]
      have htailEq : tailPins i.val =
          pinPins view.local ++ ((match view.global with | none => [] | some g => pinPins g)
            ++ tailPins (i.val + 1)) := by
        simp only [tailPins, hdrop, List.flatMap_cons, viewPins, List.append_assoc]
      have hqCur : 2 * (cur.values.dirs.val.length + cur.values.rows.val.length) + 1 ≤ Usize.max := by
        rw [hvals]; exact queueRoom
      have hlive1 : IndexLiveness cur
          (pinPins view.local ++ ((match view.global with | none => [] | some g => pinPins g)
            ++ tailPins (i.val + 1) ++ restPins)) := by
        simpa only [htailEq, List.append_assoc] using hlive
      apply WP.spec_bind (release_pin_refines cur _ view.local hlive1 hqCur)
      intro cur1 ⟨hvals1, hlive2⟩
      have hglob : WP.spec
          (match view.global with
            | none => Result.ok cur1
            | some g => Spike.engine.release_pin cur1 g)
          (fun cur2 => cur2.values = index.values ∧ IndexLiveness cur2 (tailPins (i.val + 1) ++ restPins)) := by
        cases hg : view.global with
        | none =>
            rw [WP.spec_ok]
            exact ⟨hvals1.trans hvals, by simpa [hg] using hlive2⟩
        | some g =>
            have hq1 : 2 * (cur1.values.dirs.val.length + cur1.values.rows.val.length) + 1 ≤ Usize.max := by
              rw [hvals1, hvals]; exact queueRoom
            apply WP.spec_mono
              (release_pin_refines cur1 (tailPins (i.val + 1) ++ restPins) g
                (by simpa [hg, List.append_assoc] using hlive2) hq1)
            intro cur2 ⟨hvals2, hlive3⟩
            exact ⟨hvals2.trans (hvals1.trans hvals), hlive3⟩
      apply WP.spec_bind hglob
      intro cur2 ⟨hvals2, hlive3⟩
      apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
      intro j hj
      change WP.spec (Result.ok (ControlFlow.cont (cur2, j))) _
      rw [WP.spec_ok]
      dsimp only
      have hjVal : j.val = i.val + 1 := by omega
      exact ⟨⟨by omega, hvals2, hjVal.symm ▸ hlive3⟩, by omega⟩
    · have hge : total ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt hlt
      rw [ite_eq_right hlt, WP.spec_ok]
      have hnil : tailPins i.val = [] := by simp [tailPins, List.drop_eq_nil_of_le hge]
      exact ⟨hvals, by simpa [hnil] using hlive⟩
  · exact ⟨Nat.zero_le _, rfl, by simpa [tailPins, txPins] using live⟩

end KvRust
