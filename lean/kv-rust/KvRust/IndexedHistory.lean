-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lineage

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Every active ring frame has a valid radix view and every retained compacted
frame has an empty radix root. -/
structure HistoryIndexValid (history : CcfKv.engine.History) : Prop where
  index : IndexValid history.index
  active
    : ∀ frame ∈ history.activeFrames,
        IndexView history.index frame.data (indexRows history.index frame.data)
  retainedEmpty : ∀ frame ∈ history.retained.val, frame.data = 0#u32

theorem HistoryIndexValid.head {history : CcfKv.engine.History}
    (valid : HistoryIndexValid history) (prior : List CcfKv.engine.Frame)
    (frame : CcfKv.engine.Frame) (split : history.activeFrames = prior ++ [frame])
    : IndexView history.index frame.data (indexRows history.index frame.data) :=
  valid.active frame (by simp [split])

theorem HistoryIndexValid.congr {before after : CcfKv.engine.History}
    (valid : HistoryIndexValid before) (sameIndex : after.index = before.index)
    (sameActive : after.activeFrames = before.activeFrames)
    (sameRetained : after.retained = before.retained)
    : HistoryIndexValid after := by
  refine ⟨sameIndex.symm ▸ valid.index, ?_, ?_⟩
  · intro frame hmem
    rw [sameIndex]
    exact valid.active frame (sameActive ▸ hmem)
  · intro frame hmem
    exact valid.retainedEmpty frame (sameRetained ▸ hmem)

theorem HistoryIndexValid.of_preserves_pins {before after : CcfKv.engine.History}
    {extraPins : List U32}
    (valid : HistoryIndexValid before)
    (liveAfter : IndexValid after.index)
    (pres
      : IndexPreservesPins before.index after.index
          (framePins after.activeFrames ++ extraPins))
    (activeFrom
      : ∀ f' ∈ after.activeFrames,
          f'.data = 0#u32 ∨ ∃ f ∈ before.activeFrames, f'.data = f.data)
    (retainedEmpty : ∀ f' ∈ after.retained.val, f'.data = 0#u32)
    : HistoryIndexValid after := by
  refine ⟨liveAfter, ?_, retainedEmpty⟩
  intro f' hf'
  rcases activeFrom f' hf' with h0 | ⟨f, hf, hdata⟩
  · have hemp : IndexView after.index 0#u32 [] := by
      have h := index_empty_root_refines after.index
      unfold CcfKv.kv_index.AddressIndex.empty_root CcfKv.radix.SingleRadix.empty_root at h
      rw [WP.spec_ok] at h
      exact h.2
    rw [h0, index_rows_eq hemp]
    exact hemp
  · by_cases hzero : f'.data = 0#u32
    · have hemp : IndexView after.index 0#u32 [] := by
        have h := index_empty_root_refines after.index
        unfold CcfKv.kv_index.AddressIndex.empty_root CcfKv.radix.SingleRadix.empty_root at h
        rw [WP.spec_ok] at h
        exact h.2
      rw [hzero, index_rows_eq hemp]
      exact hemp
    · have hmem : f'.data ∈ framePins after.activeFrames :=
        List.mem_filterMap.mpr ⟨f', hf', by simp [hzero]⟩
      have hvOld := valid.active f hf
      rw [← hdata] at hvOld
      have hvNew :=
        index_preserves_pins_view pres f'.data _
          (Or.inr (List.mem_append_left extraPins hmem)) hvOld
      rwa [index_rows_eq hvNew]

/-- Project the entire extracted frame into the executable model. -/
noncomputable def modelFrame (encode : List U8 → String) (index : CellIndex)
    (frame : CcfKv.engine.Frame)
    : Kv.Model.Frame :=
  {
    modelMetadata (encode ∘ alloc.vec.Vec.val) frame with
      data := encodeData encode (indexedCellData (indexRows index frame.data))
  }

/-- A native frame agrees on all metadata fields with its ghost archive entry. -/
def FrameMetaEq (encode : List U8 → String) (nf : CcfKv.engine.Frame)
    (gf : Kv.Model.Frame)
    : Prop :=
  gf.version = nf.version.val
  ∧ gf.revisions = (modelMetadata (encode ∘ alloc.vec.Vec.val) nf).revisions
  ∧ gf.births = (modelMetadata (encode ∘ alloc.vec.Vec.val) nf).births

theorem frame_meta_eq_modelFrame (encode : List U8 → String) (index : CellIndex)
    (nf : CcfKv.engine.Frame)
    : FrameMetaEq encode nf (modelFrame encode index nf) :=
  ⟨rfl, rfl, rfl⟩

/-- Alignment between the ring-buffered active suffix + metadata-only `retained`
frames and the full newest-first ghost native branch `natHistory`. -/
structure ArchiveAligned (encode : List U8 → String) (history : CcfKv.engine.History)
    (natHistory : List Kv.Model.Frame)
    : Prop where
  nonempty : 0 < natHistory.length
  base
    : ∃ baseFrame,
        history.activeFrames[0]? = some baseFrame
        ∧ baseFrame.version.val ≤ history.global.val
        ∧ (history.reuse_compacted_images = true → baseFrame.version = history.global)
        ∧ baseFrame.version.val + history.activeFrames.length = natHistory.length
  activeEq
    : ∀ (baseFrame : CcfKv.engine.Frame),
        history.activeFrames[0]? = some baseFrame
        → ∀ (i : Nat) (hi : i < history.activeFrames.length),
            natHistory.reverse[baseFrame.version.val + i]?
            = some (modelFrame encode history.index (history.activeFrames[i]'hi))
  retainedEq
    : ∀ rf ∈ history.retained.val,
        rf.version.val < history.global.val
        ∧ rf.data = 0#u32
        ∧ ∃ gf, natHistory.reverse[rf.version.val]? = some gf ∧ FrameMetaEq encode rf gf
  retainedReuse : history.reuse_compacted_images = false → history.retained.val = []
  verIndexed : ∀ (v : Nat) gf, natHistory.reverse[v]? = some gf → gf.version = v

theorem ArchiveAligned.active_version {encode : List U8 → String}
    {history : CcfKv.engine.History} {natHistory : List Kv.Model.Frame}
    (aligned : ArchiveAligned encode history natHistory)
    (baseFrame : CcfKv.engine.Frame) (hbase : history.activeFrames[0]? = some baseFrame)
    (i : Nat) (hi : i < history.activeFrames.length)
    : (history.activeFrames[i]'hi).version.val = baseFrame.version.val + i := by
  have heq := aligned.activeEq baseFrame hbase i hi
  have hv := aligned.verIndexed (baseFrame.version.val + i) _ heq
  simpa [modelFrame, modelMetadata] using hv

theorem ArchiveAligned.active_mem_nat {encode : List U8 → String}
    {history : CcfKv.engine.History} {natHistory : List Kv.Model.Frame}
    (aligned : ArchiveAligned encode history natHistory)
    (f : CcfKv.engine.Frame) (hf : f ∈ history.activeFrames)
    : modelFrame encode history.index f ∈ natHistory := by
  obtain ⟨baseFrame, hbase, _, _, _⟩ := aligned.base
  obtain ⟨i, hi, rfl⟩ := List.mem_iff_getElem.mp hf
  have hmemRev : modelFrame encode history.index (history.activeFrames[i]'hi) ∈ natHistory.reverse :=
    List.mem_of_getElem? (aligned.activeEq baseFrame hbase i hi)
  exact List.mem_reverse.mp hmemRev

theorem ArchiveAligned.head_eq {encode : List U8 → String}
    {history : CcfKv.engine.History} {natHistory : List Kv.Model.Frame}
    (aligned : ArchiveAligned encode history natHistory)
    {prior : List CcfKv.engine.Frame} {head : CcfKv.engine.Frame}
    (hsplit : history.activeFrames = prior ++ [head])
    : natHistory.head? = some (modelFrame encode history.index head) := by
  obtain ⟨baseFrame, hbase, _, _, hsum⟩ := aligned.base
  have hidx : prior.length < history.activeFrames.length := by simp [hsplit]
  have hheadAt : history.activeFrames[prior.length]'hidx = head := by
    apply Option.some.inj
    rw [← List.getElem?_eq_getElem hidx, hsplit]
    simp
  have heq := aligned.activeEq baseFrame hbase prior.length hidx
  rw [hheadAt] at heq
  have hlen : baseFrame.version.val + prior.length = natHistory.length - 1 := by
    rw [hsplit, List.length_append, List.length_singleton] at hsum; omega
  rw [hlen, List.getElem?_reverse (by have := aligned.nonempty; omega)] at heq
  have hsub : natHistory.length - 1 - (natHistory.length - 1) = 0 := Nat.sub_self _
  rw [hsub] at heq
  simpa [List.head?_eq_getElem?] using heq

theorem ArchiveAligned.of_preserves_pins {encode : List U8 → String}
    {before after : CcfKv.engine.History} {natHistory : List Kv.Model.Frame}
    {extraPins : List U32}
    (aligned : ArchiveAligned encode before natHistory)
    (validBefore : HistoryIndexValid before)
    (pres
      : IndexPreservesPins before.index after.index
          (framePins after.activeFrames ++ extraPins))
    (hact : after.activeFrames = before.activeFrames)
    (hret : ∀ rf ∈ after.retained.val, rf ∈ before.retained.val)
    (hglobal : after.global = before.global)
    (hreuse : after.reuse_compacted_images = before.reuse_compacted_images)
    : ArchiveAligned encode after natHistory := by
  refine ⟨aligned.nonempty, ?_, ?_, ?_, ?_, aligned.verIndexed⟩
  · obtain ⟨bf, hbf, hle, hre, hsum⟩ := aligned.base
    exact ⟨bf, hact.symm ▸ hbf, hglobal.symm ▸ hle,
      fun h => hglobal.symm ▸ hre (hreuse ▸ h), hact.symm ▸ hsum⟩
  · intro bf hbf i hi
    have hbf0 : before.activeFrames[0]? = some bf := hact ▸ hbf
    have hi0 : i < before.activeFrames.length := hact ▸ hi
    have hprev := aligned.activeEq bf hbf0 i hi0
    have hgetEq : after.activeFrames[i]'hi = before.activeFrames[i]'hi0 := by
      apply Option.some.inj
      rw [← List.getElem?_eq_getElem hi, ← List.getElem?_eq_getElem hi0, hact]
    rw [hgetEq]
    let f := before.activeFrames[i]'hi0
    have hfMem : f ∈ after.activeFrames := by rw [hact]; exact List.getElem_mem hi0
    have hpin : f.data = 0#u32 ∨ f.data ∈ framePins after.activeFrames ++ extraPins := by
      by_cases hz : f.data = 0#u32
      · exact Or.inl hz
      · exact Or.inr (List.mem_append_left extraPins (List.mem_filterMap.mpr ⟨f, hfMem, by simp [hz]⟩))
    have hview := index_preserves_pins_view pres f.data _ hpin
      (validBefore.active f (List.getElem_mem hi0))
    have hrows : indexRows after.index (before.activeFrames[i]'hi0).data =
        indexRows before.index (before.activeFrames[i]'hi0).data :=
      index_rows_eq hview
    simpa only [modelFrame, hrows] using hprev
  · intro rf hrf
    rw [hglobal]
    exact aligned.retainedEq rf (hret rf hrf)
  · intro hf
    have hemp := aligned.retainedReuse (hreuse ▸ hf)
    cases h : after.retained.val with
    | nil => rfl
    | cons x _ =>
        have hx := hret x (by rw [h]; exact List.mem_cons_self)
        rw [hemp] at hx
        cases hx

theorem ArchiveAligned.append {encode : List U8 → String}
    {before after : CcfKv.engine.History} {natHistory : List Kv.Model.Frame}
    {nfNew : CcfKv.engine.Frame} {extraPins : List U32}
    (aligned : ArchiveAligned encode before natHistory)
    (validBefore : HistoryIndexValid before)
    (pres
      : IndexPreservesPins before.index after.index
          (framePins after.activeFrames ++ extraPins))
    (hact : after.activeFrames = before.activeFrames ++ [nfNew])
    (hret : after.retained = before.retained)
    (hglobal : after.global = before.global)
    (hreuse : after.reuse_compacted_images = before.reuse_compacted_images)
    (hverNew : nfNew.version.val = natHistory.length)
    : ArchiveAligned encode after
        (modelFrame encode after.index nfNew :: natHistory) := by
  refine ⟨by simp, ?_, ?_, ?_, ?_, ?_⟩
  · obtain ⟨bf, hbf, hle, hre, hsum⟩ := aligned.base
    have hpos0 : 0 < before.activeFrames.length := (List.getElem?_eq_some_iff.mp hbf).1
    refine ⟨bf, by rw [hact, List.getElem?_append_left hpos0]; exact hbf,
      hglobal.symm ▸ hle, fun h => hglobal.symm ▸ hre (hreuse ▸ h), ?_⟩
    rw [hact, List.length_append, List.length_singleton, List.length_cons]
    omega
  · intro bf hbf i hi
    obtain ⟨bf0, hbf0, _, _, hsum⟩ := aligned.base
    have hpos0 : 0 < before.activeFrames.length := (List.getElem?_eq_some_iff.mp hbf0).1
    have hbfEq : bf = bf0 := by
      have : after.activeFrames[0]? = some bf0 := by
        rw [hact, List.getElem?_append_left hpos0]; exact hbf0
      exact Option.some.inj (hbf.symm.trans this)
    subst hbfEq
    rw [List.reverse_cons]
    by_cases hlt : i < before.activeFrames.length
    · have hgetEq : after.activeFrames[i]'hi = before.activeFrames[i]'hlt := by
        apply Option.some.inj
        rw [← List.getElem?_eq_getElem hi, ← List.getElem?_eq_getElem hlt, hact,
          List.getElem?_append_left hlt]
      rw [hgetEq, List.getElem?_append_left (by rw [List.length_reverse]; omega)]
      let f := before.activeFrames[i]'hlt
      have hfMem : f ∈ after.activeFrames := by
        rw [hact]; exact List.mem_append_left _ (List.getElem_mem hlt)
      have hpin : f.data = 0#u32 ∨ f.data ∈ framePins after.activeFrames ++ extraPins := by
        by_cases hz : f.data = 0#u32
        · exact Or.inl hz
        · exact Or.inr (List.mem_append_left extraPins (List.mem_filterMap.mpr ⟨f, hfMem, by simp [hz]⟩))
      have hview := index_preserves_pins_view pres f.data _ hpin
        (validBefore.active f (List.getElem_mem hlt))
      have hrows : indexRows after.index (before.activeFrames[i]'hlt).data =
          indexRows before.index (before.activeFrames[i]'hlt).data :=
        index_rows_eq hview
      have hprev := aligned.activeEq bf hbf0 i hlt
      simpa only [modelFrame, hrows] using hprev
    · have hiEq : i = before.activeFrames.length := by
        rw [hact, List.length_append, List.length_singleton] at hi; omega
      have hgetEq : after.activeFrames[i]'hi = nfNew := by
        apply Option.some.inj
        rw [← List.getElem?_eq_getElem hi, hact, hiEq, List.getElem?_append_right (Nat.le_refl _),
          Nat.sub_self]
        rfl
      rw [hgetEq, hiEq, hsum, List.getElem?_append_right (by rw [List.length_reverse]),
        List.length_reverse, Nat.sub_self]
      rfl
  · intro rf hrf
    rw [hret] at hrf
    obtain ⟨hltG, h0, gf, hgf, hmeta⟩ := aligned.retainedEq rf hrf
    have hltLen : rf.version.val < natHistory.length := by
      have := (List.getElem?_eq_some_iff.mp hgf).1
      rwa [List.length_reverse] at this
    refine ⟨hglobal.symm ▸ hltG, h0, gf, ?_, hmeta⟩
    rw [List.reverse_cons, List.getElem?_append_left (by rw [List.length_reverse]; exact hltLen)]
    exact hgf
  · intro hf
    rw [hret]
    exact aligned.retainedReuse (hreuse ▸ hf)
  · intro v gf hgf
    rw [List.reverse_cons] at hgf
    by_cases hlt : v < natHistory.length
    · rw [List.getElem?_append_left (by rw [List.length_reverse]; exact hlt)] at hgf
      exact aligned.verIndexed v gf hgf
    · rw [List.getElem?_append_right (by rw [List.length_reverse]; exact Nat.le_of_not_gt hlt)] at hgf
      have hveq : v = natHistory.length := by
        have := (List.getElem?_eq_some_iff.mp hgf).1
        simp at this; omega
      subst hveq
      rw [List.length_reverse, Nat.sub_self] at hgf
      have hgfEq : gf = modelFrame encode after.index nfNew := Option.some.inj (by simpa using hgf.symm)
      subst hgfEq
      exact hverNew

theorem model_frame_retained (encode : List U8 → String) {before after : CellIndex}
    (kept : IndexKeeps before after) (frame : CcfKv.engine.Frame)
    (view : IndexView before frame.data (indexRows before frame.data))
    : modelFrame encode after frame = modelFrame encode before frame := by
  have same := index_rows_eq (index_keeps_view kept _ _ view)
  simp only [modelFrame, same]

theorem model_frame_retained_active (encode : List U8 → String)
    {history : CcfKv.engine.History} {arena : CellIndex}
    (valid : HistoryIndexValid history) (kept : IndexKeeps history.index arena)
    : history.activeFrames.map (modelFrame encode arena)
      = history.activeFrames.map (modelFrame encode history.index) := by
  apply List.map_congr_left
  intro frame mem
  exact model_frame_retained encode kept frame (valid.active frame mem)

theorem HistoryIndexValid.append {before after : CcfKv.engine.History}
    (valid : HistoryIndexValid before) (kept : IndexKeeps before.index after.index)
    (live : IndexValid after.index) (frame : CcfKv.engine.Frame)
    (view : IndexView after.index frame.data (indexRows after.index frame.data))
    (hact : after.activeFrames = before.activeFrames ++ [frame])
    (hret : after.retained = before.retained)
    : HistoryIndexValid after := by
  refine ⟨live, ?_, fun f hf => valid.retainedEmpty f (hret ▸ hf)⟩
  intro f hmem
  rw [hact] at hmem
  rcases List.mem_append.mp hmem with old | hnew
  · have preserved := index_keeps_view kept _ _ (valid.active f old)
    rwa [index_rows_eq preserved]
  · rw [List.mem_singleton.mp hnew]
    exact view

/-- Encoded raw-byte order on projected map images, independent of any ordering
on `String` itself. -/
def encKeyLt (encode : List U8 → String) (a b : String × Kv.Model.Cell String) : Prop :=
  ∃ ka kb : List U8, encode ka = a.1 ∧ encode kb = b.1 ∧ ka < kb

private theorem encKeyLt_irrefl {encode : List U8 → String}
    (inj : Function.Injective encode) (a : String × Kv.Model.Cell String)
    : ¬ encKeyLt encode a a := by
  rintro ⟨ka, kb, ha, hb, hlt⟩
  have heq : ka = kb := inj (ha.trans hb.symm)
  exact lt_irrefl kb (heq ▸ hlt)

private theorem encKeyLt_trans {encode : List U8 → String}
    (inj : Function.Injective encode) {a b c : String × Kv.Model.Cell String}
    (ab : encKeyLt encode a b) (bc : encKeyLt encode b c)
    : encKeyLt encode a c := by
  obtain ⟨ka, kb, ha, hb, hlt1⟩ := ab
  obtain ⟨kb', kc, hb', hc, hlt2⟩ := bc
  have hkb : kb = kb' := inj (hb.trans hb'.symm)
  exact ⟨ka, kc, ha, hc, lt_trans hlt1 (hkb ▸ hlt2)⟩

theorem encKeyLt_perm_eq {encode : List U8 → String}
    (inj : Function.Injective encode) {a b : List (String × Kv.Model.Cell String)}
    (ha : a.Pairwise (encKeyLt encode)) (hb : b.Pairwise (encKeyLt encode))
    (perm : a.Perm b)
    : a = b := by
  induction a generalizing b with
  | nil => exact perm.nil_eq
  | cons x xs ih =>
      cases b with
      | nil => exact (List.Perm.nil_eq perm.symm).symm
      | cons y ys =>
          obtain ⟨hx, hxs⟩ := List.pairwise_cons.mp ha
          obtain ⟨hy, hys⟩ := List.pairwise_cons.mp hb
          have hxy : x = y := by
            have hyIn : y ∈ x :: xs := perm.symm.subset List.mem_cons_self
            have hxIn : x ∈ y :: ys := perm.subset List.mem_cons_self
            rcases List.mem_cons.mp hyIn with rfl | hyXs
            · rfl
            · rcases List.mem_cons.mp hxIn with rfl | hxYs
              · rfl
              · exact (encKeyLt_irrefl inj x (encKeyLt_trans inj (hx y hyXs) (hy x hxYs))).elim
          subst hxy
          exact congrArg (List.cons x) (ih hxs hys (List.Perm.cons_inv perm))

private theorem packed_same_map_lt {a b : CcfKv.engine.Address}
    (hmap : a.map.val = b.map.val) (hlt : packedAddress a < packedAddress b)
    : a.key.val < b.key.val := by
  have hbo : byteOrder (packedAddress a) (packedAddress b) < 0#i8 := (byteOrder_lt _ _).mpr hlt
  have hpre : ∀ (p xs ys : List U8), byteOrder (p ++ xs) (p ++ ys) = byteOrder xs ys := by
    intro p xs ys
    induction p with
    | nil => rfl
    | cons h t ih => simp [byteOrder, ih]
  unfold packedAddress addressBytes at hbo
  rw [hmap, List.append_assoc, List.append_assoc, hpre, hpre] at hbo
  exact (byteOrder_lt _ _).mp hbo

theorem modelFrame_image_sorted {encode : List U8 → String}
    (inj : Function.Injective encode) (index : CellIndex) (frame : CcfKv.engine.Frame)
    (view : IndexView index frame.data (indexRows index frame.data)) (m : String)
    : (Kv.Model.image (modelFrame encode index frame).data m).Pairwise
        (encKeyLt encode) := by
  have hsort := index_view_sorted view
  change (Kv.Model.image (encodeData encode (indexedCellData (indexRows index frame.data))) m).Pairwise
    (encKeyLt encode)
  generalize indexRows index frame.data = rows at hsort
  induction rows with
  | nil => simp [indexedCellData, encodeData, Kv.Model.image]
  | cons row rest ih =>
      obtain ⟨a, c⟩ := row
      obtain ⟨hhead, hrest⟩ := List.pairwise_cons.mp hsort
      by_cases hm : encode a.map.val = m
      · simp only [indexedCellData, encodeData, encodeAddr, byteAddr, List.map_cons,
          Kv.Model.image, List.filterMap_cons, hm, ite_true]
        refine List.pairwise_cons.mpr ⟨?_, ih hrest⟩
        intro y hy
        obtain ⟨⟨⟨mt, kt⟩, ct⟩, hmem, hfilt⟩ := List.mem_filterMap.mp hy
        have hmt : mt = m := by
          by_cases h : mt = m
          · exact h
          · simp [h] at hfilt
        have hpair : (kt, ct) = y := by simpa [hmt] using hfilt
        obtain ⟨⟨⟨mb, kb⟩, cb⟩, hmem1, hpair1⟩ := List.mem_map.mp hmem
        obtain ⟨⟨ab, cb'⟩, hmem2, hpair2⟩ := List.mem_map.mp hmem1
        have habMap : encode ab.map.val = m := by
          have h1 : encode mb = mt := congrArg (fun x => x.1.1) hpair1
          have h2 : ab.map.val = mb := congrArg (fun x => x.1.1) hpair2
          exact (congrArg encode h2).trans (h1.trans hmt)
        have habKey : encode ab.key.val = y.1 := by
          have h1 : encode kb = kt := congrArg (fun x => x.1.2) hpair1
          have h2 : ab.key.val = kb := congrArg (fun x => x.1.2) hpair2
          have h3 : kt = y.1 := congrArg Prod.fst hpair
          exact (congrArg encode h2).trans (h1.trans h3)
        have hsameMap : a.map.val = ab.map.val := inj (hm.trans habMap.symm)
        exact ⟨a.key.val, ab.key.val, rfl, habKey, packed_same_map_lt hsameMap (hhead (ab, cb') hmem2)⟩
      · simp only [indexedCellData, encodeData, encodeAddr, byteAddr, List.map_cons,
          Kv.Model.image, List.filterMap_cons, hm, ite_false]
        exact ih hrest

/-- Under single-radix storage, any two valid frames whose projected map images
are permutations of each other have identical map images. -/
theorem modelFrame_image_eq_of_perm {encode : List U8 → String}
    (inj : Function.Injective encode) (index : CellIndex) (f1 f2 : CcfKv.engine.Frame)
    (v1 : IndexView index f1.data (indexRows index f1.data))
    (v2 : IndexView index f2.data (indexRows index f2.data)) (m : String)
    (perm
      : (Kv.Model.image (modelFrame encode index f1).data m).Perm
          (Kv.Model.image (modelFrame encode index f2).data m))
    : Kv.Model.image (modelFrame encode index f1).data m
      = Kv.Model.image (modelFrame encode index f2).data m :=
  encKeyLt_perm_eq inj
    (modelFrame_image_sorted inj index f1 v1 m)
    (modelFrame_image_sorted inj index f2 v2 m)
    perm

end KvRust
