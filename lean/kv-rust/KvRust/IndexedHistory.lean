-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lineage

@[expose] public section

namespace KvRust

open Aeneas.Std

/-- Every archived slot has a valid view, not just the slots on the current branch. -/
structure HistoryIndexValid (history : CcfKv.engine.History) : Prop where
  index : IndexValid history.index
  archived
    : ∀ (i : Nat) (frame : CcfKv.engine.Frame),
        history.log.frames.val[i]? = some frame
        → IndexView history.index frame.data (indexRows history.index frame.data)

theorem HistoryIndexValid.active {history : CcfKv.engine.History}
    (valid : HistoryIndexValid history) (frame : CcfKv.engine.Frame)
    (active : frame ∈ history.activeFrames)
    : IndexView history.index frame.data (indexRows history.index frame.data) := by
  obtain ⟨id, _, saved⟩ := List.mem_filterMap.mp active
  exact valid.archived id.val frame saved

theorem HistoryIndexValid.head {history : CcfKv.engine.History}
    (valid : HistoryIndexValid history) (prior : List CcfKv.engine.Frame)
    (frame : CcfKv.engine.Frame) (split : history.activeFrames = prior ++ [frame])
    : IndexView history.index frame.data (indexRows history.index frame.data) :=
  valid.active frame (by simp [split])

theorem HistoryIndexValid.congr {before after : CcfKv.engine.History}
    (valid : HistoryIndexValid before) (sameIndex : after.index = before.index)
    (sameArchive : after.log.frames = before.log.frames)
    : HistoryIndexValid after := by
  refine ⟨sameIndex.symm ▸ valid.index, ?_⟩
  intro i frame saved
  rw [sameIndex]
  exact valid.archived i frame (by simpa only [sameArchive] using saved)

/-- A persistent history update preserves both the frame slots and their storage roots. -/
structure HistoryKeeps (before after : CcfKv.engine.History) : Prop where
  slots : FrameSlotsPreserved before after
  index : IndexKeeps before.index after.index

theorem HistoryKeeps.of_same {before after : CcfKv.engine.History}
    (sameSlots : after.log.frames = before.log.frames)
    (sameIndex : after.index = before.index)
    : HistoryKeeps before after :=
  ⟨FrameSlotsPreserved.of_same before after sameSlots, sameIndex.symm ▸ .refl _⟩

theorem HistoryKeeps.rows {before after : CcfKv.engine.History}
    (kept : HistoryKeeps before after) (valid : HistoryIndexValid before) (i : Nat)
    (frame : CcfKv.engine.Frame) (saved : before.log.frames.val[i]? = some frame)
    : indexRows after.index frame.data = indexRows before.index frame.data :=
  index_rows_eq (index_keeps_view kept.index _ _ (valid.archived i frame saved))

theorem HistoryIndexValid.of_preserves_pins {before after : CcfKv.engine.History}
    {extraPins : List U32}
    (valid : HistoryIndexValid before)
    (liveAfter : IndexValid after.index)
    (pres
      : IndexPreservesPins before.index after.index
          (framePins after.log.frames.val ++ extraPins))
    (slots
      : ∀ (i : Nat) (f' : CcfKv.engine.Frame),
          after.log.frames.val[i]? = some f'
          → f'.data = 0#u32
            ∨ ∃ (j : Nat) (f : CcfKv.engine.Frame),
                before.log.frames.val[j]? = some f ∧ f'.data = f.data)
    : HistoryIndexValid after := by
  refine ⟨liveAfter, ?_⟩
  intro i f' hf'
  rcases slots i f' hf' with h0 | ⟨j, f, hf, hdata⟩
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
    · have hmem : f'.data ∈ framePins after.log.frames.val :=
        List.mem_filterMap.mpr ⟨f', List.mem_iff_getElem?.mpr ⟨i, hf'⟩, by simp [hzero]⟩
      have hvOld := valid.archived j f hf
      rw [← hdata] at hvOld
      have hvNew := index_preserves_pins_view pres f'.data _ (Or.inr (List.mem_append_left extraPins hmem)) hvOld
      rwa [index_rows_eq hvNew]

/-- Project the entire extracted frame into the executable model. -/
noncomputable def modelFrame (encode : List U8 → String) (index : CellIndex)
    (frame : CcfKv.engine.Frame)
    : Kv.Model.Frame :=
  {
    modelMetadata (encode ∘ alloc.vec.Vec.val) frame with
      data := encodeData encode (indexedCellData (indexRows index frame.data))
  }

/-- Ghost active branch frames derived from the immutable ghost native archive. -/
def natModelFrames (log : CcfKv.branch_log.BranchLog CcfKv.engine.Frame)
    (natArchive : List Kv.Model.Frame)
    : List Kv.Model.Frame :=
  log.branch.val.reverse.filterMap fun id => natArchive[id.val]?

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

/-- Alignment between the native frame archive (whose compacted/rolled-back
entries may have `data = 0#u32` and elided metadata when `meta_live = false`)
and the immutable ghost native archive `natArchive`. -/
structure ArchiveAligned (encode : List U8 → String) (history : CcfKv.engine.History)
    (natArchive : List Kv.Model.Frame)
    : Prop where
  len : natArchive.length = history.log.frames.val.length
  versionEq
    : ∀ (i : Nat) nf gf,
        history.log.frames.val[i]? = some nf
        → natArchive[i]? = some gf
        → gf.version = nf.version.val
  metaEq
    : ∀ (i : Nat) nf gf,
        history.log.frames.val[i]? = some nf
        → natArchive[i]? = some gf
        → nf.meta_live = true
        → FrameMetaEq encode nf gf
  globalMetaLive
    : ∀ (off : Nat) (id : Usize) nf,
        history.log.branch.val[off]? = some id
        → history.log.frames.val[id.val]? = some nf
        → (history.reuse_compacted_images = true → history.global.val ≤ nf.version.val)
        → nf.meta_live = true
  activeLive
    : ∀ (off : Nat) (id : Usize) nf gf,
        history.log.branch.val[off]? = some id
        → history.log.frames.val[id.val]? = some nf
        → natArchive[id.val]? = some gf
        → (history.reuse_compacted_images = true → history.global.val ≤ nf.version.val)
        → modelFrame encode history.index nf = gf

theorem natModelFrames_length {log : CcfKv.branch_log.BranchLog CcfKv.engine.Frame}
    {natArchive : List Kv.Model.Frame} (valid : BranchValid log)
    (hlen : natArchive.length = log.frames.val.length)
    : (natModelFrames log natArchive).length = log.branch.val.length := by
  have hl (ids : List Usize) (h : ∀ id ∈ ids, id.val < natArchive.length) :
      (ids.filterMap fun id => natArchive[id.val]?).length = ids.length := by
    induction ids with
    | nil => rfl
    | cons a t ih =>
        simp [List.getElem?_eq_getElem (h a List.mem_cons_self),
          ih (fun x hx => h x (List.mem_cons_of_mem _ hx))]
  unfold natModelFrames
  rw [hl _ (fun id hid => hlen.symm ▸ valid.2 id (List.mem_reverse.mp hid)), List.length_reverse]

theorem natModelFrames_append
    {before after : CcfKv.branch_log.BranchLog CcfKv.engine.Frame}
    {natArchive : List Kv.Model.Frame} {gf : Kv.Model.Frame} {id : Usize}
    (valid : BranchValid before) (hlen : natArchive.length = before.frames.val.length)
    (hid : id.val = before.frames.val.length)
    (hbr : after.branch.val = before.branch.val ++ [id])
    : natModelFrames after (natArchive ++ [gf])
      = gf :: natModelFrames before natArchive := by
  unfold natModelFrames
  rw [hbr, List.reverse_append, List.reverse_singleton, List.singleton_append, List.filterMap_cons]
  have hnew : (natArchive ++ [gf])[id.val]? = some gf := by
    rw [hid, ← hlen, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]; rfl
  rw [hnew]
  dsimp only
  congr 1
  apply List.filterMap_congr
  intro x hx
  have hlt : x.val < natArchive.length := hlen.symm ▸ valid.2 x (List.mem_reverse.mp hx)
  exact List.getElem?_append_left hlt

private theorem list_filter_is_take {α : Type} (xs : List α) (p : α → Bool) (n : Nat)
    (h : ∀ i (hi : i < xs.length), p xs[i] = decide (i < n))
    : xs.filter p = xs.take n := by
  induction xs generalizing n with
  | nil => simp
  | cons x xs ih =>
      have hhead := h 0 (by simp)
      change p x = decide (0 < n) at hhead
      cases n with
      | zero =>
          have htail : ∀ i (hi : i < xs.length), p xs[i] = decide (i < 0) := by
            intro i hi
            have he := h (i + 1) (by simp; omega)
            change p xs[i] = decide (i + 1 < 0) at he
            simpa using he
          simp [hhead, ih 0 htail]
      | succ n =>
          have htail : ∀ i (hi : i < xs.length), p xs[i] = decide (i < n) := by
            intro i hi
            have he := h (i + 1) (by simp; omega)
            change p xs[i] = decide (i + 1 < n + 1) at he
            simpa using he
          simp [hhead, ih n htail]

theorem natModelFrames_take {before after : CcfKv.branch_log.BranchLog CcfKv.engine.Frame}
    {natArchive : List Kv.Model.Frame} {n : Nat}
    (valid : BranchValid before) (hlen : natArchive.length = before.frames.val.length)
    (hbr : after.branch.val = before.branch.val.take n)
    (hver
      : ∀ (i : Nat) (hi : i < before.branch.val.length) (gf : Kv.Model.Frame),
          natArchive[before.branch.val[i].val]? = some gf → gf.version = i)
    (hn : 0 < n)
    : natModelFrames after natArchive
      = (natModelFrames before natArchive).filter
          (fun f => decide (f.version ≤ n - 1)) := by
  have hfm_rev : ∀ (ids : List Usize),
      ids.reverse.filterMap (fun id => natArchive[id.val]?)
      = (ids.filterMap fun id => natArchive[id.val]?).reverse := by
    intro ids
    induction ids with
    | nil => rfl
    | cons a t ih =>
        simp [List.reverse_cons, List.filterMap_append, List.filterMap_cons, ih]
        cases natArchive[a.val]? <;> simp
  unfold natModelFrames
  rw [hbr, hfm_rev, hfm_rev, List.filter_reverse]
  congr 1
  have hbd : ∀ id ∈ before.branch.val, id.val < natArchive.length :=
    fun id hid => hlen.symm ▸ valid.2 id hid
  have htake : ∀ (ids : List Usize) (m : Nat),
      (∀ id ∈ ids, id.val < natArchive.length) →
      (ids.take m).filterMap (fun id => natArchive[id.val]?) =
      (ids.filterMap (fun id => natArchive[id.val]?)).take m := by
    intro ids
    induction ids with
    | nil => intro m _; simp
    | cons a t ih =>
        intro m hbd'
        have hb := hbd' a List.mem_cons_self
        have hr := fun k => ih k (fun x hx => hbd' x (List.mem_cons_of_mem _ hx))
        cases m <;> simp [List.getElem?_eq_getElem hb, hr]
  rw [htake _ _ hbd]
  symm
  apply list_filter_is_take
  intro i hi
  have hlenF : (before.branch.val.filterMap fun id => natArchive[id.val]?).length =
      before.branch.val.length := by
    have := natModelFrames_length valid hlen
    unfold natModelFrames at this
    rw [hfm_rev, List.length_reverse] at this
    exact this
  have hi' : i < before.branch.val.length := hlenF ▸ hi
  have hget : ∀ (ids : List Usize) (k : Nat) (hk : k < ids.length),
      (∀ id ∈ ids, id.val < natArchive.length) →
      (ids.filterMap fun id => natArchive[id.val]?)[k]? = natArchive[ids[k].val]? := by
    intro ids
    induction ids with
    | nil => intro k hk _; simp at hk
    | cons a t ih =>
        intro k hk hbd'
        have hb := hbd' a List.mem_cons_self
        cases k with
        | zero => simp [List.getElem?_eq_getElem hb]
        | succ j =>
            simp only [List.filterMap_cons, List.getElem?_eq_getElem hb, List.getElem?_cons_succ,
              List.getElem_cons_succ]
            exact ih j (by simpa using hk)
              (fun x hx => hbd' x (List.mem_cons_of_mem _ hx))
  have hv := hver i hi' ((before.branch.val.filterMap fun id => natArchive[id.val]?)[i])
    (by rw [← hget _ i hi' hbd, List.getElem?_eq_getElem hi])
  rw [hv]
  exact decide_eq_decide.mpr (by omega)

theorem ArchiveAligned.of_preserves_pins {encode : List U8 → String}
    {before after : CcfKv.engine.History} {natArchive : List Kv.Model.Frame}
    {extraPins : List U32}
    (aligned : ArchiveAligned encode before natArchive)
    (validBefore : HistoryIndexValid before)
    (pres
      : IndexPreservesPins before.index after.index
          (framePins after.log.frames.val ++ extraPins))
    (hbr : after.log.branch = before.log.branch)
    (hframes : after.log.frames = before.log.frames)
    (hglobal : after.global = before.global)
    (hreuse : after.reuse_compacted_images = before.reuse_compacted_images)
    : ArchiveAligned encode after natArchive := by
  refine ⟨
    by rw [hframes]; exact aligned.len,
    fun i nf gf hnf hgf => aligned.versionEq i nf gf (hframes ▸ hnf) hgf,
    fun i nf gf hnf hgf hml => aligned.metaEq i nf gf (hframes ▸ hnf) hgf hml,
    fun off id nf hid hnf hlive =>
      aligned.globalMetaLive off id nf (hbr ▸ hid) (hframes ▸ hnf)
        (by rw [← hreuse, ← hglobal]; exact hlive),
    ?_
  ⟩
  intro off id nf gf hid hnf hgf hlive
  have hnf0 : before.log.frames.val[id.val]? = some nf := hframes ▸ hnf
  have hmf0 := aligned.activeLive off id nf gf (hbr ▸ hid) hnf0 hgf
    (by rw [← hreuse, ← hglobal]; exact hlive)
  have hpin : nf.data = 0#u32 ∨ nf.data ∈ framePins after.log.frames.val ++ extraPins := by
    by_cases hz : nf.data = 0#u32
    · exact Or.inl hz
    · exact Or.inr (List.mem_append_left extraPins
        (List.mem_filterMap.mpr ⟨nf, List.mem_iff_getElem?.mpr ⟨id.val, hnf⟩, by simp [hz]⟩))
  have hview := index_preserves_pins_view pres nf.data _ hpin (validBefore.archived id.val nf hnf0)
  have hrows : indexRows after.index nf.data = indexRows before.index nf.data :=
    index_rows_eq hview
  simpa only [modelFrame, hrows] using hmf0

theorem ArchiveAligned.append {encode : List U8 → String}
    {before after : CcfKv.engine.History} {natArchive : List Kv.Model.Frame}
    {nfNew : CcfKv.engine.Frame} {idNew : Usize} {extraPins : List U32}
    (aligned : ArchiveAligned encode before natArchive)
    (validBefore : HistoryIndexValid before)
    (validLogBefore : BranchValid before.log)
    (pres
      : IndexPreservesPins before.index after.index
          (framePins after.log.frames.val ++ extraPins))
    (hframes : after.log.frames.val = before.log.frames.val ++ [nfNew])
    (hbr : after.log.branch.val = before.log.branch.val ++ [idNew])
    (hidNew : idNew.val = before.log.frames.val.length)
    (hglobal : after.global = before.global)
    (hreuse : after.reuse_compacted_images = before.reuse_compacted_images)
    (hmetaNew : nfNew.meta_live = true)
    : ArchiveAligned encode after
        (natArchive ++ [modelFrame encode after.index nfNew]) := by
  refine ⟨
    by rw [hframes, List.length_append, List.length_append, aligned.len]; rfl,
    ?_,
    ?_,
    ?_,
    ?_
  ⟩
  · intro i nf gf hnf hgf
    rw [hframes] at hnf
    by_cases hlt : i < before.log.frames.val.length
    · rw [List.getElem?_append_left hlt] at hnf
      rw [List.getElem?_append_left (aligned.len.symm ▸ hlt)] at hgf
      exact aligned.versionEq i nf gf hnf hgf
    · have hge := Nat.le_of_not_gt hlt
      rw [List.getElem?_append_right hge] at hnf
      rw [List.getElem?_append_right (aligned.len.symm ▸ hge)] at hgf
      have hsub : i - before.log.frames.val.length = 0 := by
        have := (List.getElem?_eq_some_iff.mp hnf).1
        simp at this; omega
      have hsub' : i - natArchive.length = 0 := aligned.len.symm ▸ hsub
      rw [hsub] at hnf; rw [hsub'] at hgf
      have hnfEq : nf = nfNew := Option.some.inj (by simpa using hnf.symm)
      have hgfEq : gf = modelFrame encode after.index nfNew := Option.some.inj (by simpa using hgf.symm)
      subst hnfEq hgfEq
      rfl
  · intro i nf gf hnf hgf hml
    rw [hframes] at hnf
    by_cases hlt : i < before.log.frames.val.length
    · rw [List.getElem?_append_left hlt] at hnf
      rw [List.getElem?_append_left (aligned.len.symm ▸ hlt)] at hgf
      exact aligned.metaEq i nf gf hnf hgf hml
    · have hge := Nat.le_of_not_gt hlt
      rw [List.getElem?_append_right hge] at hnf
      rw [List.getElem?_append_right (aligned.len.symm ▸ hge)] at hgf
      have hsub : i - before.log.frames.val.length = 0 := by
        have := (List.getElem?_eq_some_iff.mp hnf).1
        simp at this; omega
      have hsub' : i - natArchive.length = 0 := aligned.len.symm ▸ hsub
      rw [hsub] at hnf; rw [hsub'] at hgf
      have hnfEq : nf = nfNew := Option.some.inj (by simpa using hnf.symm)
      have hgfEq : gf = modelFrame encode after.index nfNew := Option.some.inj (by simpa using hgf.symm)
      subst hnfEq hgfEq
      exact frame_meta_eq_modelFrame encode after.index nf
  · intro off id nf hid hnf hlive
    rw [hbr] at hid
    by_cases hoff : off < before.log.branch.val.length
    · rw [List.getElem?_append_left hoff] at hid
      have hidLt : id.val < before.log.frames.val.length :=
        validLogBefore.2 id (List.mem_iff_getElem?.mpr ⟨off, hid⟩)
      have hnf0 : before.log.frames.val[id.val]? = some nf := by
        rwa [hframes, List.getElem?_append_left hidLt] at hnf
      exact aligned.globalMetaLive off id nf hid hnf0
        (by rw [← hreuse, ← hglobal]; exact hlive)
    · rw [List.getElem?_append_right (Nat.le_of_not_gt hoff)] at hid
      have hsub : off - before.log.branch.val.length = 0 := by
        have := (List.getElem?_eq_some_iff.mp hid).1
        simp at this; omega
      rw [hsub] at hid
      have hidEq : id = idNew := Option.some.inj (by simpa using hid.symm)
      subst hidEq
      rw [hframes, hidNew, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self] at hnf
      have hnfEq : nf = nfNew := Option.some.inj (by simpa using hnf.symm)
      subst hnfEq
      exact hmetaNew
  · intro off id nf gf hid hnf hgf hlive
    rw [hbr] at hid
    by_cases hoff : off < before.log.branch.val.length
    · rw [List.getElem?_append_left hoff] at hid
      have hidLt : id.val < before.log.frames.val.length :=
        validLogBefore.2 id (List.mem_iff_getElem?.mpr ⟨off, hid⟩)
      have hnf0 : before.log.frames.val[id.val]? = some nf := by
        rwa [hframes, List.getElem?_append_left hidLt] at hnf
      have hgf0 : natArchive[id.val]? = some gf := by
        rwa [List.getElem?_append_left (aligned.len.symm ▸ hidLt)] at hgf
      have hmf0 := aligned.activeLive off id nf gf hid hnf0 hgf0
        (by rw [← hreuse, ← hglobal]; exact hlive)
      have hpin : nf.data = 0#u32 ∨ nf.data ∈ framePins after.log.frames.val ++ extraPins := by
        by_cases hz : nf.data = 0#u32
        · exact Or.inl hz
        · exact Or.inr (List.mem_append_left extraPins
            (List.mem_filterMap.mpr ⟨nf, List.mem_iff_getElem?.mpr ⟨id.val, hnf⟩, by simp [hz]⟩))
      have hview := index_preserves_pins_view pres nf.data _ hpin (validBefore.archived id.val nf hnf0)
      have hrows : indexRows after.index nf.data = indexRows before.index nf.data :=
        index_rows_eq hview
      simpa only [modelFrame, hrows] using hmf0
    · rw [List.getElem?_append_right (Nat.le_of_not_gt hoff)] at hid
      have hsub : off - before.log.branch.val.length = 0 := by
        have := (List.getElem?_eq_some_iff.mp hid).1
        simp at this; omega
      rw [hsub] at hid
      have hidEq : id = idNew := Option.some.inj (by simpa using hid.symm)
      subst hidEq
      rw [hframes, hidNew, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self] at hnf
      rw [hidNew, ← aligned.len, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self] at hgf
      have hnfEq : nf = nfNew := Option.some.inj (by simpa using hnf.symm)
      have hgfEq : gf = modelFrame encode after.index nfNew := Option.some.inj (by simpa using hgf.symm)
      subst hnfEq hgfEq
      rfl

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
    (archive : after.log.frames.val = before.log.frames.val ++ [frame])
    : HistoryIndexValid after := by
  refine ⟨live, ?_⟩
  intro i f entry
  rw [archive] at entry
  by_cases old : i < before.log.frames.val.length
  · rw [List.getElem?_append_left old] at entry
    have preserved := index_keeps_view kept _ _ (valid.archived i f entry)
    rwa [index_rows_eq preserved]
  · rw [List.getElem?_append_right (Nat.le_of_not_gt old)] at entry
    have member := List.mem_iff_getElem?.mpr ⟨_, entry⟩
    simpa using List.mem_singleton.mp member ▸ view

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
