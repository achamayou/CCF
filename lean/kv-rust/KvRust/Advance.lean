-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.IndexedHistory
public import KvRust.RetainedCuts
public import KvRust.SortedPublication

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private abbrev Stamps := CcfKv.engine.Assoc CcfKv.engine.Bytes CcfKv.engine.Stamp
private abbrev NativeWrites := CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write
private abbrev StampMap := Assoc String Stamp

local instance : DecidableEq CcfKv.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

local instance : DecidableEq CcfKv.engine.Address :=
  fun a b =>
    decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

private theorem byte_same (a b : CcfKv.engine.Bytes)
    : CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey.same a b = .ok (decide (a = b)) := by
  rw [bytes_same]
  congr 1

private def encodedStamps (encode : CcfKv.engine.Bytes → String) (rows : Stamps)
    : StampMap :=
  rows.val.map fun (m, s) => (encode m, modelStamp s)

private def revisionStep (data : Data) (stamp : Stamp) (rev : StampMap)
    (row : Addr String String × Option String)
    : StampMap :=
  if row.2.isSome || (find data row.1).isSome then Kv.Model.set rev row.1.1 stamp else rev

private def birthStep (stamp : Stamp) (birth : StampMap)
    (row : Addr String String × Option String)
    : StampMap :=
  if (find birth row.1.1).isSome then birth else Kv.Model.set birth row.1.1 stamp

private def encodeRow (encode : List U8 → String)
    (row : CcfKv.engine.Address × CcfKv.engine.Write)
    : Addr String String × Option String :=
  (
    encodeAddr encode (byteAddr row.1),
    match row.2 with
    | .Remove => none
    | .Put value => some (encode (alloc.vec.Vec.val value))
  )

private theorem stamp_set (encode : CcfKv.engine.Bytes → String)
    (inj : Function.Injective encode) (rows : Stamps) (m : CcfKv.engine.Bytes)
    (stamp : CcfKv.engine.Stamp) (hc : rows.val.length < Usize.max)
    : WP.spec
        (CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
          rows m stamp)
        (fun next =>
          encodedStamps encode next
            = Kv.Model.set (encodedStamps encode rows) (encode m) (modelStamp stamp)
          ∧ next.val.length ≤ rows.val.length + 1) := by
  apply WP.spec_mono (assoc_set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
    CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
    rows m stamp (fun a => byte_same a m) clone_bytes (fun _ => rfl) hc)
  intro next he
  constructor
  · simp only [encodedStamps, he, set_projected rows.val m stamp encode modelStamp inj]
  · rw [he, Kv.Model.set, List.length_cons]
    exact Nat.succ_le_succ (List.length_filter_le _ _)

private theorem update_birth_step (encode : List U8 → String)
    (inj : Function.Injective encode) (rows : Stamps)
    (row : CcfKv.engine.Address × CcfKv.engine.Write) (stamp : CcfKv.engine.Stamp)
    (hc : rows.val.length < Usize.max)
    : WP.spec (CcfKv.engine.update_birth rows row.1.map stamp)
        (fun next =>
          encodedStamps (encode ∘ alloc.vec.Vec.val) next
            = birthStep (modelStamp stamp)
                (encodedStamps (encode ∘ alloc.vec.Vec.val) rows) (encodeRow encode row)
          ∧ next.val.length ≤ rows.val.length + 1) := by
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  have hi : Function.Injective enc := inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  let m := row.1.map
  have hf : find (encodedStamps enc rows) (enc m) = (find rows.val m).map modelStamp :=
    find_projected rows.val m enc modelStamp hi
  unfold CcfKv.engine.update_birth
  apply WP.spec_bind (assoc_index CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey rows m
    (fun a => byte_same a m))
  intro i why
  have hs := stamp_set enc hi rows m stamp hc
  change WP.spec _ (fun next => encodedStamps enc next =
    (if (find (encodedStamps enc rows) (enc m)).isSome then encodedStamps enc rows
     else Kv.Model.set (encodedStamps enc rows) (enc m) (modelStamp stamp))
       ∧ next.val.length ≤ rows.val.length + 1)
  cases i with
  | none =>
      simpa [hf, why, clone_bytes] using hs
  | some i =>
      obtain ⟨s, _, he⟩ := why
      simp [hf, he]

private def advanceRevision (revisions : Stamps) (index : CellIndex)
    (root : CcfKv.radix.RadixRoot) (a : CcfKv.engine.Address) (w : CcfKv.engine.Write)
    (stamp : CcfKv.engine.Stamp)
    : Result (Stamps × CcfKv.engine.Address) := do
  let written ←
    match w with
    | .Put _ => Result.ok true
    | .Remove => Result.ok false
  if written then
    let m ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
    let next ←
      CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
        CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
        revisions m stamp
    Result.ok (next, a)
  else
    let c ← CcfKv.kv_index.AddressIndex.get index root a
    if core.option.Option.is_some c then
      let m ← CcfKv.engine.Bytes.Insts.CoreCloneClone.clone a.map
      let next ←
        CcfKv.engine.Assoc.set CcfKv.engine.Bytes.Insts.Ccf_kvEngineKey
          CcfKv.engine.Bytes.Insts.CoreCloneClone CcfKv.engine.Stamp.Insts.CoreCloneClone
          revisions m stamp
      Result.ok (next, a)
    else
      Result.ok (revisions, a)

private theorem update_revision_step (encode : List U8 → String)
    (inj : Function.Injective encode) (revisions : Stamps) (index : CellIndex)
    (root : CcfKv.radix.RadixRoot) (data : CellRows) (view : IndexView index root data)
    (a : CcfKv.engine.Address) (w : CcfKv.engine.Write) (stamp : CcfKv.engine.Stamp)
    (hc : revisions.val.length < Usize.max) (room : IndexKeyRoom (a, w))
    : WP.spec (advanceRevision revisions index root a w stamp)
        (fun (next, addr) =>
          addr = a
          ∧ encodedStamps (encode ∘ alloc.vec.Vec.val) next
            = revisionStep (encodeData encode (indexedCellData data)) (modelStamp stamp)
                (encodedStamps (encode ∘ alloc.vec.Vec.val) revisions)
                (encodeRow encode (a, w))
          ∧ next.val.length ≤ revisions.val.length + 1) := by
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  have hi : Function.Injective enc := inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  have hs := stamp_set enc hi revisions a.map stamp hc
  cases w with
  | Put value =>
      simp only [advanceRevision, bind_ok, ite_true, clone_bytes]
      apply WP.spec_bind hs
      intro next h
      simpa [revisionStep, encodeRow, encodeAddr, byteAddr, enc] using h
  | Remove =>
      have keyRoom : 2 * (8 + a.map.val.length + a.key.val.length) + 1 ≤ Usize.max := room
      have hinj : Function.Injective (encodeAddr encode ∘ byteAddr) :=
        (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
      have hf : find (encodeData encode (indexedCellData data)) (encodeAddr encode (byteAddr a))
            = (find data a).map (encodeCell encode ∘ byteCell) := by
        simpa [encodeData, indexedCellData, Function.comp_def]
          using find_projected data a (encodeAddr encode ∘ byteAddr)
            (encodeCell encode ∘ byteCell) hinj
      simp only [advanceRevision, bind_ok, Bool.false_eq_true, ite_false]
      apply WP.spec_bind (index_get_refines index root data view a (by omega))
      intro cell read
      rw [← read] at hf
      change find (encodeData encode (indexedCellData data)) (encode a.map.val, encode a.key.val)
        = cell.map (encodeCell encode ∘ byteCell) at hf
      cases cell with
      | none =>
          simp [revisionStep, encodeRow, encodeAddr, byteAddr, hf, core.option.Option.is_some]
      | some c =>
          simp only [core.option.Option.is_some, clone_bytes, bind_ok]
          apply WP.spec_bind hs
          intro next h
          simpa [revisionStep, encodeRow, hf, enc, encodeAddr, byteAddr] using h

private theorem advance_stamps_matches (encode : List U8 → String)
    (inj : Function.Injective encode) (revisions births : Stamps) (index : CellIndex)
    (root : CcfKv.radix.RadixRoot) (data : CellRows) (view : IndexView index root data)
    (row : IndexWrite) (stamp : CcfKv.engine.Stamp)
    (hr : revisions.val.length < Usize.max) (hb : births.val.length < Usize.max)
    (room : IndexKeyRoom row)
    : WP.spec (CcfKv.engine.advance_stamps revisions births index root row stamp)
        (fun (rev, birth) =>
          (encodedStamps (encode ∘ alloc.vec.Vec.val) rev
              = revisionStep (encodeData encode (indexedCellData data)) (modelStamp stamp)
                  (encodedStamps (encode ∘ alloc.vec.Vec.val) revisions)
                  (encodeRow encode row)
            ∧ rev.val.length ≤ revisions.val.length + 1)
          ∧ (encodedStamps (encode ∘ alloc.vec.Vec.val) birth
                = birthStep (modelStamp stamp)
                    (encodedStamps (encode ∘ alloc.vec.Vec.val) births)
                    (encodeRow encode row)
              ∧ birth.val.length ≤ births.val.length + 1)) := by
  obtain ⟨a, w⟩ := row
  have he : CcfKv.engine.advance_stamps revisions births index root (a, w) stamp = (do
      let (rev, addr) ← advanceRevision revisions index root a w stamp
      let birth ← CcfKv.engine.update_birth births addr.map stamp
      Result.ok (rev, birth)) := by
    cases w <;> simp [CcfKv.engine.advance_stamps, advanceRevision]
  rw [he]
  apply WP.spec_bind
    (update_revision_step encode inj revisions index root data view a w stamp hr room)
  rintro ⟨rev, addr⟩ ⟨same, hv⟩
  change addr = a at same
  subst addr
  apply WP.spec_bind (update_birth_step encode inj births (a, w) stamp hb)
  intro birth h
  rw [WP.spec_ok]
  exact ⟨hv, h⟩

private theorem stamp_loop (encode : List U8 → String) (inj : Function.Injective encode)
    (index : CellIndex) (root : CcfKv.radix.RadixRoot) (data : CellRows)
    (view : IndexView index root data) (pending : NativeWrites) (version identity : U64)
    (revs births : Stamps)
    (hr : revs.val.length + pending.val.length ≤ Usize.max)
    (hb : births.val.length + pending.val.length ≤ Usize.max)
    (room : ∀ w ∈ pending.val, IndexKeyRoom w)
    : WP.spec
        (CcfKv.engine.Frame.advance_loop root index pending version identity revs births
          0#usize)
        (fun (p, r, b) =>
          p = pending
          ∧ encodedStamps (encode ∘ alloc.vec.Vec.val) r
            = (pending.val.map (encodeRow encode)).foldl
                (revisionStep (encodeData encode (indexedCellData data))
                  { version := version.val, identity := identity.val })
                (encodedStamps (encode ∘ alloc.vec.Vec.val) revs)
          ∧ encodedStamps (encode ∘ alloc.vec.Vec.val) b
            = (pending.val.map (encodeRow encode)).foldl
                (birthStep { version := version.val, identity := identity.val })
                (encodedStamps (encode ∘ alloc.vec.Vec.val) births)) := by
  let rows := pending.val
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  let stamp : CcfKv.engine.Stamp := {version, identity}
  let foldRev := fun (r : Stamps) (ws : List (CcfKv.engine.Address × CcfKv.engine.Write)) =>
    (ws.map (encodeRow encode)).foldl
      (revisionStep (encodeData encode (indexedCellData data)) (modelStamp stamp)) (encodedStamps enc r)
  let foldBirth := fun (b : Stamps) (ws : List (CcfKv.engine.Address × CcfKv.engine.Write)) =>
    (ws.map (encodeRow encode)).foldl (birthStep (modelStamp stamp)) (encodedStamps enc b)
  unfold CcfKv.engine.Frame.advance_loop
  apply loop.spec_decr_nat (fun (p : NativeWrites × Stamps × Stamps × Usize) =>
      rows.length - p.2.2.2.val)
    (fun (p, r, b, i) => p = pending ∧ i.val ≤ rows.length
      ∧ r.val.length + (rows.length - i.val) ≤ Usize.max
      ∧ b.val.length + (rows.length - i.val) ≤ Usize.max
      ∧ foldRev r (rows.drop i.val) = foldRev revs rows
      ∧ foldBirth b (rows.drop i.val) = foldBirth births rows)
    _ _ _
  · rintro ⟨p, r, b, i⟩ ⟨hp, hi, hrc, hbc, hrev, hbirth⟩
    dsimp only at hp hi hrc hbc hrev hbirth ⊢
    subst p
    unfold CcfKv.engine.Frame.advance_loop.body
    have hlen : (alloc.vec.Vec.len pending).val = rows.length := alloc.vec.Vec.len_val _
    have hcap : rows.length ≤ Usize.max := alloc.vec.Vec.len_ineq pending
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len pending
    · have hx : i.val < rows.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending i hx)
      intro row hrow
      apply WP.spec_bind (advance_stamps_matches encode inj r b index root data view row stamp
        (by omega) (by omega) (room row (hrow ▸ List.getElem_mem _)))
      rintro ⟨rs, bs⟩ ⟨hrs, hbs⟩
      change WP.spec (do
        let j ← i + 1#usize
        Result.ok (ControlFlow.cont (pending, rs, bs, j))) _
      have hinc : i.val + (1#usize : Usize).val ≤ Usize.max := by omega
      apply WP.spec_bind (Usize.add_spec hinc)
      intro j hj
      have hj' : j.val = i.val + 1 := by omega
      have hdrop : rows.drop i.val = row :: rows.drop j.val := by
        rw [hj', List.drop_eq_getElem_cons hx, ← hrow]
      have hr' := hrs.2
      have hb' := hbs.2
      simp only [WP.spec_ok]
      refine ⟨⟨True.intro, by omega, by omega, by omega, ?_, ?_⟩, by omega⟩
      · simpa only [hdrop, foldRev, List.map_cons, List.foldl_cons, enc, ← hrs.1] using hrev
      · simpa only [hdrop, foldBirth, List.map_cons, List.foldl_cons, enc, ← hbs.1] using hbirth
    · have hx : rows.length ≤ i.val := by rw [← hlen]; exact Nat.le_of_not_gt h
      rw [ite_eq_right h, WP.spec_ok]
      simp only [List.drop_eq_nil_of_le hx, foldRev, foldBirth, List.map_nil, List.foldl_nil] at hrev hbirth
      exact ⟨rfl, hrev, hbirth⟩
  · simpa [rows] using ⟨hr, hb⟩

/-- The extracted advance publishes the entire frame modulo binding order, including
exact revision and birth metadata. -/
theorem frame_advance_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (before : CcfKv.engine.Frame)
    (index : CellIndex) (pins : List U32) (live : IndexLiveness index pins)
    (hrootPin : before.data = 0#u32 ∨ before.data ∈ pins)
    (view : IndexView index before.data (indexRows index before.data)) (model : Store)
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (version identity : U64) (hBefore : model.head = modelFrame encode index before)
    (hVersion : version.val = model.head.version + 1)
    (hIdentity : identity.val = model.nextIdentity)
    (space
      : IndexBatchRoom index pins.length
          ((indexRows index before.data).length + pending.val.length) pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    (hRevs : before.revisions.val.length + pending.val.length ≤ Usize.max)
    (hBirths : before.births.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.Frame.advance before index version identity pending)
        (fun (after, arena) =>
          FrameOrderEq (modelFrame encode arena after)
            (advance model (encodeWrites encode (byteWrites pending.val))).head
          ∧ IndexView arena after.data (indexRows arena after.data)
          ∧ IndexLiveness arena (if after.data = 0#u32 then pins else after.data :: pins)
          ∧ IndexKeeps index arena
          ∧ IndexGrowth index arena
              (pending.val.length
                * ((indexRows index before.data).length + pending.val.length + 1))
              pending.val.length) := by
  let data := indexRows index before.data
  unfold CcfKv.engine.Frame.advance
  simp only [clone_assoc, bind_ok]
  apply WP.spec_bind
    (stamp_loop encode inj index before.data data view pending version identity
      before.revisions before.births hRevs hBirths addresses)
  rintro ⟨actualPending, rev, birth⟩ ⟨hp, hr, hb⟩
  subst actualPending
  change WP.spec (do
    let base ← CcfKv.engine.publication_base index before.data pending
    let (root, after) ← CcfKv.engine.publish_selected index base pending version
    Result.ok (({version, data := root, revisions := rev, births := birth} :
      CcfKv.engine.Frame), after)) _
  apply WP.spec_bind
    (publication_base_refines index before.data data pending pins.length view live.valid
      space)
  intro base chosen
  apply WP.spec_bind
    (sorted_publication_refines index before.data base data pending version pins
      view live hrootPin space addresses chosen)
  rintro ⟨root, after⟩ ⟨⟨out, updated, hPermOut⟩, arenaLive, kept, growth⟩
  have hw : encodeWrites encode (byteWrites pending.val) = pending.val.map (encodeRow encode) := by
    simp only [encodeWrites, byteWrites, List.map_map, Function.comp_def]
    apply List.map_congr_left
    rintro ⟨a, w⟩ _
    cases w <;> rfl
  have projected := index_rows_eq updated
  have hdbPerm : (encodeData encode (indexedCellData (indexRows after root))).Perm
      (publish (encodeData encode (indexedCellData data)) version.val
        (encodeWrites encode (byteWrites pending.val))) := by
    rw [projected, ← publish_encoding encode inj, ← indexed_fold_projects]
    exact (hPermOut.map _).map _
  change WP.spec (Result.ok (({
      version := version
      data := root
      revisions := rev
      births := birth
    } : CcfKv.engine.Frame), after)) _
  rw [WP.spec_ok]
  refine ⟨?_, projected.symm ▸ updated, arenaLive, kept, growth⟩
  refine ⟨?_, ?_, ?_, ?_⟩
  · simp only [modelFrame, modelMetadata, advance]
    exact hVersion
  · simp only [modelFrame, modelMetadata, advance]
    simp only [hBefore, modelFrame, modelMetadata] at hVersion ⊢
    rw [← hVersion]
    exact hdbPerm
  · intro m
    simp only [modelFrame, modelMetadata, advance]
    simp only [hBefore, modelFrame, modelMetadata] at hVersion ⊢
    rw [← hVersion, ← hIdentity, hw]
    simp only [encodedStamps] at hr
    rw [hr]; rfl
  · intro m
    simp only [modelFrame, modelMetadata, advance]
    simp only [hBefore, modelFrame, modelMetadata] at hVersion ⊢
    rw [← hVersion, ← hIdentity, hw]
    simp only [encodedStamps] at hb
    rw [hb]; rfl

/-- The extracted frame advance publishes the relaxed model's next frame
without requiring either the existing bindings or staged writes to be ordered alike. -/
theorem frame_advance_order_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (before : CcfKv.engine.Frame)
    (index : CellIndex) (pins : List U32) (live : IndexLiveness index pins)
    (hrootPin : before.data = 0#u32 ∨ before.data ∈ pins)
    (view : IndexView index before.data (indexRows index before.data)) (model : Store)
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (referenceWrites : Pending) (version identity : U64)
    (heads : FrameOrderEq (modelFrame encode index before) model.head)
    (related : (encodeWrites encode (byteWrites pending.val)).Perm referenceWrites)
    (uniqueData : Kv.Properties.Unique model.head.data)
    (uniqueWrites : Kv.Properties.Unique (encodeWrites encode (byteWrites pending.val)))
    (hVersion : version.val = model.head.version + 1)
    (hIdentity : identity.val = model.nextIdentity)
    (space
      : IndexBatchRoom index pins.length
          ((indexRows index before.data).length + pending.val.length) pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    (hRevs : before.revisions.val.length + pending.val.length ≤ Usize.max)
    (hBirths : before.births.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.Frame.advance before index version identity pending)
        (fun (after, arena) =>
          FrameOrderEq (modelFrame encode arena after)
            (advance model referenceWrites).head
          ∧ IndexView arena after.data (indexRows arena after.data)
          ∧ IndexLiveness arena (if after.data = 0#u32 then pins else after.data :: pins)
          ∧ IndexKeeps index arena) := by
  let representative := {model with head := modelFrame encode index before}
  have nextVersion : version.val = representative.head.version + 1 :=
    heads.version.symm ▸ hVersion
  apply WP.spec_mono (frame_advance_matches_model encode inj before index pins live hrootPin view
    representative pending version identity rfl nextVersion hIdentity space addresses hRevs hBirths)
  rintro ⟨after, arena⟩ ⟨published, retained, lAfter, kept, _⟩
  refine ⟨?_, retained, lAfter, kept⟩
  exact published.trans (advance_order_eq representative model _ _ heads rfl related
    (unique_of_perm heads.data.symm uniqueData) uniqueWrites)

theorem prepare_frame_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (history : CcfKv.engine.History)
    (prior : List CcfKv.engine.Frame) (head : CcfKv.engine.Frame)
    (extraPins : List U32)
    (branch : BranchValid history.log) (split : history.activeFrames = prior ++ [head])
    (valid : HistoryIndexValid history)
    (live : IndexLiveness history.index (framePins history.activeFrames ++ extraPins))
    (model : Store)
    (pending : CcfKv.engine.Assoc CcfKv.engine.Address CcfKv.engine.Write)
    (version identity : U64)
    (before : model.head = modelFrame encode history.index head)
    (nextVersion : version.val = model.head.version + 1)
    (nextId : identity.val = model.nextIdentity)
    (room
      : IndexBatchRoom history.index
          (framePins history.activeFrames ++ extraPins).length
          ((indexRows history.index head.data).length + pending.val.length)
          pending.val.length)
    (addresses : ∀ row ∈ pending.val, IndexKeyRoom row)
    (revisions : head.revisions.val.length + pending.val.length ≤ Usize.max)
    (births : head.births.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (CcfKv.engine.History.prepare_frame history version identity pending)
        (fun (after, prepared) =>
          ∃ arena,
            prepared = {history with index := arena}
            ∧ FrameOrderEq (modelFrame encode arena after)
                (advance model (encodeWrites encode (byteWrites pending.val))).head
            ∧ IndexView arena after.data (indexRows arena after.data)
            ∧ IndexLiveness arena
                (if after.data = 0#u32 then
                    framePins history.activeFrames ++ extraPins
                  else
                    after.data :: (framePins history.activeFrames ++ extraPins))
            ∧ IndexKeeps history.index arena
            ∧ IndexGrowth history.index arena
                (pending.val.length
                  * ((indexRows history.index head.data).length + pending.val.length + 1))
                pending.val.length) := by
  unfold CcfKv.engine.History.prepare_frame
  apply WP.spec_bind (branch_active_len history.log branch)
  intro count hc
  have size : count.val = prior.length + 1 := by
    change count.val = history.activeFrames.length at hc
    simpa [split] using hc
  have one : (1#usize : Usize).val = 1 := rfl
  apply WP.spec_bind (Usize.sub_spec (x := count) (y := 1#usize) (by omega))
  intro off ho
  have selected : history.activeFrames[off.val]? = some head := by
    have pos : off.val = prior.length := by omega
    rw [split, pos, List.getElem?_append_right (Nat.le_refl _), Nat.sub_self]
    rfl
  apply WP.spec_bind (branch_active_at history.log branch off head selected)
  intro f h
  subst f
  have hheadPin : head.data = 0#u32 ∨ head.data ∈ framePins history.activeFrames ++ extraPins := by
    by_cases hz : head.data = 0#u32
    · exact Or.inl hz
    · have hmemAct : head ∈ history.activeFrames := by simp [split]
      exact Or.inr (List.mem_append_left extraPins
        (List.mem_filterMap.mpr ⟨head, hmemAct, by simp [hz]⟩))
  apply WP.spec_bind
    (frame_advance_matches_model encode inj head history.index
      (framePins history.activeFrames ++ extraPins) live hheadPin
      (valid.head prior head split) model pending version identity before nextVersion
      nextId room addresses revisions births)
  rintro ⟨next, arena⟩ spec
  change WP.spec (Result.ok (next, {history with index := arena})) _
  rw [WP.spec_ok]
  exact ⟨arena, rfl, spec⟩

end KvRust
