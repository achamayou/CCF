-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Lineage

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

private abbrev Stamps := Spike.engine.Assoc Spike.engine.Bytes Spike.engine.Stamp
private abbrev NativeData := Spike.engine.Assoc Spike.engine.Address Spike.engine.Cell
private abbrev NativeWrites := Spike.engine.Assoc Spike.engine.Address Spike.engine.Write
private abbrev StampMap := Assoc String Stamp

local instance : DecidableEq Spike.engine.Bytes :=
  fun a b =>
    decidable_of_iff (alloc.vec.Vec.val a = alloc.vec.Vec.val b)
      ⟨alloc.vec.Vec.ext a b, congrArg alloc.vec.Vec.val⟩

local instance : DecidableEq Spike.engine.Address :=
  fun a b =>
    decidable_of_iff (byteAddr a = byteAddr b) ⟨byteAddr_inj, congrArg byteAddr⟩

private theorem byte_same (a b : Spike.engine.Bytes)
    : Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey.same a b = .ok (decide (a = b)) := by
  rw [bytes_same]
  congr 1

private def encodedStamps (encode : Spike.engine.Bytes → String) (rows : Stamps)
    : StampMap :=
  rows.val.map fun (m, s) => (encode m, modelStamp s)

/-- Project the entire extracted frame into the executable model. -/
def modelFrame (encode : List U8 → String) (f : Spike.engine.Frame) : Frame :=
  {
    modelMetadata (encode ∘ alloc.vec.Vec.val) f with
      data := encodeData encode (byteData f.data)
  }

private def revisionStep (data : Data) (stamp : Stamp) (rev : StampMap)
    (row : Addr String String × Option String)
    : StampMap :=
  if row.2.isSome || (find data row.1).isSome then Kv.Model.set rev row.1.1 stamp else rev

private def birthStep (stamp : Stamp) (birth : StampMap)
    (row : Addr String String × Option String)
    : StampMap :=
  if (find birth row.1.1).isSome then birth else Kv.Model.set birth row.1.1 stamp

private def encodeRow (encode : List U8 → String)
    (row : Spike.engine.Address × Spike.engine.Write)
    : Addr String String × Option String :=
  (
    encodeAddr encode (byteAddr row.1),
    match row.2 with
    | .Remove => none
    | .Put value => some (encode (alloc.vec.Vec.val value))
  )

private theorem stamp_set (encode : Spike.engine.Bytes → String)
    (inj : Function.Injective encode) (rows : Stamps) (m : Spike.engine.Bytes)
    (stamp : Spike.engine.Stamp) (hc : rows.val.length < Usize.max)
    : WP.spec
        (Spike.engine.Assoc.set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
          Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Stamp.Insts.CoreCloneClone
          rows m stamp)
        (fun next =>
          encodedStamps encode next
            = Kv.Model.set (encodedStamps encode rows) (encode m) (modelStamp stamp)
          ∧ next.val.length ≤ rows.val.length + 1) := by
  apply WP.spec_mono (assoc_set Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey
    Spike.engine.Bytes.Insts.CoreCloneClone Spike.engine.Stamp.Insts.CoreCloneClone
    rows m stamp (fun a => byte_same a m) clone_bytes (fun _ => rfl) hc)
  intro next he
  constructor
  · simp only [encodedStamps, he, set_projected rows.val m stamp encode modelStamp inj]
  · rw [he, Kv.Model.set, List.length_cons]
    exact Nat.succ_le_succ (List.length_filter_le _ _)

private theorem update_birth_step (encode : List U8 → String)
    (inj : Function.Injective encode) (rows : Stamps)
    (row : Spike.engine.Address × Spike.engine.Write) (stamp : Spike.engine.Stamp)
    (hc : rows.val.length < Usize.max)
    : WP.spec (Spike.engine.update_birth rows row.1.map stamp)
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
  unfold Spike.engine.update_birth
  apply WP.spec_bind (assoc_index Spike.engine.Bytes.Insts.Ccf_kv_spikeEngineKey rows m
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

private theorem update_revision_step (encode : List U8 → String)
    (inj : Function.Injective encode) (rows : Stamps) (data : NativeData)
    (row : Spike.engine.Address × Spike.engine.Write) (stamp : Spike.engine.Stamp)
    (hc : rows.val.length < Usize.max)
    : WP.spec (Spike.engine.update_revision rows data row stamp)
        (fun next =>
          encodedStamps (encode ∘ alloc.vec.Vec.val) next
            = revisionStep (encodeData encode (byteData data)) (modelStamp stamp)
                (encodedStamps (encode ∘ alloc.vec.Vec.val) rows) (encodeRow encode row)
          ∧ next.val.length ≤ rows.val.length + 1) := by
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  have hi : Function.Injective enc := inj.comp (fun _ _ => alloc.vec.Vec.ext _ _)
  obtain ⟨a, w⟩ := row
  have hs := stamp_set enc hi rows a.map stamp hc
  cases w with
  | Put value =>
      simpa [Spike.engine.update_revision, clone_bytes, revisionStep, encodeRow,
        encodeAddr, byteAddr, enc] using hs
  | Remove =>
      have hinj : Function.Injective (encodeAddr encode ∘ byteAddr) :=
        (encode_addr_inj inj).comp (fun _ _ => byteAddr_inj)
      have hf
          : find (encodeData encode (byteData data)) (encodeAddr encode (byteAddr a))
            = (find data.val a).map (encodeCell encode ∘ byteCell) := by
        simpa [encodeData, byteData, Function.comp_def]
          using find_projected data.val a (encodeAddr encode ∘ byteAddr)
            (encodeCell encode ∘ byteCell) hinj
      simp [Spike.engine.update_revision]
      apply WP.spec_bind
        (assoc_index Spike.engine.Address.Insts.Ccf_kv_spikeEngineKey data a
          (fun addr => compare_address addr a))
      intro i why
      cases i with
      | none =>
          simp [revisionStep, encodeRow, hf, why]
      | some i =>
          obtain ⟨c, _, hc⟩ := why
          have hf' : find (encodeData encode (byteData data))
              (encode (alloc.vec.Vec.val a.map), encode (alloc.vec.Vec.val a.key)) =
              (find data.val a).map (encodeCell encode ∘ byteCell) := hf
          simpa [revisionStep, encodeRow, hf', hc, clone_bytes, enc, encodeAddr, byteAddr] using hs

private theorem stamp_loop (encode : List U8 → String) (inj : Function.Injective encode)
    (data : NativeData) (pending : NativeWrites) (version identity : U64)
    (revs births : Stamps)
    (hr : revs.val.length + pending.val.length ≤ Usize.max)
    (hb : births.val.length + pending.val.length ≤ Usize.max)
    : WP.spec
        (Spike.engine.Frame.advance_loop data pending version identity revs births
          0#usize)
        (fun (p, r, b) =>
          p = pending
          ∧ encodedStamps (encode ∘ alloc.vec.Vec.val) r
            = (pending.val.map (encodeRow encode)).foldl
                (revisionStep (encodeData encode (byteData data))
                  { version := version.val, identity := identity.val })
                (encodedStamps (encode ∘ alloc.vec.Vec.val) revs)
          ∧ encodedStamps (encode ∘ alloc.vec.Vec.val) b
            = (pending.val.map (encodeRow encode)).foldl
                (birthStep { version := version.val, identity := identity.val })
                (encodedStamps (encode ∘ alloc.vec.Vec.val) births)) := by
  let rows := pending.val
  let enc := encode ∘ alloc.vec.Vec.val (α := U8)
  let stamp : Spike.engine.Stamp := {version, identity}
  let foldRev := fun (r : Stamps) (ws : List (Spike.engine.Address × Spike.engine.Write)) =>
    (ws.map (encodeRow encode)).foldl
      (revisionStep (encodeData encode (byteData data)) (modelStamp stamp)) (encodedStamps enc r)
  let foldBirth := fun (b : Stamps) (ws : List (Spike.engine.Address × Spike.engine.Write)) =>
    (ws.map (encodeRow encode)).foldl (birthStep (modelStamp stamp)) (encodedStamps enc b)
  unfold Spike.engine.Frame.advance_loop
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
    unfold Spike.engine.Frame.advance_loop.body
    have hlen : (alloc.vec.Vec.len pending).val = rows.length := alloc.vec.Vec.len_val _
    have hcap : rows.length ≤ Usize.max := alloc.vec.Vec.len_ineq pending
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases h : i < alloc.vec.Vec.len pending
    · have hx : i.val < rows.length := by rw [← hlen]; exact h
      rw [ite_eq_left h, alloc.vec.Vec.index_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec pending i hx)
      intro row hrow
      apply WP.spec_bind (update_revision_step encode inj r data row stamp (by omega))
      intro rs hrs
      change WP.spec (do
        let bs ← Spike.engine.update_birth b row.1.map stamp
        let j ← i + 1#usize
        Result.ok (ControlFlow.cont (pending, rs, bs, j))) _
      apply WP.spec_bind (update_birth_step encode inj b row stamp (by omega))
      intro bs hbs
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

/-- The extracted advance publishes the entire frame, including revision and birth metadata. -/
theorem frame_advance_matches_model (encode : List U8 → String)
    (inj : Function.Injective encode) (before : Spike.engine.Frame) (model : Store)
    (pending : Spike.engine.Assoc Spike.engine.Address Spike.engine.Write)
    (version identity : U64) (hBefore : model.head = modelFrame encode before)
    (hVersion : version.val = model.head.version + 1)
    (hIdentity : identity.val = model.nextIdentity)
    (hData : before.data.val.length + pending.val.length ≤ Usize.max)
    (hRevs : before.revisions.val.length + pending.val.length ≤ Usize.max)
    (hBirths : before.births.val.length + pending.val.length ≤ Usize.max)
    : WP.spec (Spike.engine.Frame.advance before version identity pending)
        (fun after =>
          modelFrame encode after
          = (advance model (encodeWrites encode (byteWrites pending.val))).head) := by
  unfold Spike.engine.Frame.advance
  simp only [clone_assoc, bind_ok]
  apply WP.spec_bind
    (stamp_loop encode inj before.data pending version identity before.revisions
      before.births hRevs hBirths)
  rintro ⟨actualPending, rev, birth⟩ ⟨hp, hr, hb⟩
  subst actualPending
  change WP.spec (do
    let data ← Spike.engine.publish before.data pending version
    Result.ok ({version, data, revisions := rev, births := birth} : Spike.engine.Frame)) _
  apply WP.spec_bind (publish_matches_model before.data pending version hData)
  intro actual hd
  have hw : encodeWrites encode (byteWrites pending.val) = pending.val.map (encodeRow encode) := by
    simp only [encodeWrites, byteWrites, List.map_map, Function.comp_def]
    apply List.map_congr_left
    rintro ⟨a, w⟩ _
    cases w <;> rfl
  simp only [WP.spec_ok, modelFrame, modelMetadata, advance]
  have hdb : encodeData encode (byteData actual) =
      publish (encodeData encode (byteData before.data)) version.val
        (encodeWrites encode (byteWrites pending.val)) := by
    rw [hd, publish_encoding encode inj]
  simp only [hBefore, modelFrame, modelMetadata] at hVersion ⊢
  rw [← hVersion, ← hIdentity, hdb, hw]
  simp only [encodedStamps] at hr hb
  rw [hr, hb]
  rfl

end KvRust
