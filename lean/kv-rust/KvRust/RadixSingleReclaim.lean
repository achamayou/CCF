-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.RadixSingle
public import KvRust.RetireQueue

import all Aeneas.Data.List.List

@[expose] public section

namespace KvRust

open Aeneas.Std

theorem wp_spec_exists {α : Type} {m : Result α} {P : α → Prop} (h : WP.spec m P)
    : ∃ x, m = Result.ok x ∧ P x := by
  cases hm : m using Result.cases with
  | ret x => exact ⟨x, rfl, by simpa [hm] using h⟩
  | vis _ _ => simp [hm] at h
  | div => simp [hm] at h

/-- Lockstep simulation between two `Aeneas.Std.loop` computations when the
reference loop is known to terminate with `Result.ok y₁`. -/
theorem loop_lockstep {α₁ α₂ β₁ β₂ : Type}
    (b₁ : α₁ → Result (ControlFlow α₁ β₁)) (b₂ : α₂ → Result (ControlFlow α₂ β₂))
    (rel : α₁ → α₂ → Prop) (post : β₁ → β₂ → Prop)
    (step
      : ∀ x₁ x₂,
          rel x₁ x₂
          → ∀ r₁,
              b₁ x₁ = Result.ok r₁
              → WP.spec (b₂ x₂)
                  (fun r₂ =>
                    match r₁, r₂ with
                    | .done y₁, .done y₂ => post y₁ y₂
                    | .cont x₁', .cont x₂' => rel x₁' x₂'
                    | _, _ => False))
    {x₁ : α₁} {x₂ : α₂} {y₁ : β₁}
    (hrel : rel x₁ x₂) (hrun : loop b₁ x₁ = Result.ok y₁)
    : WP.spec (loop b₂ x₂) (fun y₂ => post y₁ y₂) := by
  let Q (a₁ : α₁) (z₁ : β₁) : Prop := ∀ a₂, rel a₁ a₂ → WP.spec (loop b₂ a₂) (post z₁)
  let Reach (a₁ : α₁) : Prop := ∃ z, loop b₁ a₁ = Result.ok z
  let motive : (α₁ → Result β₁) → Prop := fun f => ∀ a₁, Reach a₁ → WP.dspec (f a₁) (Q a₁)
  have hadm : Lean.Order.admissible motive := by
    apply Lean.Order.admissible_pi
    intro a₁
    apply Lean.Order.admissible_pi
    intro _
    exact WP.dspec_func_admissible a₁ (Q a₁)
  have hmain : motive (loop b₁) := by
    apply loop.fixpoint_induct b₁ motive hadm
    intro f ih a₁ ⟨z, hz⟩
    have hspec : WP.spec (loop b₁ a₁) (· = z) := by rw [hz, WP.spec_ok]
    rw [loop.eq_1] at hspec hz
    cases hb₁ : b₁ a₁ using Result.cases with
    | div =>
        rw [hb₁] at hspec
        simp at hspec
    | vis e k =>
        rw [hb₁] at hspec
        simp at hspec
    | ret r₁ =>
        change b₁ a₁ = Result.ok r₁ at hb₁
        simp only [hb₁, bind_ok] at hz ⊢
        cases r₁ with
        | done z₁ =>
            rw [WP.dspec_ok]
            intro a₂ hrel'
            rw [loop.eq_1]
            apply WP.spec_bind (step a₁ a₂ hrel' (.done z₁) hb₁)
            intro r₂ hr₂
            cases r₂ with
            | done w₂ => simpa [WP.spec_ok] using hr₂
            | cont _ => exact hr₂.elim
        | cont a₁' =>
            have hih := ih a₁' ⟨z, hz⟩
            apply WP.dspec_mono hih
            intro z₁ hz₁ a₂ hrel'
            rw [loop.eq_1]
            apply WP.spec_bind (step a₁ a₂ hrel' (.cont a₁') hb₁)
            intro r₂ hr₂
            cases r₂ with
            | done _ => exact hr₂.elim
            | cont a₂' => exact hz₁ a₂' hr₂
  have hd := hmain x₁ ⟨y₁, hrun⟩
  rw [hrun, WP.dspec_ok] at hd
  exact hd x₂ hrel

/-- Every non-zero link referenced by a pin or directory child points to a live slot. -/
def SingleLinkLive {V : Type} (dirs : List (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V))) (link : U32)
    : Prop :=
  if link < 2147483648#u32 then
    0 < link.val ∧ ∃ d, dirs[link.val - 1]? = some (some d)
  else
    2147483648 < link.val ∧ ∃ r, rows[link.val - 2147483649]? = some (some r)

def arenaEdges (dirs : List (Option Spike.radix.RadixDir)) : List U32 :=
  (dirs.filterMap id).flatMap (·.children.val)

theorem radixReferences_eq (dirs : List (Option Spike.radix.RadixDir))
    (pins : List U32) (target : U32)
    : radixReferences dirs pins target = (pins ++ arenaEdges dirs).count target :=
  rfl

/-- Exact reference-count invariant against an arbitrary owner multiset `owners`. -/
structure RefCountsExact {V : Type}
    (dirs : List (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32)
    (owners : List U32)
    : Prop where
  dirLen : dirRefs.val.length = dirs.length
  rowLen : rowRefs.val.length = rows.length
  dirVal
    : ∀ (link : U32) (c : U32),
        0 < link.val
        → link < 2147483648#u32
        → dirRefs.val[link.val - 1]? = some c
        → c.val
          = match dirs[link.val - 1]? with
            | some none => 0
            | _ => owners.count link
  rowVal
    : ∀ (link : U32) (c : U32),
        2147483648 < link.val
        → rowRefs.val[link.val - 2147483649]? = some c
        → c.val
          = match rows[link.val - 2147483649]? with
            | some none => 0
            | _ => owners.count link

theorem RefCountsExact.perm {V : Type}
    {dirs : List (Option Spike.radix.RadixDir)}
    {rows : List (Option (Spike.radix.RadixRow V))}
    {dirRefs rowRefs : alloc.vec.Vec U32}
    {a b : List U32}
    (h : RefCountsExact dirs rows dirRefs rowRefs a) (hp : a.Perm b)
    : RefCountsExact dirs rows dirRefs rowRefs b :=
  ⟨
    h.dirLen,
    h.rowLen,
    fun link c hpos hlt hc => by
      have hv := h.dirVal link c hpos hlt hc
      cases hd : dirs[link.val - 1]? <;> simp only [hd] at hv ⊢
      · rwa [← hp.count_eq]
      · rename_i o; cases o <;> simp only at hv ⊢
        · exact hv
        · rwa [← hp.count_eq],
    fun link c htag hc => by
      have hv := h.rowVal link c htag hc
      cases hr : rows[link.val - 2147483649]? <;> simp only [hr] at hv ⊢
      · rwa [← hp.count_eq]
      · rename_i o; cases o <;> simp only at hv ⊢
        · exact hv
        · rwa [← hp.count_eq]
  ⟩

/-- Full memory-safety and liveness invariant of a refcounted `SingleRadix` arena
relative to its active root pins `pins`. -/
structure SingleLiveness {V : Type} (arena : Spike.radix.SingleRadix V) (pins : List U32)
    : Prop where
  valid : ArenaValid arena.values
  dirsBound : arena.values.dirs.val.length ≤ 2147483647
  rowsBound : arena.values.rows.val.length ≤ 2147483647
  freeDirsNodup : arena.values.free_dirs.val.Nodup
  freeRowsNodup : arena.values.free_rows.val.Nodup
  pinsLive : ∀ p ∈ pins, SingleLinkLive arena.values.dirs.val arena.values.rows.val p
  childrenLive
    : ∀ d ∈ arena.values.dirs.val.filterMap id,
      ∀ c ∈ d.children.val,
        c ≠ 0#u32 → SingleLinkLive arena.values.dirs.val arena.values.rows.val c
  counts
    : RefCountsExact arena.values.dirs.val arena.values.rows.val
        arena.dir_refs arena.row_refs (pins ++ arenaEdges arena.values.dirs.val)
  queue
    : ∃ entries,
        RetirementQueueView arena.retired entries
        ∧ entries.Nodup
        ∧ ∀ link ∈ entries,
            SingleLinkLive arena.values.dirs.val arena.values.rows.val link
            ∧ radixReferences arena.values.dirs.val pins link = 0

theorem SingleLiveness.perm {V : Type} {arena : Spike.radix.SingleRadix V}
    {a b : List U32} (h : SingleLiveness arena a) (hp : a.Perm b)
    : SingleLiveness arena b := by
  obtain ⟨entries, qv, qnd, qzero⟩ := h.queue
  refine ⟨h.valid, h.dirsBound, h.rowsBound, h.freeDirsNodup, h.freeRowsNodup,
    fun p hm => h.pinsLive p (hp.symm.subset hm), h.childrenLive,
    h.counts.perm (hp.append_right _), entries, qv, qnd, ?_⟩
  intro link hl
  obtain ⟨hlive, hz⟩ := qzero link hl
  refine ⟨hlive, ?_⟩
  rw [radixReferences_eq, ← (hp.append_right _).count_eq]
  exact hz

/-- All pinned roots retain their exact views and bindings across reclamation or mutation. -/
def SinglePreservesPins {V : Type} (before after : Spike.radix.SingleRadix V)
    (pins : List U32)
    : Prop :=
  ∀ r ∈ pins,
    ∀ bindings,
      SingleView before r bindings
      → SingleView after r bindings
        ∧ singleBindings after bindings = singleBindings before bindings

theorem SinglePreservesPins.refl {V : Type} (arena : Spike.radix.SingleRadix V)
    (pins : List U32)
    : SinglePreservesPins arena arena pins :=
  fun _ _ _ v => ⟨v, rfl⟩

theorem SinglePreservesPins.trans {V : Type} {a b c : Spike.radix.SingleRadix V}
    {pins : List U32} (ab : SinglePreservesPins a b pins)
    (bc : SinglePreservesPins b c pins)
    : SinglePreservesPins a c pins := by
  intro r hr bs v
  obtain ⟨vb, sb⟩ := ab r hr bs v
  obtain ⟨vc, sc⟩ := bc r hr bs vb
  exact ⟨vc, sc.trans sb⟩

theorem SinglePreservesPins.mono {V : Type} {a b : Spike.radix.SingleRadix V}
    {small large : List U32} (h : SinglePreservesPins a b large)
    (sub : ∀ r ∈ small, r ∈ large)
    : SinglePreservesPins a b small :=
  fun r hr => h r (sub r hr)

theorem SinglePreservesPins.of_keeps {V : Type} {a b : Spike.radix.SingleRadix V}
    (kept : ArenaKeeps a.values b.values) (pins : List U32)
    : SinglePreservesPins a b pins :=
  fun r _ bs v => single_retains_views a b kept r bs v

/-! ### Reference-count primitives and bounded retirement -/

private theorem u32_cast_usize_val (x : U32) : (UScalar.cast .Usize x).val = x.val := by
  rw [UScalar.cast_val_mod_pow_greater_numBits_eq .Usize x
    (by
      simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U32_numBits_eq]
      rcases System.Platform.numBits_eq with h | h <;> simp [h])]

private theorem count_nodup_le_range {l : List Nat} {n : Nat}
    (hnd : l.Nodup) (hb : ∀ x ∈ l, x < n)
    : l.length ≤ n := by
  have hsub : l ⊆ List.range n := fun x hx => List.mem_range.mpr (hb x hx)
  have := hnd.length_le_of_subset hsub
  simpa using this

private theorem free_len_le_slots {T : Type} {slots : alloc.vec.Vec (Option T)}
    {free : alloc.vec.Vec Usize} (vacant : RadixFree slots free) (hnd : free.val.Nodup)
    : free.val.length ≤ slots.val.length := by
  have hmapNd : (free.val.map UScalar.val).Nodup :=
    hnd.map (fun _ _ h => UScalar.eq_of_val_eq h)
  have hle := count_nodup_le_range (l := free.val.map UScalar.val) (n := slots.val.length)
    hmapNd (fun x hx => by
      obtain ⟨u, hu, rfl⟩ := List.mem_map.mp hx
      have hnone := vacant.2 u hu
      exact (List.getElem?_eq_some_iff.mp hnone).1)
  simpa using hle

private theorem live_entries_bound {V : Type}
    {dirs : List (Option Spike.radix.RadixDir)}
    {rows : List (Option (Spike.radix.RadixRow V))}
    {entries : List U32} (hnd : entries.Nodup)
    (hlive : ∀ link ∈ entries, SingleLinkLive dirs rows link)
    : entries.length ≤ dirs.length + rows.length := by
  let enc (link : U32) : Nat :=
    if link < 2147483648#u32 then link.val - 1 else dirs.length + (link.val - 2147483649)
  have hinj : ∀ a ∈ entries, ∀ b ∈ entries, enc a = enc b → a = b := by
    intro a ha b hb heq
    have la := hlive a ha
    have lb := hlive b hb
    unfold enc at heq
    unfold SingleLinkLive at la lb
    by_cases hta : a < 2147483648#u32 <;> by_cases htb : b < 2147483648#u32
    · simp only [hta, htb, ite_true] at heq la lb
      exact UScalar.eq_of_val_eq (by omega)
    · simp only [hta, htb, ite_true, ite_false] at heq la lb
      obtain ⟨_, d, hd⟩ := la
      have hlt := (List.getElem?_eq_some_iff.mp hd).1
      omega
    · simp only [hta, htb, ite_true, ite_false] at heq la lb
      obtain ⟨_, d, hd⟩ := lb
      have hlt := (List.getElem?_eq_some_iff.mp hd).1
      omega
    · simp only [hta, htb, ite_false] at heq la lb
      exact UScalar.eq_of_val_eq (by omega)
  have hndEnc : (entries.map enc).Nodup := by
    induction entries with
    | nil => exact List.nodup_nil
    | cons x xs ih =>
        obtain ⟨hx, hxs⟩ := List.nodup_cons.mp hnd
        refine List.nodup_cons.mpr ⟨?_, ih hxs
          (fun l hl => hlive l (List.mem_cons_of_mem _ hl))
          (fun a ha b hb => hinj a (List.mem_cons_of_mem _ ha) b (List.mem_cons_of_mem _ hb))⟩
        intro hmem
        obtain ⟨y, hy, hxy⟩ := List.mem_map.mp hmem
        have eq := hinj y (List.mem_cons_of_mem _ hy) x List.mem_cons_self hxy
        exact hx (eq ▸ hy)
  have hltEnc : ∀ x ∈ entries.map enc, x < dirs.length + rows.length := by
    intro x hx
    obtain ⟨link, hl, rfl⟩ := List.mem_map.mp hx
    have liv := hlive link hl
    unfold enc SingleLinkLive at *
    by_cases htag : link < 2147483648#u32
    · simp only [htag, ite_true] at liv ⊢
      obtain ⟨_, _, hd⟩ := liv
      have := (List.getElem?_eq_some_iff.mp hd).1
      omega
    · simp only [htag, ite_false] at liv ⊢
      obtain ⟨_, _, hr⟩ := liv
      have := (List.getElem?_eq_some_iff.mp hr).1
      omega
  have := count_nodup_le_range hndEnc hltEnc
  simpa using this

/-- Capacity headroom so retaining a link cannot overflow a `u32` counter. -/
def OwnersBounded (owners : List U32) (headroom : Nat) : Prop :=
  ∀ target, owners.count target + headroom ≤ U32.max

theorem retain_link_refines {V : Type}
    (dirs : List (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (owners : List U32) (link : U32)
    (counts : RefCountsExact dirs rows dirRefs rowRefs owners)
    (live : link ≠ 0#u32 → SingleLinkLive dirs rows link)
    (room : link ≠ 0#u32 → owners.count link < U32.max)
    : WP.spec (Spike.radix.retain_link dirRefs rowRefs link)
        (fun (dr, rr) =>
          RefCountsExact dirs rows dr rr
            (if link = 0#u32 then owners else link :: owners)) := by
  unfold Spike.radix.retain_link
  by_cases hzero : link = 0#u32
  · simp [hzero, counts]
  · rw [ite_eq_right hzero]
    have hlive := live hzero
    have hroom := room hzero
    have htagVal : (Spike.radix.RADIX_LEAF_TAG : U32).val = 2147483648 := by
      simp [Spike.radix.RADIX_LEAF_TAG]
    have hone : (1#u32 : U32).val = 1 := rfl
    by_cases hdir : link < Spike.radix.RADIX_LEAF_TAG
    · rw [ite_eq_left hdir]
      have hltTag : link < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hdir
      simp only [SingleLinkLive, hltTag, ite_true] at hlive
      obtain ⟨hpos, d, hd⟩ := hlive
      have hbound : link.val - 1 < dirs.length := (List.getElem?_eq_some_iff.mp hd).1
      apply WP.spec_bind (U32.sub_spec (x := link) (y := 1#u32) (by omega))
      intro sub hsub
      have hidx : (UScalar.cast .Usize sub).val = link.val - 1 := by
        rw [u32_cast_usize_val]; omega
      simp only [lift, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind
        (alloc.vec.Vec.index_mut_usize_spec dirRefs (UScalar.cast .Usize sub)
          (by change (UScalar.cast .Usize sub).val < dirRefs.val.length; rw [hidx, counts.dirLen]; exact hbound))
      rintro ⟨c, back⟩ ⟨hc, hback⟩
      have hcGet : dirRefs.val[link.val - 1]? = some c := by
        rw [← hidx, List.getElem?_eq_getElem (by rw [hidx, counts.dirLen]; exact hbound), ← hc]
      have hcVal : c.val = owners.count link := by
        have := counts.dirVal link c hpos hltTag hcGet
        simpa [hd] using this
      apply WP.spec_bind (retain_reference_matches c link owners hcVal (by omega))
      rintro ⟨_, c'⟩ ⟨_, hc'⟩
      change WP.spec (Result.ok (back c', rowRefs)) _
      rw [WP.spec_ok, hback]
      refine ⟨by simp [alloc.vec.Vec.set_val_eq, counts.dirLen], counts.rowLen, ?_, ?_⟩
      · intro l cl hlpos hllt hcl
        rw [alloc.vec.Vec.set_val_eq, hidx] at hcl
        by_cases heq : l = link
        · subst heq
          rw [List.getElem?_set_self (by rw [counts.dirLen]; exact hbound)] at hcl
          have hclEq : cl = c' := Option.some.inj hcl.symm
          simp [hclEq, hc', hd, hzero]
        · have hne : link.val - 1 ≠ l.val - 1 := fun h => heq (UScalar.eq_of_val_eq (by omega))
          rw [List.getElem?_set_ne hne] at hcl
          have hv := counts.dirVal l cl hlpos hllt hcl
          cases hdl : dirs[l.val - 1]? <;> simp only [hdl] at hv ⊢
          · simp [hv, hzero, Ne.symm heq]
          · rename_i o; cases o <;> simp [hv, hzero, Ne.symm heq]
      · intro l cl hltag hcl
        have hne : l ≠ link := fun h => by
          rw [h] at hltag; have : link.val < 2147483648 := hltTag; omega
        have hv := counts.rowVal l cl hltag hcl
        cases hrl : rows[l.val - 2147483649]? <;> simp only [hrl] at hv ⊢
        · simp [hv, hzero, Ne.symm hne]
        · rename_i o; cases o <;> simp [hv, hzero, Ne.symm hne]
    · rw [ite_eq_right hdir]
      have hgeTag : ¬ link < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hdir
      simp only [SingleLinkLive, hgeTag, ite_false] at hlive
      obtain ⟨htag, r, hr⟩ := hlive
      have hbound : link.val - 2147483649 < rows.length := (List.getElem?_eq_some_iff.mp hr).1
      apply WP.spec_bind (U32.sub_spec (x := link) (y := Spike.radix.RADIX_LEAF_TAG) (by omega))
      intro sub1 hsub1
      apply WP.spec_bind (U32.sub_spec (x := sub1) (y := 1#u32) (by omega))
      intro sub2 hsub2
      have hidx : (UScalar.cast .Usize sub2).val = link.val - 2147483649 := by
        rw [u32_cast_usize_val]; omega
      simp only [lift, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind
        (alloc.vec.Vec.index_mut_usize_spec rowRefs (UScalar.cast .Usize sub2)
          (by change (UScalar.cast .Usize sub2).val < rowRefs.val.length; rw [hidx, counts.rowLen]; exact hbound))
      rintro ⟨c, back⟩ ⟨hc, hback⟩
      have hcGet : rowRefs.val[link.val - 2147483649]? = some c := by
        rw [← hidx, List.getElem?_eq_getElem (by rw [hidx, counts.rowLen]; exact hbound), ← hc]
      have hcVal : c.val = owners.count link := by
        have := counts.rowVal link c htag hcGet
        simpa [hr] using this
      apply WP.spec_bind (retain_reference_matches c link owners hcVal (by omega))
      rintro ⟨_, c'⟩ ⟨_, hc'⟩
      change WP.spec (Result.ok (dirRefs, back c')) _
      rw [WP.spec_ok, hback]
      refine ⟨counts.dirLen, by simp [alloc.vec.Vec.set_val_eq, counts.rowLen], ?_, ?_⟩
      · intro l cl hlpos hllt hcl
        have hne : l ≠ link := fun h => by
          rw [h] at hllt; have : link.val < 2147483648 := hllt; omega
        have hv := counts.dirVal l cl hlpos hllt hcl
        cases hdl : dirs[l.val - 1]? <;> simp only [hdl] at hv ⊢
        · simp [hv, hzero, Ne.symm hne]
        · rename_i o; cases o <;> simp [hv, hzero, Ne.symm hne]
      · intro l cl hltag hcl
        rw [alloc.vec.Vec.set_val_eq, hidx] at hcl
        by_cases heq : l = link
        · subst heq
          rw [List.getElem?_set_self (by rw [counts.rowLen]; exact hbound)] at hcl
          have hclEq : cl = c' := Option.some.inj hcl.symm
          simp [hclEq, hc', hr, hzero]
        · have hne : link.val - 2147483649 ≠ l.val - 2147483649 :=
            fun h => heq (UScalar.eq_of_val_eq (by omega))
          rw [List.getElem?_set_ne hne] at hcl
          have hv := counts.rowVal l cl hltag hcl
          cases hrl : rows[l.val - 2147483649]? <;> simp only [hrl] at hv ⊢
          · simp [hv, hzero, Ne.symm heq]
          · rename_i o; cases o <;> simp [hv, hzero, Ne.symm heq]

theorem release_link_refines {V : Type}
    (dirs : List (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (queue : NativeRetireQueue)
    (entries owners : List U32) (link : U32)
    (counts
      : RefCountsExact dirs rows dirRefs rowRefs
          (if link = 0#u32 then owners else link :: owners))
    (live : link ≠ 0#u32 → SingleLinkLive dirs rows link)
    (qv : RetirementQueueView queue entries)
    (qroom
      : link ≠ 0#u32
        → owners.count link = 0
        → queue.len.val = queue.slots.val.length
        → 2 * queue.slots.val.length + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.release_link dirRefs rowRefs queue link)
        (fun (dr, rr, rq) =>
          RefCountsExact dirs rows dr rr owners
          ∧ RetirementQueueView rq
              (if link != 0#u32 && owners.count link == 0 then
                  entries ++ [link]
                else
                  entries)) := by
  unfold Spike.radix.release_link
  by_cases hzero : link = 0#u32
  · subst hzero
    simpa [WP.spec_ok] using ⟨counts, qv⟩
  · rw [ite_eq_right hzero]
    simp only [hzero, ite_false] at counts
    have hlive := live hzero
    have htagVal : (Spike.radix.RADIX_LEAF_TAG : U32).val = 2147483648 := by
      simp [Spike.radix.RADIX_LEAF_TAG]
    have hone : (1#u32 : U32).val = 1 := rfl
    by_cases hdir : link < Spike.radix.RADIX_LEAF_TAG
    · rw [ite_eq_left hdir]
      have hltTag : link < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hdir
      simp only [SingleLinkLive, hltTag, ite_true] at hlive
      obtain ⟨hpos, d, hd⟩ := hlive
      have hbound : link.val - 1 < dirs.length := (List.getElem?_eq_some_iff.mp hd).1
      apply WP.spec_bind (U32.sub_spec (x := link) (y := 1#u32) (by omega))
      intro sub hsub
      have hidx : (UScalar.cast .Usize sub).val = link.val - 1 := by
        rw [u32_cast_usize_val]; omega
      simp only [lift, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind
        (alloc.vec.Vec.index_mut_usize_spec dirRefs (UScalar.cast .Usize sub)
          (by change (UScalar.cast .Usize sub).val < dirRefs.val.length; rw [hidx, counts.dirLen]; exact hbound))
      rintro ⟨c, back⟩ ⟨hc, hback⟩
      have hcGet : dirRefs.val[link.val - 1]? = some c := by
        rw [← hidx, List.getElem?_eq_getElem (by rw [hidx, counts.dirLen]; exact hbound), ← hc]
      have hcVal : c.val = (link :: owners).count link := by
        have := counts.dirVal link c hpos hltTag hcGet
        simpa [hd] using this
      apply WP.spec_bind (release_owner_schedules c queue link owners entries hcVal qv (qroom hzero))
      rintro ⟨c', rq⟩ ⟨hc', hqv⟩
      change WP.spec (Result.ok (back c', rowRefs, rq)) _
      rw [WP.spec_ok, hback]
      refine ⟨⟨by simp [alloc.vec.Vec.set_val_eq, counts.dirLen], counts.rowLen, ?_, ?_⟩, ?_⟩
      · intro l cl hlpos hllt hcl
        rw [alloc.vec.Vec.set_val_eq, hidx] at hcl
        by_cases heq : l = link
        · subst heq
          rw [List.getElem?_set_self (by rw [counts.dirLen]; exact hbound)] at hcl
          have hclEq : cl = c' := Option.some.inj hcl.symm
          simp [hclEq, hc', hd]
        · have hne : link.val - 1 ≠ l.val - 1 := fun h => heq (UScalar.eq_of_val_eq (by omega))
          rw [List.getElem?_set_ne hne] at hcl
          have hv := counts.dirVal l cl hlpos hllt hcl
          cases hdl : dirs[l.val - 1]? <;> simp only [hdl] at hv ⊢
          · simpa [List.count_cons, Ne.symm heq] using hv
          · rename_i o; cases o <;> simpa [List.count_cons, Ne.symm heq] using hv
      · intro l cl hltag hcl
        have hne : l ≠ link := fun h => by
          rw [h] at hltag; have : link.val < 2147483648 := hltTag; omega
        have hv := counts.rowVal l cl hltag hcl
        cases hrl : rows[l.val - 2147483649]? <;> simp only [hrl] at hv ⊢
        · simpa [List.count_cons, Ne.symm hne] using hv
        · rename_i o; cases o <;> simpa [List.count_cons, Ne.symm hne] using hv
      · by_cases hz : owners.count link = 0 <;> simp [hzero, hz] at hqv ⊢ <;> exact hqv
    · rw [ite_eq_right hdir]
      have hgeTag : ¬ link < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hdir
      simp only [SingleLinkLive, hgeTag, ite_false] at hlive
      obtain ⟨htag, r, hr⟩ := hlive
      have hbound : link.val - 2147483649 < rows.length := (List.getElem?_eq_some_iff.mp hr).1
      apply WP.spec_bind (U32.sub_spec (x := link) (y := Spike.radix.RADIX_LEAF_TAG) (by omega))
      intro sub1 hsub1
      apply WP.spec_bind (U32.sub_spec (x := sub1) (y := 1#u32) (by omega))
      intro sub2 hsub2
      have hidx : (UScalar.cast .Usize sub2).val = link.val - 2147483649 := by
        rw [u32_cast_usize_val]; omega
      simp only [lift, bind_ok, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind
        (alloc.vec.Vec.index_mut_usize_spec rowRefs (UScalar.cast .Usize sub2)
          (by change (UScalar.cast .Usize sub2).val < rowRefs.val.length; rw [hidx, counts.rowLen]; exact hbound))
      rintro ⟨c, back⟩ ⟨hc, hback⟩
      have hcGet : rowRefs.val[link.val - 2147483649]? = some c := by
        rw [← hidx, List.getElem?_eq_getElem (by rw [hidx, counts.rowLen]; exact hbound), ← hc]
      have hcVal : c.val = (link :: owners).count link := by
        have := counts.rowVal link c htag hcGet
        simpa [hr] using this
      apply WP.spec_bind (release_owner_schedules c queue link owners entries hcVal qv (qroom hzero))
      rintro ⟨c', rq⟩ ⟨hc', hqv⟩
      change WP.spec (Result.ok (dirRefs, back c', rq)) _
      rw [WP.spec_ok, hback]
      refine ⟨⟨counts.dirLen, by simp [alloc.vec.Vec.set_val_eq, counts.rowLen], ?_, ?_⟩, ?_⟩
      · intro l cl hlpos hllt hcl
        have hne : l ≠ link := fun h => by
          rw [h] at hllt; have : link.val < 2147483648 := hllt; omega
        have hv := counts.dirVal l cl hlpos hllt hcl
        cases hdl : dirs[l.val - 1]? <;> simp only [hdl] at hv ⊢
        · simpa [List.count_cons, Ne.symm hne] using hv
        · rename_i o; cases o <;> simpa [List.count_cons, Ne.symm hne] using hv
      · intro l cl hltag hcl
        rw [alloc.vec.Vec.set_val_eq, hidx] at hcl
        by_cases heq : l = link
        · subst heq
          rw [List.getElem?_set_self (by rw [counts.rowLen]; exact hbound)] at hcl
          have hclEq : cl = c' := Option.some.inj hcl.symm
          simp [hclEq, hc', hr]
        · have hne : link.val - 2147483649 ≠ l.val - 2147483649 :=
            fun h => heq (UScalar.eq_of_val_eq (by omega))
          rw [List.getElem?_set_ne hne] at hcl
          have hv := counts.rowVal l cl hltag hcl
          cases hrl : rows[l.val - 2147483649]? <;> simp only [hrl] at hv ⊢
          · simpa [List.count_cons, Ne.symm heq] using hv
          · rename_i o; cases o <;> simpa [List.count_cons, Ne.symm heq] using hv
      · by_cases hz : owners.count link = 0 <;> simp [hzero, hz] at hqv ⊢ <;> exact hqv

theorem single_new_refines (V : Type)
    : WP.spec (Spike.radix.SingleRadix.new V)
        (fun arena =>
          SingleLiveness arena []
          ∧ WP.spec (Spike.radix.SingleRadix.empty_root arena)
              (fun root => SingleView arena root [])) := by
  unfold Spike.radix.SingleRadix.new Spike.radix.Arena.new Spike.radix.SingleRadix.empty_root
  simp only [bind_ok]
  apply WP.spec_bind retirement_queue_new
  intro rq hrq
  rw [WP.spec_ok]
  refine ⟨
    ⟨
      ⟨
        by simp [RadixFree],
        by simp [RadixFree],
        (fun _ _ h => by simp at h),
        radix_empty_knowledge _
      ⟩,
      by simp,
      by simp,
      by simp,
      by simp,
      (fun _ h => by cases h),
      (fun _ h => by simp at h),
      ⟨by simp, by simp, (fun _ _ _ _ h => by simp at h), (fun _ _ _ h => by simp at h)⟩,
      ⟨[], hrq, List.nodup_nil, (fun _ h => by cases h)⟩
    ⟩,
    ?_
  ⟩
  rw [WP.spec_ok]
  exact ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩

theorem single_retain_root_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (pins : List U32) (root : Spike.radix.RadixRoot)
    (live : SingleLiveness arena pins)
    (rootLive
      : root ≠ 0#u32 → SingleLinkLive arena.values.dirs.val arena.values.rows.val root)
    (notQueued : root ≠ 0#u32 → radixReferences arena.values.dirs.val pins root > 0)
    (room : root ≠ 0#u32 → radixReferences arena.values.dirs.val pins root < U32.max)
    : WP.spec (Spike.radix.SingleRadix.retain_root arena root)
        (fun after =>
          after.values = arena.values
          ∧ SingleLiveness after (if root = 0#u32 then pins else root :: pins)) := by
  unfold Spike.radix.SingleRadix.retain_root
  apply WP.spec_bind
    (retain_link_refines arena.values.dirs.val arena.values.rows.val
      arena.dir_refs arena.row_refs (pins ++ arenaEdges arena.values.dirs.val) root
      live.counts rootLive room)
  rintro ⟨dr, rr⟩ hcounts
  change WP.spec (Result.ok { arena with dir_refs := dr, row_refs := rr }) _
  rw [WP.spec_ok]
  refine ⟨rfl, ?_⟩
  obtain ⟨entries, qv, qnd, qzero⟩ := live.queue
  by_cases hz : root = 0#u32
  · simp only [hz, ite_true] at hcounts ⊢
    exact ⟨live.valid, live.dirsBound, live.rowsBound, live.freeDirsNodup, live.freeRowsNodup,
      live.pinsLive, live.childrenLive, hcounts, entries, qv, qnd, qzero⟩
  · simp only [hz, ite_false] at hcounts ⊢
    refine ⟨live.valid, live.dirsBound, live.rowsBound, live.freeDirsNodup, live.freeRowsNodup,
      ?_, live.childrenLive, by simpa only [List.cons_append] using hcounts,
      entries, qv, qnd, ?_⟩
    · intro p hp
      rcases List.mem_cons.mp hp with rfl | old
      · exact rootLive hz
      · exact live.pinsLive p old
    · intro link hl
      obtain ⟨hliv, hcnt⟩ := qzero link hl
      refine ⟨hliv, ?_⟩
      have hne : link ≠ root := fun h => by
        rw [h] at hcnt
        have := notQueued hz
        omega
      simpa [radixReferences_eq, List.cons_append, List.count_cons, Ne.symm hne] using hcnt

theorem single_release_root_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (rest : List U32) (root : Spike.radix.RadixRoot)
    (live : SingleLiveness arena (if root = 0#u32 then rest else root :: rest))
    (qroom
      : 2 * (arena.values.dirs.val.length + arena.values.rows.val.length) + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.SingleRadix.release_root arena root)
        (fun after =>
          after.values = arena.values ∧ SingleLiveness after rest) := by
  unfold Spike.radix.SingleRadix.release_root
  obtain ⟨entries, qv, qnd, qzero⟩ := live.queue
  have hqBound : entries.length ≤ arena.values.dirs.val.length + arena.values.rows.val.length :=
    live_entries_bound qnd (fun l hl => (qzero l hl).1)
  have hcounts : RefCountsExact arena.values.dirs.val arena.values.rows.val
      arena.dir_refs arena.row_refs
      (if root = 0#u32 then rest ++ arenaEdges arena.values.dirs.val
       else root :: (rest ++ arenaEdges arena.values.dirs.val)) := by
    by_cases hz : root = 0#u32 <;> simp [hz] at live ⊢
    · exact live.counts
    · simpa [List.cons_append] using live.counts
  have hrootLive : root ≠ 0#u32 → SingleLinkLive arena.values.dirs.val arena.values.rows.val root := by
    intro hne
    have hmem : root ∈ (if root = 0#u32 then rest else root :: rest) := by simp [hne]
    exact live.pinsLive root hmem
  apply WP.spec_bind
    (release_link_refines arena.values.dirs.val arena.values.rows.val
      arena.dir_refs arena.row_refs arena.retired entries
      (rest ++ arenaEdges arena.values.dirs.val) root hcounts hrootLive qv
      (fun _ _ hfull => by
        have hs := qv.size
        omega))
  rintro ⟨dr, rr, rq⟩ ⟨hcnt', hqv'⟩
  change WP.spec (Result.ok { arena with dir_refs := dr, row_refs := rr, retired := rq }) _
  rw [WP.spec_ok]
  refine ⟨rfl, ?_⟩
  have hpinsRest : ∀ p ∈ rest, SingleLinkLive arena.values.dirs.val arena.values.rows.val p := by
    intro p hp
    apply live.pinsLive p
    by_cases hz : root = 0#u32 <;> simp [hz, hp]
  refine ⟨
    live.valid,
    live.dirsBound,
    live.rowsBound,
    live.freeDirsNodup,
    live.freeRowsNodup,
    hpinsRest,
    live.childrenLive,
    hcnt',
    _,
    hqv',
    ?_,
    ?_
  ⟩
  · by_cases hpush : (root != 0#u32 && (rest ++ arenaEdges arena.values.dirs.val).count root == 0) = true
    · rw [ite_eq_left hpush]
      simp only [Bool.and_eq_true, bne_iff_ne, beq_iff_eq] at hpush
      obtain ⟨hne, _⟩ := hpush
      have hnotIn : root ∉ entries := by
        intro hin
        have hz0 := (qzero root hin).2
        simp only [radixReferences_eq, hne, ite_false, List.cons_append, List.count_cons_self] at hz0
        omega
      exact List.nodup_append.mpr ⟨qnd, List.nodup_singleton _, fun x hx y hy => by
        rw [List.mem_singleton.mp hy]; exact fun h => hnotIn (h ▸ hx)⟩
    · rw [ite_eq_right hpush]
      exact qnd
  · intro link hl
    by_cases hpush : (root != 0#u32 && (rest ++ arenaEdges arena.values.dirs.val).count root == 0) = true
    · rw [ite_eq_left hpush] at hl
      simp only [Bool.and_eq_true, bne_iff_ne, beq_iff_eq] at hpush
      rcases List.mem_append.mp hl with old | newly
      · obtain ⟨hliv, hz0⟩ := qzero link old
        have hne : link ≠ root := fun h => by
          rw [h] at hz0
          simp only [radixReferences_eq, hpush.1, ite_false, List.cons_append, List.count_cons_self] at hz0
          omega
        refine ⟨hliv, ?_⟩
        simpa [radixReferences_eq, hpush.1, List.cons_append, List.count_cons, Ne.symm hne] using hz0
      · rw [List.mem_singleton.mp newly]
        exact ⟨hrootLive hpush.1, hpush.2⟩
    · rw [ite_eq_right hpush] at hl
      obtain ⟨hliv, hz0⟩ := qzero link hl
      refine ⟨hliv, ?_⟩
      by_cases hz : root = 0#u32
      · simpa [hz] using hz0
      · have hne : link ≠ root := fun h => by
          rw [h] at hz0
          simp only [radixReferences_eq, hz, ite_false, List.cons_append, List.count_cons_self] at hz0
          omega
        simpa [radixReferences_eq, hz, List.cons_append, List.count_cons, Ne.symm hne] using hz0

private theorem single_retire_one_loop_refines {V : Type}
    (dirs : List (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (queue : NativeRetireQueue)
    (dir : Spike.radix.RadixDir) (baseOwners entries : List U32)
    (counts : RefCountsExact dirs rows dirRefs rowRefs (dir.children.val ++ baseOwners))
    (childrenLive : ∀ c ∈ dir.children.val, c ≠ 0#u32 → SingleLinkLive dirs rows c)
    (qv : RetirementQueueView queue entries)
    (qnd : entries.Nodup)
    (qzero
      : ∀ l ∈ entries,
          SingleLinkLive dirs rows l ∧ (dir.children.val ++ baseOwners).count l = 0)
    (qroom : 2 * (dirs.length + rows.length) + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.SingleRadix.retire_one_loop dirRefs rowRefs queue dir 0#usize)
        (fun (dr, rr, rq) =>
          RefCountsExact dirs rows dr rr baseOwners
          ∧ ∃ entries',
              RetirementQueueView rq entries'
              ∧ entries'.Nodup
              ∧ ∀ l ∈ entries', SingleLinkLive dirs rows l ∧ baseOwners.count l = 0) := by
  unfold Spike.radix.SingleRadix.retire_one_loop
  have hfan : (Spike.radix.RADIX_FANOUT : Usize).val = 17 := by simp [Spike.radix.RADIX_FANOUT]
  have hclen : dir.children.val.length = 17 := by simp
  apply loop.spec_decr_nat (fun (_, _, _, slot) => 17 - (slot : Usize).val)
    (fun (dr, rr, rq, slot) =>
      slot.val ≤ 17
      ∧ RefCountsExact dirs rows dr rr (dir.children.val.drop slot.val ++ baseOwners)
      ∧ ∃ es,
          RetirementQueueView rq es
          ∧ es.Nodup
          ∧ ∀ l ∈ es,
              SingleLinkLive dirs rows l
              ∧ (dir.children.val.drop slot.val ++ baseOwners).count l = 0)
    _ _ _
  · rintro ⟨dr, rr, rq, slot⟩ ⟨hslot, hcnt, es, hqv, hnd, hzero⟩
    dsimp only at hslot hcnt hqv hnd hzero ⊢
    unfold Spike.radix.SingleRadix.retire_one_loop.body
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases run : slot < Spike.radix.RADIX_FANOUT
    · have hslt : slot.val < 17 := by
        have : slot.val < (Spike.radix.RADIX_FANOUT : Usize).val := run
        omega
      rw [ite_eq_left run]
      apply WP.spec_bind (Array.index_usize_spec dir.children slot (by simpa using hslt))
      intro child hchild
      have hdrop : dir.children.val.drop slot.val = child :: dir.children.val.drop (slot.val + 1) := by
        rw [List.drop_eq_getElem_cons (by omega), ← hchild]
      have hchildMem : child ∈ dir.children.val := hchild ▸ List.getElem_mem (by omega)
      let nextOwners := dir.children.val.drop (slot.val + 1) ++ baseOwners
      have hcntStep : RefCountsExact dirs rows dr rr
          (if child = 0#u32 then nextOwners else child :: nextOwners) := by
        rw [hdrop, List.cons_append] at hcnt
        by_cases hz : child = 0#u32
        · simp only [hz, ite_true]
          refine ⟨hcnt.dirLen, hcnt.rowLen, ?_, ?_⟩
          · intro l c hlpos hllt hcl
            have hv := hcnt.dirVal l c hlpos hllt hcl
            have hne : l ≠ 0#u32 := fun h => by rw [h] at hlpos; exact Nat.lt_irrefl 0 hlpos
            cases hdl : dirs[l.val - 1]? <;> simp only [hdl] at hv ⊢
            · simpa [hz, nextOwners, List.count_cons, Ne.symm hne] using hv
            · rename_i o; cases o <;> simpa [hz, nextOwners, List.count_cons, Ne.symm hne] using hv
          · intro l c hltag hcl
            have hv := hcnt.rowVal l c hltag hcl
            have hne : l ≠ 0#u32 := fun h => by
              rw [h] at hltag; have : (0#u32 : U32).val = 0 := rfl; omega
            cases hrl : rows[l.val - 2147483649]? <;> simp only [hrl] at hv ⊢
            · simpa [hz, nextOwners, List.count_cons, Ne.symm hne] using hv
            · rename_i o; cases o <;> simpa [hz, nextOwners, List.count_cons, Ne.symm hne] using hv
        · simpa [hz, nextOwners] using hcnt
      have hstepSpec :
          WP.spec
            (if child != 0#u32 then Spike.radix.release_link dr rr rq child
             else Result.ok (dr, rr, rq))
            (fun (dr', rr', rq') =>
              RefCountsExact dirs rows dr' rr' nextOwners
              ∧ ∃ es',
                  RetirementQueueView rq' es'
                  ∧ es'.Nodup
                  ∧ ∀ l ∈ es', SingleLinkLive dirs rows l ∧ nextOwners.count l = 0) := by
        by_cases hnz : child != 0#u32
        · have hne : child ≠ 0#u32 := bne_iff_ne.mp hnz
          rw [ite_eq_left hnz]
          have hqBound : es.length ≤ dirs.length + rows.length :=
            live_entries_bound hnd (fun l hl => (hzero l hl).1)
          apply WP.spec_mono
            (release_link_refines dirs rows dr rr rq es nextOwners child hcntStep
              (fun _ => childrenLive child hchildMem hne) hqv
              (fun _ _ hfull => by have hs := hqv.size; omega))
          rintro ⟨dr', rr', rq'⟩ ⟨hcnt', hqv'⟩
          refine ⟨hcnt', _, hqv', ?_, ?_⟩
          · by_cases hp : (child != 0#u32 && nextOwners.count child == 0) = true
            · rw [ite_eq_left hp]
              have hnotIn : child ∉ es := by
                intro hin
                have hz0 := (hzero child hin).2
                rw [hdrop, List.cons_append, List.count_cons_self] at hz0
                omega
              exact List.nodup_append.mpr ⟨hnd, List.nodup_singleton _, fun x hx y hy => by
                rw [List.mem_singleton.mp hy]; exact fun h => hnotIn (h ▸ hx)⟩
            · rw [ite_eq_right hp]
              exact hnd
          · intro l hl
            by_cases hp : (child != 0#u32 && nextOwners.count child == 0) = true
            · rw [ite_eq_left hp] at hl
              simp only [Bool.and_eq_true, bne_iff_ne, beq_iff_eq] at hp
              rcases List.mem_append.mp hl with old | newly
              · obtain ⟨hliv, hz0⟩ := hzero l old
                rw [hdrop, List.cons_append] at hz0
                have hne' : l ≠ child := fun h => by rw [h, List.count_cons_self] at hz0; omega
                exact ⟨hliv, by simpa [nextOwners, List.count_cons, Ne.symm hne'] using hz0⟩
              · rw [List.mem_singleton.mp newly]
                exact ⟨childrenLive child hchildMem hne, hp.2⟩
            · rw [ite_eq_right hp] at hl
              obtain ⟨hliv, hz0⟩ := hzero l hl
              rw [hdrop, List.cons_append] at hz0
              have hne' : l ≠ child := fun h => by rw [h, List.count_cons_self] at hz0; omega
              exact ⟨hliv, by simpa [nextOwners, List.count_cons, Ne.symm hne'] using hz0⟩
        · have hz : child = 0#u32 := by by_contra h; exact hnz (bne_iff_ne.mpr h)
          rw [ite_eq_right hnz, WP.spec_ok]
          refine ⟨by simpa [hz] using hcntStep, es, hqv, hnd, ?_⟩
          intro l hl
          obtain ⟨hliv, hz0⟩ := hzero l hl
          rw [hdrop, List.cons_append] at hz0
          have hne' : l ≠ 0#u32 := by
            unfold SingleLinkLive at hliv
            by_cases ht : l < 2147483648#u32 <;> simp only [ht, ite_true, ite_false] at hliv
            · intro h; rw [h] at hliv; exact Nat.lt_irrefl 0 hliv.1
            · intro h; rw [h] at hliv; have : (0#u32 : U32).val = 0 := rfl; omega
          exact ⟨hliv, by simpa [hz, nextOwners, List.count_cons, Ne.symm hne'] using hz0⟩
      apply WP.spec_bind hstepSpec
      rintro ⟨dr', rr', rq'⟩ ⟨hcnt', es', hqv', hnd', hzero'⟩
      have hcap : 17 ≤ Usize.max := by scalar_tac
      apply WP.spec_bind (Usize.add_spec (x := slot) (y := 1#usize) (by omega))
      intro slot1 hslot1
      rw [WP.spec_ok]
      dsimp only
      have hseq : slot1.val = slot.val + 1 := by omega
      refine ⟨⟨by omega, by simpa [hseq, nextOwners] using hcnt', es', hqv', hnd',
        by simpa [hseq, nextOwners] using hzero'⟩, by omega⟩
    · have hdone : slot.val = 17 := by
        have : ¬ slot.val < (Spike.radix.RADIX_FANOUT : Usize).val := run
        omega
      rw [ite_eq_right run, WP.spec_ok]
      have hnil : dir.children.val.drop slot.val = [] := List.drop_eq_nil_of_le (by omega)
      simp only [hnil, List.nil_append] at hcnt hzero
      exact ⟨hcnt, es, hqv, hnd, hzero⟩
  · have h0 : (0#usize : Usize).val = 0 := rfl
    exact ⟨by omega, by simpa [h0] using counts, entries, qv, qnd, by simpa [h0] using qzero⟩

theorem wp_spec_and {α : Type} {m : Result α} {P Q : α → Prop}
    (hp : WP.spec m P) (hq : WP.spec m Q)
    : WP.spec m (fun x => P x ∧ Q x) := by
  obtain ⟨x, hm, hpx⟩ := wp_spec_exists hp
  rw [hm, WP.spec_ok] at hq ⊢
  exact ⟨hpx, hq⟩

theorem single_retire_one_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (pins : List U32) (live : SingleLiveness arena pins)
    (qroom
      : 2 * (arena.values.dirs.val.length + arena.values.rows.val.length) + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.SingleRadix.retire_one arena)
        (fun (_, after) =>
          SingleLiveness after pins
          ∧ SinglePreservesPins arena after pins
          ∧ after.values.dirs.val.length = arena.values.dirs.val.length
          ∧ after.values.rows.val.length = arena.values.rows.val.length) := by
  unfold Spike.radix.SingleRadix.retire_one
  obtain ⟨entries, qv, qnd, qzero⟩ := live.queue
  apply WP.spec_bind (retirement_queue_pop arena.retired entries qv)
  rintro ⟨item, rq⟩ ⟨hitem, hqv⟩
  subst item
  cases entries with
  | nil =>
      change WP.spec (Result.ok (false, { arena with retired := rq })) _
      rw [WP.spec_ok]
      refine ⟨⟨live.valid, live.dirsBound, live.rowsBound, live.freeDirsNodup, live.freeRowsNodup,
        live.pinsLive, live.childrenLive, live.counts,
        ⟨[], hqv, List.nodup_nil, (fun _ h => by cases h)⟩⟩, ?_, rfl, rfl⟩
      intro r _ bs v
      exact ⟨⟨v.lookup, v.values, v.sorted⟩, rfl⟩
  | cons link tail =>
      change WP.spec (if link < Spike.radix.RADIX_LEAF_TAG then _ else _) _
      obtain ⟨hnotInTail, htailNd⟩ := List.nodup_cons.mp qnd
      obtain ⟨hlinkLive, hlinkZero⟩ := qzero link List.mem_cons_self
      have htagVal : (Spike.radix.RADIX_LEAF_TAG : U32).val = 2147483648 := by
        simp [Spike.radix.RADIX_LEAF_TAG]
      have hone : (1#u32 : U32).val = 1 := rfl
      by_cases hdir : link < Spike.radix.RADIX_LEAF_TAG
      · rw [ite_eq_left hdir]
        have hltTag : link < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hdir
        simp only [SingleLinkLive, hltTag, ite_true] at hlinkLive
        obtain ⟨hpos, dir, hdirSaved⟩ := hlinkLive
        have hidxBound : link.val - 1 < arena.values.dirs.val.length :=
          (List.getElem?_eq_some_iff.mp hdirSaved).1
        apply WP.spec_bind (U32.sub_spec (x := link) (y := 1#u32) (by omega))
        intro sub hsub
        let idx := UScalar.cast .Usize sub
        have hidx : idx.val = link.val - 1 := by simp only [idx, u32_cast_usize_val]; omega
        simp only [lift, bind_ok]
        have hfreeLen : arena.values.free_dirs.val.length < Usize.max := by
          have := free_len_le_slots live.valid.dirs live.freeDirsNodup
          omega
        have hdirLive : arena.values.dirs.val[idx.val]? = some (some dir) := by rwa [hidx]
        apply WP.spec_bind
          (wp_spec_and
            (radix_recycle_slot_matches arena.values.dirs arena.values.free_dirs idx dir
              hdirLive live.valid.dirs hfreeLen)
            (radix_recycle_dir_refines arena.values.dirs arena.values.free_dirs pins link
              idx dir (by omega) hdirLive live.valid.dirs hfreeLen hlinkZero))
        rintro ⟨removed, dirs', freeDirs'⟩
          ⟨⟨hrem, hcleared, hfreePush, hfreeValid, hkeepDirs⟩,
            ⟨_, _, hdirInv, hknow, hrefSplit, htreesKept⟩⟩
        subst removed
        have hdirsEq : dirs'.val = arena.values.dirs.val.set idx.val none := by
          apply List.ext_getElem?
          intro j
          by_cases hj : j = idx.val
          · subst hj; rw [hcleared, List.getElem?_set_self (by omega)]
          · rw [hkeepDirs j hj, List.getElem?_set_ne (Ne.symm hj)]
        have hdirsLen : dirs'.val.length = arena.values.dirs.val.length := by simp [hdirsEq]
        have hnotInFree : idx ∉ arena.values.free_dirs.val := by
          intro hin
          have hnone := live.valid.dirs.2 idx hin
          rw [hdirLive] at hnone
          cases hnone
        have hfreeNd : freeDirs'.val.Nodup := by
          rw [hfreePush]
          exact List.nodup_append.mpr ⟨live.freeDirsNodup, List.nodup_singleton _,
            fun x hx y hy => by rw [List.mem_singleton.mp hy]; exact fun h => hnotInFree (h ▸ hx)⟩
        have hliveAfter (l : U32) (hl : SingleLinkLive arena.values.dirs.val arena.values.rows.val l)
            (hne : l ≠ link) : SingleLinkLive dirs'.val arena.values.rows.val l := by
          unfold SingleLinkLive at hl ⊢
          by_cases ht : l < 2147483648#u32
          · simp only [ht, ite_true] at hl ⊢
            obtain ⟨hlp, dl, hdl⟩ := hl
            have hneIdx : l.val - 1 ≠ idx.val := fun h => hne (UScalar.eq_of_val_eq (by omega))
            exact ⟨hlp, dl, (hkeepDirs _ hneIdx).trans hdl⟩
          · simpa only [ht, ite_false] using hl
        have hdirNotSelf : ∀ c ∈ dir.children.val, c ≠ link := by
          intro c hc heq
          subst heq
          have hmem : c ∈ arenaEdges arena.values.dirs.val :=
            List.mem_flatMap.mpr ⟨dir, List.mem_filterMap.mpr
              ⟨some dir, List.mem_iff_getElem?.mpr ⟨idx.val, hdirLive⟩, rfl⟩, hc⟩
          have hposC := List.count_pos_iff.mpr (List.mem_append_right pins hmem)
          rw [← radixReferences_eq] at hposC
          omega
        have hchildrenAfter : ∀ c ∈ dir.children.val, c ≠ 0#u32 →
            SingleLinkLive dirs'.val arena.values.rows.val c := by
          intro c hc hnz
          have hmemDir : dir ∈ arena.values.dirs.val.filterMap id :=
            List.mem_filterMap.mpr ⟨some dir, List.mem_iff_getElem?.mpr ⟨idx.val, hdirLive⟩, rfl⟩
          exact hliveAfter c (live.childrenLive dir hmemDir c hc hnz) (hdirNotSelf c hc)
        have hcountsMid : RefCountsExact dirs'.val arena.values.rows.val arena.dir_refs arena.row_refs
            (dir.children.val ++ (pins ++ arenaEdges dirs'.val)) := by
          refine ⟨live.counts.dirLen.trans hdirsLen.symm, live.counts.rowLen, ?_, ?_⟩
          · intro l c hlpos hllt hcl
            have hv := live.counts.dirVal l c hlpos hllt hcl
            by_cases heq : l = link
            · subst heq
              rw [← hidx, hcleared]
              have hold : arena.values.dirs.val[l.val - 1]? = some (some dir) := hdirSaved
              rw [hold] at hv
              rw [radixReferences_eq] at hlinkZero
              exact hv.trans hlinkZero
            · have hneIdx : l.val - 1 ≠ idx.val := fun h => heq (UScalar.eq_of_val_eq (by omega))
              rw [hkeepDirs _ hneIdx]
              have hsplit := hrefSplit l
              simp only [radixReferences_eq] at hsplit
              cases hdl : arena.values.dirs.val[l.val - 1]? <;> simp only [hdl] at hv ⊢
              · rw [List.count_append, Nat.add_comm]; exact hv.trans hsplit
              · rename_i o; cases o <;> simp only at hv ⊢
                · exact hv
                · rw [List.count_append, Nat.add_comm]; exact hv.trans hsplit
          · intro l c hltag hcl
            have hv := live.counts.rowVal l c hltag hcl
            have hsplit := hrefSplit l
            simp only [radixReferences_eq] at hsplit
            cases hrl : arena.values.rows.val[l.val - 2147483649]? <;> simp only [hrl] at hv ⊢
            · rw [List.count_append, Nat.add_comm]; exact hv.trans hsplit
            · rename_i o; cases o <;> simp only at hv ⊢
              · exact hv
              · rw [List.count_append, Nat.add_comm]; exact hv.trans hsplit
        have htailZero : ∀ l ∈ tail,
            SingleLinkLive dirs'.val arena.values.rows.val l
            ∧ (dir.children.val ++ (pins ++ arenaEdges dirs'.val)).count l = 0 := by
          intro l hl
          obtain ⟨hliv, hz0⟩ := qzero l (List.mem_cons_of_mem _ hl)
          have hne : l ≠ link := fun h => hnotInTail (h ▸ hl)
          have hsplit := hrefSplit l
          simp only [radixReferences_eq] at hsplit hz0
          refine ⟨hliveAfter l hliv hne, ?_⟩
          rw [List.count_append]; omega
        apply WP.spec_bind
          (single_retire_one_loop_refines dirs'.val arena.values.rows.val arena.dir_refs
            arena.row_refs rq dir (pins ++ arenaEdges dirs'.val) tail
            hcountsMid hchildrenAfter hqv htailNd htailZero (by omega))
        rintro ⟨dr', rr', rq'⟩ ⟨hcnt', es', hqv', hnd', hzero'⟩
        change WP.spec (Result.ok (true,
          ({ values := { arena.values with dirs := dirs', free_dirs := freeDirs' },
             dir_refs := dr', row_refs := rr', retired := rq' } : Spike.radix.SingleRadix V))) _
        rw [WP.spec_ok]
        refine ⟨
          ⟨
            ⟨
              hfreeValid,
              live.valid.rows,
              hdirInv live.valid.directories,
              hknow _ live.valid.knowledge
            ⟩,
            hdirsLen ▸ live.dirsBound,
            live.rowsBound,
            hfreeNd,
            live.freeRowsNodup,
            ?_,
            ?_,
            hcnt',
            es',
            hqv',
            hnd',
            hzero'
          ⟩,
          ?_,
          hdirsLen,
          rfl
        ⟩
        · intro p hp
          have hne : p ≠ link := fun h => by
            rw [h] at hp
            have := List.count_pos_iff.mpr (List.mem_append_left (arenaEdges arena.values.dirs.val) hp)
            rw [← radixReferences_eq] at this
            omega
          exact hliveAfter p (live.pinsLive p hp) hne
        · intro d hd c hc hnz
          have hdOrig : d ∈ arena.values.dirs.val.filterMap id := by
            obtain ⟨opt, hopt, hval⟩ := List.mem_filterMap.mp hd
            cases opt with
            | none => cases hval
            | some d0 =>
                simp only [id, Option.some.injEq] at hval; subst hval
                obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hopt
                have hjNe : j ≠ idx.val := fun h => by rw [h, hcleared] at hj; cases hj
                rw [hkeepDirs j hjNe] at hj
                exact List.mem_filterMap.mpr ⟨some d0, List.mem_iff_getElem?.mpr ⟨j, hj⟩, rfl⟩
          have hneC : c ≠ link := fun h => by
            subst h
            have hmem : c ∈ arenaEdges dirs'.val := List.mem_flatMap.mpr ⟨d, hd, hc⟩
            have hposC := List.count_pos_iff.mpr (List.mem_append_right pins hmem)
            have hsplit := hrefSplit c
            simp only [radixReferences_eq] at hsplit hlinkZero
            omega
          exact hliveAfter c (live.childrenLive d hdOrig c hc hnz) hneC
        · intro r hr bs v
          obtain ⟨h, tree⟩ := v.lookup
          exact ⟨⟨⟨h, htreesKept h r bs hr tree⟩, v.values, v.sorted⟩, rfl⟩
      · rw [ite_eq_right hdir]
        have hgeTag : ¬ link < 2147483648#u32 := by simpa [Spike.radix.RADIX_LEAF_TAG] using hdir
        simp only [SingleLinkLive, hgeTag, ite_false] at hlinkLive
        obtain ⟨htag, row, hrowSaved⟩ := hlinkLive
        have hidxBound : link.val - 2147483649 < arena.values.rows.val.length :=
          (List.getElem?_eq_some_iff.mp hrowSaved).1
        apply WP.spec_bind (U32.sub_spec (x := link) (y := Spike.radix.RADIX_LEAF_TAG) (by omega))
        intro sub1 hsub1
        apply WP.spec_bind (U32.sub_spec (x := sub1) (y := 1#u32) (by omega))
        intro sub2 hsub2
        let idx := UScalar.cast .Usize sub2
        have hidx : idx.val = link.val - 2147483649 := by simp only [idx, u32_cast_usize_val]; omega
        simp only [lift, bind_ok]
        have hfreeLen : arena.values.free_rows.val.length < Usize.max := by
          have := free_len_le_slots live.valid.rows live.freeRowsNodup
          omega
        have hrowLive : arena.values.rows.val[idx.val]? = some (some row) := by rwa [hidx]
        apply WP.spec_bind
          (wp_spec_and
            (radix_recycle_slot_matches arena.values.rows arena.values.free_rows idx row
              hrowLive live.valid.rows hfreeLen)
            (radix_recycle_row_refines arena.values.dirs.val arena.values.rows
              arena.values.free_rows pins link idx row (by omega) hrowLive
              live.valid.rows hfreeLen hlinkZero))
        rintro ⟨removed, rows', freeRows'⟩
          ⟨⟨rfl, hcleared, hfreePush, hfreeValid, hkeepRows⟩, ⟨_, _, hknow, hrowsKept⟩⟩
        have hrowsEq : rows'.val = arena.values.rows.val.set idx.val none := by
          apply List.ext_getElem?
          intro j
          by_cases hj : j = idx.val
          · subst hj; rw [hcleared, List.getElem?_set_self (by omega)]
          · rw [hkeepRows j hj, List.getElem?_set_ne (Ne.symm hj)]
        have hrowsLen : rows'.val.length = arena.values.rows.val.length := by simp [hrowsEq]
        have hnotInFree : idx ∉ arena.values.free_rows.val := by
          intro hin
          have hnone := live.valid.rows.2 idx hin
          rw [hrowLive] at hnone
          cases hnone
        have hfreeNd : freeRows'.val.Nodup := by
          rw [hfreePush]
          exact List.nodup_append.mpr ⟨live.freeRowsNodup, List.nodup_singleton _,
            fun x hx y hy => by rw [List.mem_singleton.mp hy]; exact fun h => hnotInFree (h ▸ hx)⟩
        have hliveAfter (l : U32) (hl : SingleLinkLive arena.values.dirs.val arena.values.rows.val l)
            (hne : l ≠ link) : SingleLinkLive arena.values.dirs.val rows'.val l := by
          unfold SingleLinkLive at hl ⊢
          by_cases ht : l < 2147483648#u32
          · simpa only [ht, ite_true] using hl
          · simp only [ht, ite_false] at hl ⊢
            obtain ⟨hlp, rl, hrl⟩ := hl
            have hneIdx : l.val - 2147483649 ≠ idx.val := fun h => hne (UScalar.eq_of_val_eq (by omega))
            exact ⟨hlp, rl, (hkeepRows _ hneIdx).trans hrl⟩
        let nextArena : Spike.radix.SingleRadix V :=
          { arena with
            values := { arena.values with rows := rows', free_rows := freeRows' }
            retired := rq }
        change WP.spec (Result.ok (true, nextArena)) _
        rw [WP.spec_ok]
        refine ⟨⟨⟨live.valid.dirs, hfreeValid, live.valid.directories,
            hknow arena.values.dirs rfl live.valid.knowledge⟩,
          live.dirsBound, hrowsLen ▸ live.rowsBound, live.freeDirsNodup, hfreeNd, ?_, ?_, ?_,
          tail, hqv, htailNd, ?_⟩, ?_, rfl, hrowsLen⟩
        · intro p hp
          have hne : p ≠ link := fun h => by
            rw [h] at hp
            have := List.count_pos_iff.mpr (List.mem_append_left (arenaEdges arena.values.dirs.val) hp)
            rw [← radixReferences_eq] at this
            omega
          exact hliveAfter p (live.pinsLive p hp) hne
        · intro d hd c hc hnz
          have hne : c ≠ link := fun h => by
            subst h
            have hmem : c ∈ arenaEdges arena.values.dirs.val := List.mem_flatMap.mpr ⟨d, hd, hc⟩
            have := List.count_pos_iff.mpr (List.mem_append_right pins hmem)
            rw [← radixReferences_eq] at this
            omega
          exact hliveAfter c (live.childrenLive d hd c hc hnz) hne
        · refine ⟨live.counts.dirLen, live.counts.rowLen.trans hrowsLen.symm, live.counts.dirVal, ?_⟩
          intro l c hltag hcl
          have hv := live.counts.rowVal l c hltag hcl
          by_cases heq : l = link
          · subst heq
            rw [← hidx, hcleared]
            rw [hrowSaved] at hv
            rw [radixReferences_eq] at hlinkZero
            exact hv.trans hlinkZero
          · have hneIdx : l.val - 2147483649 ≠ idx.val := fun h => heq (UScalar.eq_of_val_eq (by omega))
            rw [hkeepRows _ hneIdx]
            exact hv
        · intro l hl
          obtain ⟨hliv, hz0⟩ := qzero l (List.mem_cons_of_mem _ hl)
          have hne : l ≠ link := fun h => hnotInTail (h ▸ hl)
          exact ⟨hliveAfter l hliv hne, hz0⟩
        · intro r hr bs v
          obtain ⟨h, tree⟩ := v.lookup
          obtain ⟨hr', hb'⟩ := hrowsKept h r bs hr tree v.values
          exact ⟨⟨⟨h, tree⟩, hr', v.sorted⟩, hb'⟩

theorem single_retire_budget_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (budget : Usize) (pins : List U32) (live : SingleLiveness arena pins)
    (qroom
      : 2 * (arena.values.dirs.val.length + arena.values.rows.val.length) + 1 ≤ Usize.max)
    : WP.spec (Spike.radix.SingleRadix.retire_budget arena budget)
        (fun (_, after) =>
          SingleLiveness after pins
          ∧ SinglePreservesPins arena after pins
          ∧ after.values.dirs.val.length = arena.values.dirs.val.length
          ∧ after.values.rows.val.length = arena.values.rows.val.length) := by
  unfold Spike.radix.SingleRadix.retire_budget Spike.radix.SingleRadix.retire_budget_loop
  apply loop.spec_decr_nat (fun (_, completed) => budget.val - (completed : Usize).val)
    (fun (cur, completed) =>
      completed.val ≤ budget.val
      ∧ SingleLiveness cur pins
      ∧ SinglePreservesPins arena cur pins
      ∧ cur.values.dirs.val.length = arena.values.dirs.val.length
      ∧ cur.values.rows.val.length = arena.values.rows.val.length)
    _ _ _
  · rintro ⟨cur, completed⟩ ⟨hcomp, hlive, hpres, hdl, hrl⟩
    dsimp only at hcomp hlive hpres hdl hrl ⊢
    unfold Spike.radix.SingleRadix.retire_budget_loop.body
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases run : completed < budget
    · have hlt : completed.val < budget.val := run
      rw [ite_eq_left run]
      apply WP.spec_bind (single_retire_one_refines cur pins hlive (by omega))
      rintro ⟨more, next⟩ ⟨hlive', hpres', hdl', hrl'⟩
      change WP.spec
        (if more = true then do
            let completed1 ← completed + 1#usize
            Result.ok (ControlFlow.cont (next, completed1))
          else Result.ok (ControlFlow.done (completed, next))) _
      cases more with
      | false =>
          simp only [Bool.false_eq_true, ite_false, WP.spec_ok]
          exact ⟨hlive', hpres.trans hpres', hdl'.trans hdl, hrl'.trans hrl⟩
      | true =>
          rw [ite_eq_left rfl]
          have hbmax : budget.val ≤ Usize.max := by scalar_tac
          apply WP.spec_bind (Usize.add_spec (x := completed) (y := 1#usize) (by omega))
          intro c' hc'
          rw [WP.spec_ok]
          dsimp only
          exact ⟨
            ⟨by omega, hlive', hpres.trans hpres', hdl'.trans hdl, hrl'.trans hrl⟩,
            by omega
          ⟩
    · rw [ite_eq_right run, WP.spec_ok]
      exact ⟨hlive, hpres, hdl, hrl⟩
  · have h0 : (0#usize : Usize).val = 0 := rfl
    exact ⟨by omega, live, SinglePreservesPins.refl _ _, rfl, rfl⟩

/-! ### Lockstep counted allocation and path-copying mutations -/

theorem arenaEdges_length_le (dirs : List (Option Spike.radix.RadixDir))
    : (arenaEdges dirs).length ≤ 17 * dirs.length := by
  unfold arenaEdges
  induction dirs with
  | nil => simp
  | cons opt rest ih =>
      cases opt with
      | none =>
          change ((rest.filterMap id).flatMap (·.children.val)).length ≤ 17 * (rest.length + 1)
          omega
      | some d =>
          change (d.children.val ++ (rest.filterMap id).flatMap (·.children.val)).length ≤
            17 * (rest.length + 1)
          rw [List.length_append]
          have hd : d.children.val.length = 17 := by simp
          omega

theorem owners_count_le_bound (dirs : List (Option Spike.radix.RadixDir))
    (pins : List U32) (target : U32)
    : (pins ++ arenaEdges dirs).count target ≤ pins.length + 17 * dirs.length := by
  have h1 : (pins ++ arenaEdges dirs).count target ≤ (pins ++ arenaEdges dirs).length :=
    List.count_le_length
  rw [List.length_append] at h1
  have h2 := arenaEdges_length_le dirs
  omega

private theorem retain_children_refines {V : Type}
    (dirs : List (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (dir : Spike.radix.RadixDir)
    (owners : List U32)
    (counts : RefCountsExact dirs rows dirRefs rowRefs owners)
    (childrenLive : ∀ c ∈ dir.children.val, c ≠ 0#u32 → SingleLinkLive dirs rows c)
    (room : ∀ target, owners.count target + 17 ≤ U32.max)
    : WP.spec (Spike.radix.retain_children dirRefs rowRefs dir)
        (fun (dr, rr) =>
          RefCountsExact dirs rows dr rr (dir.children.val ++ owners)) := by
  unfold Spike.radix.retain_children Spike.radix.retain_children_loop
  have hfan : (Spike.radix.RADIX_FANOUT : Usize).val = 17 := by simp [Spike.radix.RADIX_FANOUT]
  have hclen : dir.children.val.length = 17 := by simp
  apply loop.spec_decr_nat (fun (_, _, slot) => 17 - (slot : Usize).val)
    (fun (dr, rr, slot) =>
      slot.val ≤ 17
      ∧ RefCountsExact dirs rows dr rr (dir.children.val.take slot.val ++ owners))
    _ _ _
  · rintro ⟨dr, rr, slot⟩ ⟨hslot, hcnt⟩
    dsimp only at hslot hcnt ⊢
    unfold Spike.radix.retain_children_loop.body
    have hone : (1#usize : Usize).val = 1 := rfl
    by_cases run : slot < Spike.radix.RADIX_FANOUT
    · have hslt : slot.val < 17 := by
        have : slot.val < (Spike.radix.RADIX_FANOUT : Usize).val := run
        omega
      rw [ite_eq_left run]
      apply WP.spec_bind (Array.index_usize_spec dir.children slot (by simpa using hslt))
      intro child hchild
      have hchildMem : child ∈ dir.children.val := hchild ▸ List.getElem_mem (by omega)
      have htakeNext : dir.children.val.take (slot.val + 1) =
          dir.children.val.take slot.val ++ [child] := by
        rw [List.take_add_one, List.getElem?_eq_getElem (by omega), ← hchild, Option.toList_some]
      have hpermNext :
          (child :: (dir.children.val.take slot.val ++ owners)).Perm
            (dir.children.val.take (slot.val + 1) ++ owners) := by
        rw [htakeNext, List.append_assoc]
        exact (List.perm_middle (l₁ := dir.children.val.take slot.val) (a := child)).symm
      have hstepSpec :
          WP.spec
            (if child != 0#u32 then Spike.radix.retain_link dr rr child else Result.ok (dr, rr))
            (fun (dr', rr') =>
              RefCountsExact dirs rows dr' rr' (dir.children.val.take (slot.val + 1) ++ owners)) := by
        by_cases hnz : child != 0#u32
        · have hne : child ≠ 0#u32 := bne_iff_ne.mp hnz
          rw [ite_eq_left hnz]
          have hroomC : (dir.children.val.take slot.val ++ owners).count child < U32.max := by
            rw [List.count_append]
            have h1 : (dir.children.val.take slot.val).count child ≤ (dir.children.val.take slot.val).length :=
              List.count_le_length
            rw [List.length_take, Nat.min_eq_left (by omega)] at h1
            have h2 := room child
            omega
          apply WP.spec_mono
            (retain_link_refines dirs rows dr rr (dir.children.val.take slot.val ++ owners) child
              hcnt (fun _ => childrenLive child hchildMem hne) (fun _ => hroomC))
          rintro ⟨dr', rr'⟩ hcnt'
          simp only [hne, ite_false] at hcnt'
          exact hcnt'.perm hpermNext
        · have hz : child = 0#u32 := by by_contra h; exact hnz (bne_iff_ne.mpr h)
          rw [ite_eq_right hnz, WP.spec_ok]
          refine ⟨hcnt.dirLen, hcnt.rowLen, ?_, ?_⟩
          · intro l c hlpos hllt hcl
            have hv := hcnt.dirVal l c hlpos hllt hcl
            have hne : l ≠ 0#u32 := fun h => by rw [h] at hlpos; exact Nat.lt_irrefl 0 hlpos
            rw [← hpermNext.count_eq, hz, List.count_cons, beq_false_of_ne (Ne.symm hne)]
            simpa using hv
          · intro l c hltag hcl
            have hv := hcnt.rowVal l c hltag hcl
            have hne : l ≠ 0#u32 := fun h => by
              rw [h] at hltag; have : (0#u32 : U32).val = 0 := rfl; omega
            rw [← hpermNext.count_eq, hz, List.count_cons, beq_false_of_ne (Ne.symm hne)]
            simpa using hv
      apply WP.spec_bind hstepSpec
      rintro ⟨dr', rr'⟩ hcnt'
      have hcap : 17 ≤ Usize.max := by scalar_tac
      apply WP.spec_bind (Usize.add_spec (x := slot) (y := 1#usize) (by omega))
      intro slot1 hslot1
      rw [WP.spec_ok]
      dsimp only
      have hseq : slot1.val = slot.val + 1 := by omega
      exact ⟨⟨by omega, by rwa [hseq]⟩, by omega⟩
    · have hdone : slot.val = 17 := by
        have : ¬ slot.val < (Spike.radix.RADIX_FANOUT : Usize).val := run
        omega
      rw [ite_eq_right run, WP.spec_ok]
      have hfull : dir.children.val.take slot.val = dir.children.val := List.take_of_length_le (by omega)
      rwa [hfull] at hcnt
  · have h0 : (0#usize : Usize).val = 0 := rfl
    exact ⟨by omega, by simpa [h0] using counts⟩

private theorem alloc_counted_lockstep {T : Type}
    (slots : alloc.vec.Vec (Option T)) (refs : alloc.vec.Vec U32)
    (free : alloc.vec.Vec Usize) (val : T)
    (idx : Usize) (slots' : alloc.vec.Vec (Option T)) (free' : alloc.vec.Vec Usize)
    (halloc : Spike.radix.allocate slots free val = Result.ok (idx, slots', free'))
    (vacant : RadixFree slots free) (freeNd : free.val.Nodup)
    (hlen : refs.val.length = slots.val.length)
    (hvacZero
      : ∀ (i : Nat) (c : U32),
          slots.val[i]? = some none → refs.val[i]? = some c → c.val = 0)
    (hpushRoom : free.val = [] → slots.val.length < Usize.max)
    : WP.spec (Spike.radix.alloc_counted slots refs free val)
        (fun (idx2, slots2, refs2, free2) =>
          idx2 = idx
          ∧ slots2 = slots'
          ∧ free2 = free'
          ∧ free'.val.Nodup
          ∧ refs2.val.length = slots'.val.length
          ∧ slots'.val[idx.val]? = some (some val)
          ∧ (idx.val = slots.val.length
              → slots'.val = slots.val ++ [some val] ∧ refs2.val = refs.val ++ [0#u32])
          ∧ (idx.val < slots.val.length
              → slots.val[idx.val]? = some none
                ∧ slots'.val = slots.val.set idx.val (some val)
                ∧ refs2 = refs
                ∧ refs.val[idx.val]? = some 0#u32)) := by
  have hspec := radix_allocate_matches slots free val vacant hpushRoom
  rw [halloc, WP.spec_ok] at hspec
  obtain ⟨hnew, hkept, hfresh, hbound, hlenLe, hfree', _⟩ := hspec
  unfold Spike.radix.alloc_counted
  rw [halloc, bind_ok]
  change WP.spec
    (if idx = alloc.vec.Vec.len refs then do
        let refs1 ← alloc.vec.Vec.push refs 0#u32
        Result.ok (idx, slots', refs1, free')
      else do
        let i1 ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice U32) refs idx
        massert (i1 = 0#u32)
        Result.ok (idx, slots', refs, free')) _
  have hfreeLen : free.val.length = (alloc.vec.Vec.len free).val := (alloc.vec.Vec.len_val free).symm
  have hrefsLen : (alloc.vec.Vec.len refs).val = refs.val.length := alloc.vec.Vec.len_val refs
  unfold Spike.radix.allocate at halloc
  by_cases hempty : alloc.vec.Vec.len free = 0#usize
  · have hfreeNil : free.val = [] := List.eq_nil_of_length_eq_zero (by rw [hfreeLen, hempty]; rfl)
    rw [ite_eq_left hempty] at halloc
    have hroom := hpushRoom hfreeNil
    obtain ⟨s1, hs1Run, hs1Eq⟩ := wp_spec_exists (alloc.vec.Vec.push_spec slots (some val) hroom)
    rw [hs1Run, bind_ok, Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq] at halloc
    obtain ⟨hidxEq, hsEq, hfEq⟩ := halloc
    have hidxVal : idx.val = slots.val.length := by rw [← hidxEq]; exact alloc.vec.Vec.len_val slots
    have heqLen : idx = alloc.vec.Vec.len refs := UScalar.eq_of_val_eq (by omega)
    rw [ite_eq_left heqLen]
    apply WP.spec_bind (alloc.vec.Vec.push_spec refs 0#u32 (by omega))
    intro refs1 hrefs1
    rw [WP.spec_ok]
    refine ⟨rfl, rfl, rfl, hfEq ▸ freeNd, ?_, hnew, ?_, fun h => (Nat.lt_irrefl _ (hidxVal ▸ h)).elim⟩
    · simp [hrefs1, ← hsEq, hs1Eq, hlen]
    · intro _; exact ⟨by rw [← hsEq, hs1Eq], hrefs1⟩
  · have hfreePos : 0 < free.val.length := by
      have : free.val.length ≠ 0 := fun h => hempty (UScalar.eq_of_val_eq (by rw [← hfreeLen, h]; rfl))
      omega
    rw [ite_eq_right hempty] at halloc
    have hone : (1#usize : Usize).val = 1 := rfl
    obtain ⟨last, hlastRun, hlastVal⟩ := wp_spec_exists
      (Usize.sub_spec (x := alloc.vec.Vec.len free) (y := 1#usize) (by omega))
    rw [hlastRun, bind_ok, alloc.vec.Vec.index_slice_index] at halloc
    have hlastEq : last.val = free.val.length - 1 := by omega
    obtain ⟨j0, hj0Run, hj0Eq⟩ := wp_spec_exists
      (alloc.vec.Vec.index_usize_spec free last (by change last.val < free.val.length; omega))
    rw [hj0Run, bind_ok] at halloc
    have hnoneJ : slots.val[j0.val]? = some none :=
      vacant.2 j0 (hj0Eq ▸ List.getElem_mem (by omega))
    have hj0B : j0.val < slots.val.length := (List.getElem?_eq_some_iff.mp hnoneJ).1
    rw [alloc.vec.Vec.index_slice_index] at halloc
    obtain ⟨opt, hoptRun, hoptEq⟩ := wp_spec_exists
      (alloc.vec.Vec.index_usize_spec slots j0 (by change j0.val < slots.val.length; exact hj0B))
    rw [hoptRun, bind_ok] at halloc
    have hoptN : opt = none := by
      have := List.getElem?_eq_getElem hj0B
      rw [hnoneJ] at this
      exact hoptEq.trans (Option.some.inj this.symm)
    simp only [hoptN, core.option.Option.is_none, Option.isNone_none, massert, ite_true, bind_ok] at halloc
    obtain ⟨f1, hf1Run, hf1Eq⟩ := wp_spec_exists
      (alloc.vec.Vec.resize_spec core.clone.CloneUsize free last 0#usize rfl)
    rw [hf1Run, bind_ok, alloc.vec.Vec.index_mut_slice_index] at halloc
    obtain ⟨⟨_, back⟩, hbRun, _, hbEq⟩ := wp_spec_exists
      (alloc.vec.Vec.index_mut_usize_spec slots j0 (by change j0.val < slots.val.length; exact hj0B))
    rw [hbRun, bind_ok] at halloc
    change Result.ok (j0, back (some val), f1) = Result.ok (idx, slots', free') at halloc
    rw [Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq] at halloc
    obtain ⟨hj0EqIdx, hsEq, hfEq⟩ := halloc
    subst hj0EqIdx
    have hltLen : j0.val < slots.val.length := hj0B
    have hneLen : j0 ≠ alloc.vec.Vec.len refs := fun h => by
      have := congrArg UScalar.val h; omega
    have hsetEq : slots'.val = slots.val.set j0.val (some val) := by
      rw [← hsEq, hbEq, alloc.vec.Vec.set_val_eq]
    have hfreeNd' : free'.val.Nodup := by
      rw [← hfEq, hf1Eq, List.resize, show last.val - free.val.length = 0 by omega,
        List.replicate_zero, List.append_nil]
      exact freeNd.sublist (List.take_sublist _ _)
    rw [ite_eq_right hneLen, alloc.vec.Vec.index_slice_index]
    apply WP.spec_bind (alloc.vec.Vec.index_usize_spec refs j0 (by change j0.val < refs.val.length; omega))
    intro c hc
    have hcGet : refs.val[j0.val]? = some c := by
      rw [List.getElem?_eq_getElem (by omega), ← hc]
    have hcZero : c = 0#u32 := UScalar.eq_of_val_eq (hvacZero j0.val c hnoneJ hcGet)
    rw [hcZero]
    simp only [massert, ite_true, bind_ok, WP.spec_ok]
    exact ⟨trivial, trivial, trivial, hfreeNd', by simp [hsetEq, hlen], hnew,
      fun h => (Nat.lt_irrefl _ (h ▸ hltLen)).elim,
      fun _ => ⟨hnoneJ, hsetEq, trivial, hcZero ▸ hcGet⟩⟩

/-- Every element of `owners` is either `0#u32` or points to a live slot. -/
private def OwnersLive {V : Type} (dirs : List (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V))) (owners : List U32)
    : Prop :=
  ∀ l ∈ owners, l ≠ 0#u32 → SingleLinkLive dirs rows l

private theorem alloc_row_counts {V : Type}
    {dirs : List (Option Spike.radix.RadixDir)}
    {rows rows' : alloc.vec.Vec (Option (Spike.radix.RadixRow V))}
    {dirRefs rowRefs rowRefs' : alloc.vec.Vec U32}
    {owners : List U32} {idx : Usize} {row : Spike.radix.RadixRow V}
    (counts : RefCountsExact dirs rows.val dirRefs rowRefs owners)
    (ownersLive : OwnersLive dirs rows.val owners)
    (hlen' : rowRefs'.val.length = rows'.val.length)
    (happend
      : idx.val = rows.val.length
        → rows'.val = rows.val ++ [some row] ∧ rowRefs'.val = rowRefs.val ++ [0#u32])
    (hreuse
      : idx.val < rows.val.length
        → rows.val[idx.val]? = some none
          ∧ rows'.val = rows.val.set idx.val (some row)
          ∧ rowRefs' = rowRefs
          ∧ rowRefs.val[idx.val]? = some 0#u32)
    (hidxLe : idx.val ≤ rows.val.length)
    : RefCountsExact dirs rows'.val dirRefs rowRefs' owners
      ∧ (∀ l, SingleLinkLive dirs rows.val l → SingleLinkLive dirs rows'.val l)
      ∧ (∀ (leaf : U32),
          leaf.val = idx.val + 2147483649
          → SingleLinkLive dirs rows'.val leaf ∧ owners.count leaf = 0) := by
  have hleafZero : ∀ (leaf : U32), leaf.val = idx.val + 2147483649 → owners.count leaf = 0 := by
    intro leaf hlval
    rw [List.count_eq_zero]
    intro hmem
    have hnz : leaf ≠ 0#u32 := fun h => by rw [h] at hlval; have : (0#u32 : U32).val = 0 := rfl; omega
    have hliv := ownersLive leaf hmem hnz
    have hge : ¬ leaf < 2147483648#u32 := by
      intro hlt; have : leaf.val < 2147483648 := hlt; omega
    simp only [SingleLinkLive, hge, ite_false] at hliv
    obtain ⟨_, r, hr⟩ := hliv
    have hsub : leaf.val - 2147483649 = idx.val := by omega
    rw [hsub] at hr
    rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
    · rw [(hreuse hlt).1] at hr; cases hr
    · rw [heq, List.getElem?_eq_none (Nat.le_refl _)] at hr; cases hr
  rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
  · obtain ⟨hnone, hset, rfl, hzero⟩ := hreuse hlt
    refine ⟨⟨counts.dirLen, hlen', counts.dirVal, ?_⟩, ?_, ?_⟩
    · intro l c hltag hcl
      by_cases hsame : l.val - 2147483649 = idx.val
      · have hlval : l.val = idx.val + 2147483649 := by omega
        have hc0 : c = 0#u32 := Option.some.inj (hcl.symm.trans (hsame ▸ hzero))
        rw [hset, hsame, List.getElem?_set_self hlt, hc0, hleafZero l hlval]
        rfl
      · rw [hset, List.getElem?_set_ne (Ne.symm hsame)]
        exact counts.rowVal l c hltag hcl
    · intro l hl
      unfold SingleLinkLive at hl ⊢
      by_cases ht : l < 2147483648#u32
      · simpa only [ht, ite_true] using hl
      · simp only [ht, ite_false] at hl ⊢
        obtain ⟨hlp, r, hr⟩ := hl
        have hne : idx.val ≠ l.val - 2147483649 := fun h => by rw [← h, hnone] at hr; cases hr
        exact ⟨hlp, r, by rw [hset, List.getElem?_set_ne hne]; exact hr⟩
    · intro leaf hlval
      refine ⟨?_, hleafZero leaf hlval⟩
      have hge : ¬ leaf < 2147483648#u32 := by intro h; have : leaf.val < 2147483648 := h; omega
      simp only [SingleLinkLive, hge, ite_false]
      exact ⟨by omega, row, by rw [hset, show leaf.val - 2147483649 = idx.val by omega, List.getElem?_set_self hlt]⟩
  · obtain ⟨hsApp, hrApp⟩ := happend heq
    refine ⟨⟨counts.dirLen, hlen', counts.dirVal, ?_⟩, ?_, ?_⟩
    · intro l c hltag hcl
      rw [hrApp] at hcl
      by_cases hltOld : l.val - 2147483649 < rows.val.length
      · rw [List.getElem?_append_left (by rw [counts.rowLen]; exact hltOld)] at hcl
        rw [hsApp, List.getElem?_append_left hltOld]
        exact counts.rowVal l c hltag hcl
      · have heqEnd : l.val - 2147483649 = rows.val.length := by
          have := (List.getElem?_eq_some_iff.mp hcl).1
          rw [List.length_append, List.length_singleton, counts.rowLen] at this
          omega
        rw [List.getElem?_append_right (by rw [counts.rowLen]; omega),
          show l.val - 2147483649 - rowRefs.val.length = 0 by rw [counts.rowLen]; omega] at hcl
        have hc0 : c = 0#u32 := Option.some.inj hcl.symm
        rw [hsApp, List.getElem?_append_right (by omega),
          show l.val - 2147483649 - rows.val.length = 0 by omega, hc0,
          hleafZero l (by omega)]
        rfl
    · intro l hl
      unfold SingleLinkLive at hl ⊢
      by_cases ht : l < 2147483648#u32
      · simpa only [ht, ite_true] using hl
      · simp only [ht, ite_false] at hl ⊢
        obtain ⟨hlp, r, hr⟩ := hl
        have hb := (List.getElem?_eq_some_iff.mp hr).1
        exact ⟨hlp, r, by rw [hsApp, List.getElem?_append_left hb]; exact hr⟩
    · intro leaf hlval
      refine ⟨?_, hleafZero leaf hlval⟩
      have hge : ¬ leaf < 2147483648#u32 := by intro h; have : leaf.val < 2147483648 := h; omega
      simp only [SingleLinkLive, hge, ite_false]
      exact ⟨by omega, row, by
        rw [hsApp, List.getElem?_append_right (by omega),
          show leaf.val - 2147483649 - rows.val.length = 0 by omega]; rfl⟩

private theorem filterMap_set_none_perm {α : Type} (xs : List (Option α)) (i : Nat)
    (x : α) (hnone : xs[i]? = some none)
    : ((xs.set i (some x)).filterMap id).Perm (x :: xs.filterMap id) := by
  induction xs generalizing i with
  | nil => simp at hnone
  | cons hd tl ih =>
      cases i with
      | zero =>
          have hhd : hd = none := Option.some.inj hnone
          subst hhd
          simp
      | succ i =>
          have hrest := ih i hnone
          cases hd with
          | none => simpa using hrest
          | some y =>
              simp only [List.set_cons_succ, List.filterMap_cons, id]
              exact (hrest.cons y).trans (List.Perm.swap x y _)

private theorem alloc_dir_counts {V : Type}
    {dirs dirs' : alloc.vec.Vec (Option Spike.radix.RadixDir)}
    {rows : List (Option (Spike.radix.RadixRow V))}
    {dirRefs dirRefs' rowRefs : alloc.vec.Vec U32}
    {pins : List U32} {idx : Usize} {dir : Spike.radix.RadixDir}
    (counts
      : RefCountsExact dirs.val rows dirRefs rowRefs
          (dir.children.val ++ (pins ++ arenaEdges dirs.val)))
    (ownersLive
      : OwnersLive dirs.val rows (dir.children.val ++ (pins ++ arenaEdges dirs.val)))
    (hlen' : dirRefs'.val.length = dirs'.val.length)
    (happend
      : idx.val = dirs.val.length
        → dirs'.val = dirs.val ++ [some dir] ∧ dirRefs'.val = dirRefs.val ++ [0#u32])
    (hreuse
      : idx.val < dirs.val.length
        → dirs.val[idx.val]? = some none
          ∧ dirs'.val = dirs.val.set idx.val (some dir)
          ∧ dirRefs' = dirRefs
          ∧ dirRefs.val[idx.val]? = some 0#u32)
    (hidxLe : idx.val ≤ dirs.val.length)
    : (arenaEdges dirs'.val).Perm (dir.children.val ++ arenaEdges dirs.val)
      ∧ RefCountsExact dirs'.val rows dirRefs' rowRefs (pins ++ arenaEdges dirs'.val)
      ∧ (∀ l, SingleLinkLive dirs.val rows l → SingleLinkLive dirs'.val rows l)
      ∧ (∀ (node : U32),
          node.val = idx.val + 1
          → node < 2147483648#u32
          → SingleLinkLive dirs'.val rows node
            ∧ (pins ++ arenaEdges dirs'.val).count node = 0) := by
  have hedgesPerm : (arenaEdges dirs'.val).Perm (dir.children.val ++ arenaEdges dirs.val) := by
    rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
    · obtain ⟨hnone, hset, _, _⟩ := hreuse hlt
      have hp := filterMap_set_none_perm dirs.val idx.val dir hnone
      simpa [arenaEdges, hset] using hp.flatMap_right (·.children.val)
    · obtain ⟨hsApp, _⟩ := happend heq
      simpa [arenaEdges, hsApp]
        using (List.perm_append_comm
                (l₁ := (dirs.val.filterMap id).flatMap (·.children.val))
                (l₂ := dir.children.val))
  have hownersPerm : (pins ++ arenaEdges dirs'.val).Perm (dir.children.val ++ (pins ++ arenaEdges dirs.val)) := by
    have h1 : (pins ++ (dir.children.val ++ arenaEdges dirs.val)).Perm
        ((pins ++ dir.children.val) ++ arenaEdges dirs.val) := by
      rw [List.append_assoc]
    have h2 : ((pins ++ dir.children.val) ++ arenaEdges dirs.val).Perm
        ((dir.children.val ++ pins) ++ arenaEdges dirs.val) :=
      List.perm_append_comm.append_right _
    have h3 : ((dir.children.val ++ pins) ++ arenaEdges dirs.val).Perm
          (dir.children.val ++ (pins ++ arenaEdges dirs.val)) := by
        rw [List.append_assoc]
    exact (hedgesPerm.append_left pins).trans (h1.trans (h2.trans h3))
  have hnodeZero : ∀ (node : U32), node.val = idx.val + 1 → node < 2147483648#u32 →
      (pins ++ arenaEdges dirs'.val).count node = 0 := by
    intro node hnval hltTag
    rw [hownersPerm.count_eq, List.count_eq_zero]
    intro hmem
    have hnz : node ≠ 0#u32 := fun h => by rw [h] at hnval; have : (0#u32 : U32).val = 0 := rfl; omega
    have hliv := ownersLive node hmem hnz
    simp only [SingleLinkLive, hltTag, ite_true] at hliv
    obtain ⟨_, d, hd⟩ := hliv
    have hsub : node.val - 1 = idx.val := by omega
    rw [hsub] at hd
    rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
    · rw [(hreuse hlt).1] at hd; cases hd
    · rw [heq, List.getElem?_eq_none (Nat.le_refl _)] at hd; cases hd
  have hcounts' := counts.perm hownersPerm.symm
  rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
  · obtain ⟨hnone, hset, rfl, hzero⟩ := hreuse hlt
    refine ⟨hedgesPerm, ⟨hlen', hcounts'.rowLen, ?_, ?_⟩, ?_, ?_⟩
    · intro l c hlpos hllt hcl
      by_cases hsame : l.val - 1 = idx.val
      · have hnval : l.val = idx.val + 1 := by omega
        have hc0 : c = 0#u32 := Option.some.inj (hcl.symm.trans (hsame ▸ hzero))
        have hAt : dirs'.val[l.val - 1]? = some (some dir) := by
          rw [hset, hsame, List.getElem?_set_self hlt]
        rw [hAt, hc0, hnodeZero l hnval hllt]
        rfl
      · have hAt : dirs'.val[l.val - 1]? = dirs.val[l.val - 1]? := by
          rw [hset, List.getElem?_set_ne (Ne.symm hsame)]
        rw [hAt]
        exact hcounts'.dirVal l c hlpos hllt hcl
    · intro l c hltag hcl
      exact hcounts'.rowVal l c hltag hcl
    · intro l hl
      unfold SingleLinkLive at hl ⊢
      by_cases ht : l < 2147483648#u32
      · simp only [ht, ite_true] at hl ⊢
        obtain ⟨hlp, d, hd⟩ := hl
        have hne : idx.val ≠ l.val - 1 := fun h => by rw [← h, hnone] at hd; cases hd
        exact ⟨hlp, d, by rw [hset, List.getElem?_set_ne hne]; exact hd⟩
      · simpa only [ht, ite_false] using hl
    · intro node hnval hltTag
      refine ⟨?_, hnodeZero node hnval hltTag⟩
      simp only [SingleLinkLive, hltTag, ite_true]
      exact ⟨by omega, dir, by rw [hset, show node.val - 1 = idx.val by omega, List.getElem?_set_self hlt]⟩
  · obtain ⟨hsApp, hrApp⟩ := happend heq
    refine ⟨hedgesPerm, ⟨hlen', hcounts'.rowLen, ?_, ?_⟩, ?_, ?_⟩
    · intro l c hlpos hllt hcl
      rw [hrApp] at hcl
      by_cases hltOld : l.val - 1 < dirs.val.length
      · rw [List.getElem?_append_left (by rw [hcounts'.dirLen]; exact hltOld)] at hcl
        have hAt : dirs'.val[l.val - 1]? = dirs.val[l.val - 1]? := by
          rw [hsApp, List.getElem?_append_left hltOld]
        rw [hAt]
        exact hcounts'.dirVal l c hlpos hllt hcl
      · have heqEnd : l.val - 1 = dirs.val.length := by
          have := (List.getElem?_eq_some_iff.mp hcl).1
          rw [List.length_append, List.length_singleton, hcounts'.dirLen] at this
          omega
        rw [List.getElem?_append_right (by rw [hcounts'.dirLen]; omega),
          show l.val - 1 - dirRefs.val.length = 0 by rw [hcounts'.dirLen]; omega] at hcl
        have hc0 : c = 0#u32 := Option.some.inj hcl.symm
        have hAt : dirs'.val[l.val - 1]? = some (some dir) := by
          rw [hsApp, List.getElem?_append_right (by omega),
            show l.val - 1 - dirs.val.length = 0 by omega]; rfl
        rw [hAt, hc0, hnodeZero l (by omega) hllt]
        rfl
    · intro l c hltag hcl
      exact hcounts'.rowVal l c hltag hcl
    · intro l hl
      unfold SingleLinkLive at hl ⊢
      by_cases ht : l < 2147483648#u32
      · simp only [ht, ite_true] at hl ⊢
        obtain ⟨hlp, d, hd⟩ := hl
        have hb := (List.getElem?_eq_some_iff.mp hd).1
        exact ⟨hlp, d, by rw [hsApp, List.getElem?_append_left hb]; exact hd⟩
      · simpa only [ht, ite_false] using hl
    · intro node hnval hltTag
      refine ⟨?_, hnodeZero node hnval hltTag⟩
      simp only [SingleLinkLive, hltTag, ite_true]
      exact ⟨by omega, dir, by
        rw [hsApp, List.getElem?_append_right (by omega),
          show node.val - 1 - dirs.val.length = 0 by omega]; rfl⟩

/-- Lockstep invariant carried through counted directory allocation and path copying. -/
private structure DirCountState {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32)
    (freeDirs : alloc.vec.Vec Usize)
    (pins : List U32)
    : Prop where
  vacant : RadixFree dirs freeDirs
  freeNd : freeDirs.val.Nodup
  dirsBound : dirs.val.length ≤ 2147483647
  pinsLive : ∀ p ∈ pins, SingleLinkLive dirs.val rows p
  childrenLive
    : ∀ d ∈ dirs.val.filterMap id,
      ∀ c ∈ d.children.val, c ≠ 0#u32 → SingleLinkLive dirs.val rows c
  counts : RefCountsExact dirs.val rows dirRefs rowRefs (pins ++ arenaEdges dirs.val)

private theorem DirCountState.ownersLive {V : Type}
    {dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)}
    {rows : List (Option (Spike.radix.RadixRow V))} {dirRefs rowRefs : alloc.vec.Vec U32}
    {freeDirs : alloc.vec.Vec Usize} {pins : List U32}
    (st : DirCountState dirs rows dirRefs rowRefs freeDirs pins)
    : OwnersLive dirs.val rows (pins ++ arenaEdges dirs.val) := by
  intro l hl hnz
  rcases List.mem_append.mp hl with hp | he
  · exact st.pinsLive l hp
  · obtain ⟨d, hd, hc⟩ := List.mem_flatMap.mp he
    exact st.childrenLive d hd l hc hnz

private theorem loop_invariant_of_ok {α β : Type}
    (b : α → Result (ControlFlow α β)) (P : α → β → Prop)
    (step
      : ∀ x r,
          b x = Result.ok r
          → match r with
            | .done y => P x y
            | .cont x' => ∀ y, P x' y → P x y)
    {x : α} {y : β} (hrun : loop b x = Result.ok y)
    : P x y := by
  let Reach (a : α) : Prop := ∃ z, loop b a = Result.ok z
  let motive : (α → Result β) → Prop := fun f => ∀ a, Reach a → WP.dspec (f a) (P a)
  have hadm : Lean.Order.admissible motive := by
    apply Lean.Order.admissible_pi
    intro a
    apply Lean.Order.admissible_pi
    intro _
    exact WP.dspec_func_admissible a (P a)
  have hmain : motive (loop b) := by
    apply loop.fixpoint_induct b motive hadm
    intro f ih a ⟨z, hz⟩
    have hspec : WP.spec (loop b a) (· = z) := by rw [hz, WP.spec_ok]
    rw [loop.eq_1] at hspec hz
    cases hb : b a using Result.cases with
    | div => rw [hb] at hspec; simp at hspec
    | vis _ _ => rw [hb] at hspec; simp at hspec
    | ret r =>
        change b a = Result.ok r at hb
        simp only [hb, bind_ok] at hz ⊢
        cases r with
        | done z₁ =>
            rw [WP.dspec_ok]
            exact step a (.done z₁) hb
        | cont a' =>
            exact WP.dspec_mono (ih a' ⟨z, hz⟩) (step a (.cont a') hb)
  have h1 := hmain x ⟨y, hrun⟩
  rw [hrun, WP.dspec_ok] at h1
  exact h1

private theorem link_at_ok_lt (idx : Usize) (isLeaf : Bool) (out : U32)
    (h : Spike.radix.link_at idx isLeaf = Result.ok out)
    : idx.val < 2147483647 := by
  by_contra hge
  have hs : WP.spec (Spike.radix.link_at idx isLeaf) (· = out) := by rw [h, WP.spec_ok]
  unfold Spike.radix.link_at at hs
  have hnot : ¬ (idx < 2147483647#usize) := fun hlt => hge hlt
  simp [massert, hnot] at hs

private theorem allocate_len_le {T : Type} (slots : alloc.vec.Vec (Option T))
    (free : alloc.vec.Vec Usize) (item : T) (idx : Usize)
    (slots' : alloc.vec.Vec (Option T)) (free' : alloc.vec.Vec Usize)
    (h : Spike.radix.allocate slots free item = Result.ok (idx, slots', free'))
    : slots.val.length ≤ slots'.val.length := by
  have hs : WP.spec (Spike.radix.allocate slots free item) (· = (idx, slots', free')) := by
    rw [h, WP.spec_ok]
  unfold Spike.radix.allocate at hs
  dsimp only at hs
  by_cases h0 : alloc.vec.Vec.len free = 0#usize
  · rw [ite_eq_left h0] at hs
    cases hpush : alloc.vec.Vec.push slots (some item) using Result.cases with
    | div => rw [hpush] at hs; simp at hs
    | vis _ _ => rw [hpush] at hs; simp at hs
    | ret s1 =>
        change alloc.vec.Vec.push slots (some item) = Result.ok s1 at hpush
        rw [hpush, bind_ok, WP.spec_ok] at hs
        unfold alloc.vec.Vec.push at hpush
        dsimp only at hpush
        split at hpush
        · rw [Result.ok.injEq] at hpush
          obtain ⟨_, hs2⟩ := Prod.mk.inj hs
          obtain ⟨hdEq, _⟩ := Prod.mk.inj hs2
          rw [← hdEq, ← hpush]
          simp [List.concat_eq_append]
        · exact absurd hpush (by simp [Result.fail])
  · rw [ite_eq_right h0] at hs
    cases hsub : alloc.vec.Vec.len free - 1#usize using Result.cases with
    | div => rw [hsub] at hs; simp at hs
    | vis _ _ => rw [hsub] at hs; simp at hs
    | ret last =>
        change alloc.vec.Vec.len free - 1#usize = Result.ok last at hsub
        rw [hsub, bind_ok] at hs
        cases hfi
              : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Usize) free
                  last
          using Result.cases with
        | div => rw [hfi] at hs; simp at hs
        | vis _ _ => rw [hfi] at hs; simp at hs
        | ret i =>
            change alloc.vec.Vec.index _ free last = Result.ok i at hfi
            rw [hfi, bind_ok] at hs
            cases hsi
                  : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice (Option T))
                      slots i
              using Result.cases with
            | div => rw [hsi] at hs; simp at hs
            | vis _ _ => rw [hsi] at hs; simp at hs
            | ret cur =>
                change alloc.vec.Vec.index _ slots i = Result.ok cur at hsi
                rw [hsi, bind_ok] at hs
                cases cur with
                | some _ => simp [core.option.Option.is_none, massert] at hs
                | none =>
                    simp only [core.option.Option.is_none, massert, Option.isNone, ite_true, bind_ok] at hs
                    cases hres
                          : alloc.vec.Vec.resize core.clone.CloneUsize free last 0#usize
                      using Result.cases with
                    | div => rw [hres] at hs; simp at hs
                    | vis _ _ => rw [hres] at hs; simp at hs
                    | ret f1 =>
                        change alloc.vec.Vec.resize _ free last 0#usize = Result.ok f1 at hres
                        rw [hres, bind_ok] at hs
                        cases him
                              : alloc.vec.Vec.index_mut
                                  (core.slice.index.SliceIndexUsizeSlice (Option T)) slots
                                  i
                          using Result.cases with
                        | div => rw [him] at hs; simp at hs
                        | vis _ _ => rw [him] at hs; simp at hs
                        | ret im =>
                            obtain ⟨cur1, back⟩ := im
                            change alloc.vec.Vec.index_mut _ slots i = Result.ok (cur1, back) at him
                            rw [him, bind_ok] at hs
                            change WP.spec (Result.ok (i, back (some item), f1)) _ at hs
                            rw [WP.spec_ok] at hs
                            have hlt : i.val < slots.val.length := by
                              by_contra hge
                              rw [alloc.vec.Vec.index_mut_slice_index] at him
                              unfold alloc.vec.Vec.index_mut_usize alloc.vec.Vec.index_usize at him
                              have hnone : slots.val[i.val]? = none := List.getElem?_eq_none (Nat.le_of_not_gt hge)
                              simp [hnone] at him
                            rw [alloc.vec.Vec.index_mut_slice_index] at him
                            have hims := alloc.vec.Vec.index_mut_usize_spec slots i hlt
                            rw [him, WP.spec_ok] at hims
                            obtain ⟨_, hs2⟩ := Prod.mk.inj hs
                            obtain ⟨hseq, _⟩ := Prod.mk.inj hs2
                            rw [← hseq, hims.2]
                            simp [alloc.vec.Vec.set]

private theorem add_directory_len_le (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (free : alloc.vec.Vec Usize) (dir : Spike.radix.RadixDir) (n : U32)
    (dirs' : alloc.vec.Vec (Option Spike.radix.RadixDir)) (free' : alloc.vec.Vec Usize)
    (h : Spike.radix.add_directory dirs free dir = Result.ok (n, dirs', free'))
    : dirs.val.length ≤ dirs'.val.length := by
  have hs : WP.spec (Spike.radix.add_directory dirs free dir) (· = (n, dirs', free')) := by
    rw [h, WP.spec_ok]
  unfold Spike.radix.add_directory at hs
  obtain ⟨first, hfRun, _⟩ := wp_spec_exists (radix_first_child_matches dir)
  rw [hfRun, bind_ok] at hs
  by_cases hfnz : first != 0#u32
  · simp only [massert, hfnz, ite_true, bind_ok] at hs
    cases hpre
          : (if first >= Spike.radix.RADIX_LEAF_TAG then
                Result.ok first
              else do
                let s := alloc.vec.Vec.deref dirs
                let rd ← Spike.radix.directory s first
                Result.ok rd.first)
      using Result.cases with
    | div => rw [hpre] at hs; simp at hs
    | vis _ _ => rw [hpre] at hs; simp at hs
    | ret first1 =>
        change _ = Result.ok first1 at hpre
        rw [hpre, bind_ok] at hs
        cases hal : Spike.radix.allocate dirs free { dir with first := first1 }
          using Result.cases with
        | div => rw [hal] at hs; simp at hs
        | vis _ _ => rw [hal] at hs; simp at hs
        | ret ar =>
            obtain ⟨idx, d1, f1⟩ := ar
            change Spike.radix.allocate dirs free { dir with first := first1 } =
              Result.ok (idx, d1, f1) at hal
            rw [hal, bind_ok] at hs
            change WP.spec (do
              let i1 ← Spike.radix.link_at idx false
              Result.ok (i1, d1, f1)) (· = (n, dirs', free')) at hs
            cases hlk : Spike.radix.link_at idx false using Result.cases with
            | div => rw [hlk] at hs; simp at hs
            | vis _ _ => rw [hlk] at hs; simp at hs
            | ret n1 =>
                change Spike.radix.link_at idx false = Result.ok n1 at hlk
                rw [hlk, bind_ok, WP.spec_ok] at hs
                obtain ⟨_, hs2⟩ := Prod.mk.inj hs
                obtain ⟨hdEq, _⟩ := Prod.mk.inj hs2
                rw [← hdEq]
                exact allocate_len_le dirs free { dir with first := first1 } idx d1 f1 hal
  · simp [massert, hfnz] at hs

private theorem copy_parent_len_le (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (free : alloc.vec.Vec Usize) (parent : U32) (slot : Usize) (child : U32) (c : U32)
    (dirs' : alloc.vec.Vec (Option Spike.radix.RadixDir)) (free' : alloc.vec.Vec Usize)
    (h
      : Spike.radix.copy_parent dirs free parent slot child = Result.ok (c, dirs', free'))
    : dirs.val.length ≤ dirs'.val.length := by
  have hs : WP.spec (Spike.radix.copy_parent dirs free parent slot child) (· = (c, dirs', free')) := by
    rw [h, WP.spec_ok]
  unfold Spike.radix.copy_parent at hs
  dsimp only at hs
  cases hd : Spike.radix.directory (alloc.vec.Vec.deref dirs) parent
    using Result.cases with
  | div => rw [hd] at hs; simp at hs
  | vis _ _ => rw [hd] at hs; simp at hs
  | ret dir =>
      change Spike.radix.directory (alloc.vec.Vec.deref dirs) parent = Result.ok dir at hd
      rw [hd, bind_ok] at hs
      cases hset : Spike.radix.RadixDir.set_child dir slot child using Result.cases with
      | div => rw [hset] at hs; simp at hs
      | vis _ _ => rw [hset] at hs; simp at hs
      | ret dir1 =>
          change Spike.radix.RadixDir.set_child dir slot child = Result.ok dir1 at hset
          rw [hset, bind_ok] at hs
          cases hpow : core.num.U32.is_power_of_two dir1.mask using Result.cases with
          | div => rw [hpow] at hs; simp at hs
          | vis _ _ => rw [hpow] at hs; simp at hs
          | ret b =>
              change core.num.U32.is_power_of_two dir1.mask = Result.ok b at hpow
              rw [hpow, bind_ok] at hs
              cases b with
              | true =>
                  simp only [ite_true] at hs
                  obtain ⟨fc, hfc, _⟩ := wp_spec_exists (radix_first_child_matches dir1)
                  rw [hfc, bind_ok, WP.spec_ok] at hs
                  obtain ⟨_, rfl, _⟩ := Prod.mk.inj hs
                  exact Nat.le_refl _
              | false =>
                  simp only [Bool.false_eq_true, ite_false] at hs
                  cases hadd : Spike.radix.add_directory dirs free dir1
                    using Result.cases with
                  | div => rw [hadd] at hs; simp at hs
                  | vis _ _ => rw [hadd] at hs; simp at hs
                  | ret ar =>
                      obtain ⟨c1, d1, f1⟩ := ar
                      change Spike.radix.add_directory dirs free dir1 = Result.ok (c1, d1, f1) at hadd
                      rw [hadd, WP.spec_ok] at hs
                      obtain ⟨_, hs2⟩ := Prod.mk.inj hs
                      obtain ⟨hdEq, _⟩ := Prod.mk.inj hs2
                      rw [← hdEq]
                      exact add_directory_len_le dirs free dir1 c1 d1 f1 hadd

private theorem rebuild_path_loop_len_mono (path : Slice (U32 × Usize))
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (child : U32) (e : Usize)
    (res : U32 × alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec Usize)
    (h : Spike.radix.rebuild_path_loop dirs free path child e = Result.ok res)
    : dirs.val.length ≤ res.2.1.val.length := by
  unfold Spike.radix.rebuild_path_loop at h
  refine loop_invariant_of_ok
    (fun (d, f, c, e) => Spike.radix.rebuild_path_loop.body path d f c e)
    (fun a z => a.1.val.length ≤ z.2.1.val.length) ?_ h
  rintro ⟨d1, f1, c1, e1⟩ r hb
  dsimp only at hb
  have hs : WP.spec (Spike.radix.rebuild_path_loop.body path d1 f1 c1 e1) (· = r) := by
    rw [hb, WP.spec_ok]
  unfold Spike.radix.rebuild_path_loop.body at hb hs
  by_cases hpos : e1 > 0#usize
  · rw [ite_eq_left hpos] at hb hs
    cases hsub : e1 - 1#usize using Result.cases with
    | div => rw [hsub] at hs; simp at hs
    | vis _ _ => rw [hsub] at hs; simp at hs
    | ret end1 =>
        change e1 - 1#usize = Result.ok end1 at hsub
        rw [hsub, bind_ok] at hb hs
        cases hp : Slice.index_usize path end1 using Result.cases with
        | div => rw [hp] at hs; simp at hs
        | vis _ _ => rw [hp] at hs; simp at hs
        | ret p =>
            obtain ⟨parent, slot⟩ := p
            change Slice.index_usize path end1 = Result.ok (parent, slot) at hp
            rw [hp, bind_ok] at hb hs
            change (do
              let (c2, d2, f2) ← Spike.radix.copy_parent d1 f1 parent slot c1
              Result.ok (ControlFlow.cont (d2, f2, c2, end1))) = Result.ok r at hb
            change WP.spec (do
              let (c2, d2, f2) ← Spike.radix.copy_parent d1 f1 parent slot c1
              Result.ok (ControlFlow.cont (d2, f2, c2, end1))) (· = r) at hs
            cases hcp : Spike.radix.copy_parent d1 f1 parent slot c1
              using Result.cases with
            | div => rw [hcp] at hs; simp at hs
            | vis _ _ => rw [hcp] at hs; simp at hs
            | ret cpRes =>
                obtain ⟨c2, d2, f2⟩ := cpRes
                change Spike.radix.copy_parent d1 f1 parent slot c1 = Result.ok (c2, d2, f2) at hcp
                rw [hcp, bind_ok] at hb
                change Result.ok (ControlFlow.cont (d2, f2, c2, end1)) = Result.ok r at hb
                rw [Result.ok.injEq] at hb
                subst hb
                intro z hz
                exact Nat.le_trans (copy_parent_len_le d1 f1 parent slot c1 c2 d2 f2 hcp) hz
  · rw [ite_eq_right hpos, Result.ok.injEq] at hb
    subst hb
    exact Nat.le_refl _

private theorem add_directory_counted_lockstep {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (freeDirs : alloc.vec.Vec Usize)
    (dir : Spike.radix.RadixDir) (pins : List U32)
    (node : U32) (dirs' : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (freeDirs' : alloc.vec.Vec Usize)
    (hadd
      : Spike.radix.add_directory dirs freeDirs dir = Result.ok (node, dirs', freeDirs'))
    (st : DirCountState dirs rows dirRefs rowRefs freeDirs pins)
    (hchildren : ∀ c ∈ dir.children.val, c ≠ 0#u32 → SingleLinkLive dirs.val rows c)
    (hrefRoom : pins.length + 17 * (dirs.val.length + 1) ≤ U32.max)
    : WP.spec (Spike.radix.add_directory_counted dirs dirRefs rowRefs freeDirs dir)
        (fun (node2, dirs2, dr2, rr2, free2) =>
          node2 = node
          ∧ dirs2 = dirs'
          ∧ free2 = freeDirs'
          ∧ DirCountState dirs' rows dr2 rr2 freeDirs' pins
          ∧ SingleLinkLive dirs'.val rows node
          ∧ ¬ SingleLinkLive dirs.val rows node
          ∧ node ≠ 0#u32
          ∧ dirs'.val.length ≤ dirs.val.length + 1
          ∧ (∀ l, SingleLinkLive dirs.val rows l → SingleLinkLive dirs'.val rows l)
          ∧ ∀ target,
              radixReferences dirs.val pins target = 0
              → dir.children.val.count target = 0
              → radixReferences dirs'.val pins target = 0) := by
  have hptrRoom : 2147483647 < Usize.max := by scalar_tac
  have haddSpec : WP.spec (Spike.radix.add_directory dirs freeDirs dir) (· = (node, dirs', freeDirs')) := by
    rw [hadd, WP.spec_ok]
  unfold Spike.radix.add_directory at hadd haddSpec
  unfold Spike.radix.add_directory_counted
  obtain ⟨first, hfRun, _⟩ := wp_spec_exists (radix_first_child_matches dir)
  rw [hfRun, bind_ok] at hadd haddSpec ⊢
  by_cases hfnz : first != 0#u32
  · simp only [massert, hfnz, ite_true, bind_ok] at hadd haddSpec ⊢
    cases hpre
          : (if first >= Spike.radix.RADIX_LEAF_TAG then
                Result.ok first
              else do
                let s := alloc.vec.Vec.deref dirs
                let rd ← Spike.radix.directory s first
                Result.ok rd.first)
      using Result.cases with
    | div =>
        rw [hpre] at haddSpec; simp at haddSpec
    | vis _ _ =>
        rw [hpre] at haddSpec; simp at haddSpec
    | ret first1 =>
        change _ = Result.ok first1 at hpre
        simp only [hpre, bind_ok] at hadd ⊢
        let dir1 : Spike.radix.RadixDir := { dir with first := first1 }
        obtain ⟨⟨idx, d1, f1⟩, hallocRun, hallocSpec⟩ := wp_spec_exists
          (radix_allocate_matches dirs freeDirs dir1 st.vacant (fun _ => by have := st.dirsBound; omega))
        obtain ⟨_, _, _, hidxBound, hlenLe, hvac', _⟩ := hallocSpec
        rw [hallocRun, bind_ok] at hadd
        have hadd1 : (Spike.radix.link_at idx false >>= fun i1 => Result.ok (i1, d1, f1)) =
            Result.ok (node, dirs', freeDirs') := hadd
        have hidxLtMax : idx.val < 2147483647 := by
          cases hlk : Spike.radix.link_at idx false using Result.cases with
          | div =>
              have hs : WP.spec (Spike.radix.link_at idx false >>= fun i1 => Result.ok (i1, d1, f1))
                  (· = (node, dirs', freeDirs')) := by rw [hadd1, WP.spec_ok]
              rw [hlk] at hs; simp at hs
          | vis _ _ =>
              have hs : WP.spec (Spike.radix.link_at idx false >>= fun i1 => Result.ok (i1, d1, f1))
                  (· = (node, dirs', freeDirs')) := by rw [hadd1, WP.spec_ok]
              rw [hlk] at hs; simp at hs
          | ret n0 =>
              change Spike.radix.link_at idx false = Result.ok n0 at hlk
              exact link_at_ok_lt idx false n0 hlk
        obtain ⟨n1, hlinkRun, hlinkVal⟩ := wp_spec_exists (radix_link_matches idx false hidxLtMax)
        rw [hlinkRun, bind_tc_ok, Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq] at hadd1
        obtain ⟨rfl, rfl, rfl⟩ := hadd1
        have hnodeVal : n1.val = idx.val + 1 := by simpa using hlinkVal
        have hnodeLt : n1 < 2147483648#u32 := by change n1.val < 2147483648; omega
        have hnodeNz : n1 ≠ 0#u32 := fun h => by rw [h] at hnodeVal; have : (0#u32 : U32).val = 0 := rfl; omega
        apply WP.spec_bind
          (retain_children_refines dirs.val rows dirRefs rowRefs dir1
            (pins ++ arenaEdges dirs.val) st.counts hchildren
            (fun t => by have := owners_count_le_bound dirs.val pins t; omega))
        rintro ⟨dr1, rr1⟩ hcnt1
        have hvacZero : ∀ (i : Nat) (c : U32), dirs.val[i]? = some none → dr1.val[i]? = some c → c.val = 0 := by
          intro i c hnone hc
          have hiLt : i < dirs.val.length := (List.getElem?_eq_some_iff.mp hnone).1
          let l : U32 := UScalar.ofNatCore (i + 1) (by have := st.dirsBound; scalar_tac)
          have hlVal : l.val = i + 1 := rfl
          have hsub : l.val - 1 = i := by omega
          have := hcnt1.dirVal l c (by omega) (by change l.val < 2147483648; have := st.dirsBound; omega) (by rwa [hsub])
          simpa [hsub, hnone] using this
        apply WP.spec_bind
          (alloc_counted_lockstep dirs dr1 freeDirs dir1 idx d1 f1 hallocRun st.vacant
            st.freeNd hcnt1.dirLen hvacZero (fun _ => by have := st.dirsBound; omega))
        rintro ⟨idx2, d2, dr2, f2⟩ ⟨hidxEq, hdEq, hfEq, hfreeNd', hdrLen', hnew, happ, hreu⟩
        subst idx2 d2 f2
        change WP.spec (Spike.radix.link_at idx false >>= fun i1 => Result.ok (i1, d1, dr2, rr1, f1)) _
        rw [hlinkRun, bind_tc_ok, WP.spec_ok]
        have howners1 : OwnersLive dirs.val rows (dir1.children.val ++ (pins ++ arenaEdges dirs.val)) := by
          intro l hl hnz
          rcases List.mem_append.mp hl with hc | ho
          · exact hchildren l hc hnz
          · exact st.ownersLive l ho hnz
        have hidxLe : idx.val ≤ dirs.val.length := by
          by_cases h : idx.val = dirs.val.length
          · exact Nat.le_of_eq h
          · have : idx.val < d1.val.length := (List.getElem?_eq_some_iff.mp hnew).1
            omega
        obtain ⟨hedgesPerm, hcnt2, hkeepLive, hnodeSpec⟩ :=
          alloc_dir_counts hcnt1 howners1 hdrLen' happ hreu hidxLe
        have hd1Bound : d1.val.length ≤ 2147483647 := by
          rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
          · have hset := (hreu hlt).2.1
            rw [hset, List.length_set]
            exact st.dirsBound
          · have hsApp := (happ heq).1
            rw [hsApp, List.length_append, List.length_singleton]
            omega
        refine ⟨rfl, rfl, rfl, ⟨hvac', hfreeNd', hd1Bound,
          fun p hp => hkeepLive p (st.pinsLive p hp), ?_, hcnt2⟩,
          (hnodeSpec n1 hnodeVal hnodeLt).1, ?_, hnodeNz, hlenLe, hkeepLive, ?_⟩
        · intro d hd c hc hnz
          have hdMem : d = dir1 ∨ d ∈ dirs.val.filterMap id := by
            rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
            · obtain ⟨hnone, hset, _, _⟩ := hreu hlt
              have hp := filterMap_set_none_perm dirs.val idx.val dir1 hnone
              rw [hset] at hd
              exact List.mem_cons.mp (hp.subset hd)
            · obtain ⟨hsApp, _⟩ := happ heq
              simp only [hsApp, List.filterMap_append, List.filterMap_cons, List.filterMap_nil, id] at hd
              rcases List.mem_append.mp hd with old | newly
              · exact Or.inr old
              · exact Or.inl (List.mem_singleton.mp newly)
          rcases hdMem with rfl | old
          · exact hkeepLive c (hchildren c hc hnz)
          · exact hkeepLive c (st.childrenLive d old c hc hnz)
        · intro hlivOld
          simp only [SingleLinkLive, hnodeLt, ite_true] at hlivOld
          obtain ⟨_, dOld, hdOld⟩ := hlivOld
          have hsub : n1.val - 1 = idx.val := by omega
          rw [hsub] at hdOld
          rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
          · rw [(hreu hlt).1] at hdOld; cases hdOld
          · rw [heq, List.getElem?_eq_none (Nat.le_refl _)] at hdOld; cases hdOld
        · intro target hzero hnotChild
          rw [radixReferences_eq, List.count_append, hedgesPerm.count_eq, List.count_append]
          rw [radixReferences_eq, List.count_append] at hzero
          have hnotChild1 : dir1.children.val.count target = 0 := hnotChild
          omega
  · simp [massert, hfnz] at haddSpec

private theorem copy_parent_counted_lockstep {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (freeDirs : alloc.vec.Vec Usize)
    (parent : U32) (slot : Usize) (child : U32) (pins entries : List U32)
    (resChild : U32) (dirs' : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (freeDirs' : alloc.vec.Vec Usize)
    (hcopy
      : Spike.radix.copy_parent dirs freeDirs parent slot child
        = Result.ok (resChild, dirs', freeDirs'))
    (st : DirCountState dirs rows dirRefs rowRefs freeDirs pins)
    (hchildLive : child ≠ 0#u32 → SingleLinkLive dirs.val rows child)
    (hchildNotQ : ∀ l ∈ entries, l ≠ child)
    (hqZero
      : ∀ l ∈ entries,
          SingleLinkLive dirs.val rows l ∧ radixReferences dirs.val pins l = 0)
    (hrefRoom : pins.length + 17 * (dirs.val.length + 1) ≤ U32.max)
    : WP.spec
        (Spike.radix.copy_parent_counted dirs dirRefs rowRefs freeDirs parent slot child)
        (fun (c2, d2, dr2, rr2, f2) =>
          c2 = resChild
          ∧ d2 = dirs'
          ∧ f2 = freeDirs'
          ∧ DirCountState dirs' rows dr2 rr2 freeDirs' pins
          ∧ (resChild ≠ 0#u32 → SingleLinkLive dirs'.val rows resChild)
          ∧ (∀ l ∈ entries, l ≠ resChild)
          ∧ (∀ l ∈ entries,
              SingleLinkLive dirs'.val rows l ∧ radixReferences dirs'.val pins l = 0)
          ∧ dirs'.val.length ≤ dirs.val.length + 1
          ∧ (∀ l, SingleLinkLive dirs.val rows l → SingleLinkLive dirs'.val rows l)) := by
  have hspec : WP.spec (Spike.radix.copy_parent dirs freeDirs parent slot child)
      (· = (resChild, dirs', freeDirs')) := by rw [hcopy, WP.spec_ok]
  unfold Spike.radix.copy_parent at hcopy hspec
  unfold Spike.radix.copy_parent_counted
  dsimp only at hcopy hspec ⊢
  cases hdirRun : Spike.radix.directory (alloc.vec.Vec.deref dirs) parent
    using Result.cases with
  | div => rw [hdirRun] at hspec; simp at hspec
  | vis _ _ => rw [hdirRun] at hspec; simp at hspec
  | ret dir =>
      change Spike.radix.directory (alloc.vec.Vec.deref dirs) parent = Result.ok dir at hdirRun
      simp only [hdirRun, bind_ok] at hcopy hspec ⊢
      have hdirMem : dir ∈ dirs.val.filterMap id := by
        have hds : WP.spec (Spike.radix.directory (alloc.vec.Vec.deref dirs) parent) (· = dir) := by
          rw [hdirRun, WP.spec_ok]
        unfold Spike.radix.directory at hds
        cases hsub : parent - 1#u32 using Result.cases with
        | div => rw [hsub] at hds; simp at hds
        | vis _ _ => rw [hsub] at hds; simp at hds
        | ret sub =>
            change parent - 1#u32 = Result.ok sub at hsub
            simp only [hsub, lift, bind_ok] at hds
            cases hidx
                  : Slice.index_usize (alloc.vec.Vec.deref dirs) (UScalar.cast .Usize sub)
              using Result.cases with
            | div => rw [hidx] at hds; simp at hds
            | vis _ _ => rw [hidx] at hds; simp at hds
            | ret opt =>
                change Slice.index_usize (alloc.vec.Vec.deref dirs) (UScalar.cast .Usize sub) = Result.ok opt at hidx
                simp only [hidx, bind_ok] at hds
                cases opt with
                | none => simp at hds
                | some d0 =>
                    simp only [WP.spec_ok] at hds; subst d0
                    have hget : dirs.val[(UScalar.cast .Usize sub).val]? = some (some dir) := by
                      unfold Slice.index_usize at hidx
                      rw [Slice.getElem?_Usize_eq] at hidx
                      simp only [alloc.vec.Vec.deref, Slice.from_val] at hidx
                      cases hge : dirs.val[(UScalar.cast .Usize sub).val]? with
                      | none =>
                          rw [hge] at hidx; exact absurd hidx (by simp [Result.fail])
                      | some v =>
                          rw [hge, Result.ok.injEq] at hidx
                          rw [hidx]
                    exact List.mem_filterMap.mpr
                      ⟨some dir, List.mem_iff_getElem?.mpr ⟨_, hget⟩, rfl⟩
      cases hset : Spike.radix.RadixDir.set_child dir slot child using Result.cases with
      | div => rw [hset] at hspec; simp at hspec
      | vis _ _ => rw [hset] at hspec; simp at hspec
      | ret dir1 =>
          change Spike.radix.RadixDir.set_child dir slot child = Result.ok dir1 at hset
          simp only [hset, bind_ok] at hcopy hspec ⊢
          have hslotLt : slot.val < 17 := by
            by_contra hge
            have hs : WP.spec (Spike.radix.RadixDir.set_child dir slot child) (· = dir1) := by
              rw [hset, WP.spec_ok]
            unfold Spike.radix.RadixDir.set_child at hs
            have hnone : dir.children.val[slot.val]? = none :=
              List.getElem?_eq_none (by simp; omega)
            simp [Array.index_mut_usize, Array.index_usize, Array.getElem?_Usize_eq, hnone] at hs
          have hsetSpec := radix_set_child_matches dir slot child hslotLt
          rw [hset, WP.spec_ok] at hsetSpec
          have hdir1Children : ∀ c ∈ dir1.children.val, c = child ∨ c ∈ dir.children.val := by
            intro c hc
            rw [hsetSpec.2.2.1] at hc
            obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hc
            by_cases hjs : j = slot.val
            · rw [hjs, List.getElem?_set_self (by simp; omega)] at hj
              exact Or.inl (Option.some.inj hj).symm
            · rw [List.getElem?_set_ne (Ne.symm hjs)] at hj
              exact Or.inr (List.mem_iff_getElem?.mpr ⟨j, hj⟩)
          have hdir1Live : ∀ c ∈ dir1.children.val, c ≠ 0#u32 → SingleLinkLive dirs.val rows c := by
            intro c hc hnz
            rcases hdir1Children c hc with rfl | old
            · exact hchildLive hnz
            · exact st.childrenLive dir hdirMem c old hnz
          have hdir1NotQ : ∀ l ∈ entries, dir1.children.val.count l = 0 := by
            intro l hl
            rw [List.count_eq_zero]
            intro hmem
            rcases hdir1Children l hmem with rfl | old
            · exact hchildNotQ l hl rfl
            · have hmemE : l ∈ arenaEdges dirs.val := List.mem_flatMap.mpr ⟨dir, hdirMem, old⟩
              have hpos := List.count_pos_iff.mpr (List.mem_append_right pins hmemE)
              have hz := (hqZero l hl).2
              rw [radixReferences_eq] at hz
              omega
          cases hpow : core.num.U32.is_power_of_two dir1.mask using Result.cases with
          | div => rw [hpow] at hspec; simp at hspec
          | vis _ _ => rw [hpow] at hspec; simp at hspec
          | ret b =>
              change core.num.U32.is_power_of_two dir1.mask = Result.ok b at hpow
              simp only [hpow, bind_ok] at hcopy hspec ⊢
              cases b with
              | true =>
                  simp only [ite_true] at hcopy hspec ⊢
                  obtain ⟨fc, hfcRun, hfcSpec⟩ := wp_spec_exists (radix_first_child_matches dir1)
                  rw [hfcRun, bind_ok] at hcopy ⊢
                  rw [Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq] at hcopy
                  obtain ⟨rfl, rfl, rfl⟩ := hcopy
                  rw [WP.spec_ok]
                  refine ⟨rfl, rfl, rfl, st, ?_, ?_, hqZero, Nat.le_succ _, fun _ h => h⟩
                  · intro hnz
                    exact hdir1Live fc (radix_first_mem dir1 (hfcSpec.symm ▸ hnz) |> fun h => hfcSpec ▸ h) hnz
                  · intro l hl heq
                    subst heq
                    by_cases hnz : l = 0#u32
                    · have hliv := (hqZero l hl).1
                      subst hnz
                      unfold SingleLinkLive at hliv
                      have hlt : (0#u32 : U32) < 2147483648#u32 := by decide
                      simp only [hlt, ite_true] at hliv
                      exact Nat.lt_irrefl 0 hliv.1
                    · have hmem : l ∈ dir1.children.val := hfcSpec ▸ radix_first_mem dir1 (hfcSpec.symm ▸ hnz)
                      have hcnt := hdir1NotQ l hl
                      exact (List.count_eq_zero.mp hcnt hmem).elim
              | false =>
                  simp only [Bool.false_eq_true, ite_false] at hcopy hspec ⊢
                  apply WP.spec_mono
                    (add_directory_counted_lockstep dirs rows dirRefs rowRefs freeDirs dir1 pins
                      resChild dirs' freeDirs' hcopy st hdir1Live hrefRoom)
                  rintro ⟨c2, d2, dr2, rr2, f2⟩
                    ⟨rfl, rfl, rfl, st', hnodeLive, hnodeFresh, hnodeNz, hlenLe, hkeepLive, hzeroPres⟩
                  refine ⟨rfl, rfl, rfl, st', fun _ => hnodeLive, ?_, ?_, hlenLe, hkeepLive⟩
                  · intro l hl heq
                    subst heq
                    exact hnodeFresh (hqZero l hl).1
                  · intro l hl
                    obtain ⟨hliv, hz⟩ := hqZero l hl
                    exact ⟨hkeepLive l hliv, hzeroPres l hz (hdir1NotQ l hl)⟩

private theorem rebuild_path_counted_lockstep {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows : List (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (freeDirs : alloc.vec.Vec Usize)
    (path : Slice (U32 × Usize)) (child : U32) (pins entries : List U32)
    (resRoot : U32) (dirs' : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (freeDirs' : alloc.vec.Vec Usize)
    (hreb
      : Spike.radix.rebuild_path dirs freeDirs path child
        = Result.ok (resRoot, dirs', freeDirs'))
    (st : DirCountState dirs rows dirRefs rowRefs freeDirs pins)
    (hchildLive : child ≠ 0#u32 → SingleLinkLive dirs.val rows child)
    (hchildNotQ : ∀ l ∈ entries, l ≠ child)
    (hqZero
      : ∀ l ∈ entries,
          SingleLinkLive dirs.val rows l ∧ radixReferences dirs.val pins l = 0)
    (hrefRoom : pins.length + 17 * (dirs'.val.length + 1) ≤ U32.max)
    : WP.spec (Spike.radix.rebuild_path_counted dirs dirRefs rowRefs freeDirs path child)
        (fun (r2, d2, dr2, rr2, f2) =>
          r2 = resRoot
          ∧ d2 = dirs'
          ∧ f2 = freeDirs'
          ∧ DirCountState dirs' rows dr2 rr2 freeDirs' pins
          ∧ (resRoot ≠ 0#u32 → SingleLinkLive dirs'.val rows resRoot)
          ∧ (∀ l ∈ entries, l ≠ resRoot)
          ∧ (∀ l ∈ entries,
              SingleLinkLive dirs'.val rows l ∧ radixReferences dirs'.val pins l = 0)
          ∧ (∀ l, SingleLinkLive dirs.val rows l → SingleLinkLive dirs'.val rows l)) := by
  unfold Spike.radix.rebuild_path at hreb
  have hrebLoop := hreb
  unfold Spike.radix.rebuild_path_loop at hreb
  unfold Spike.radix.rebuild_path_counted Spike.radix.rebuild_path_counted_loop
  let rel :
      (alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec Usize × U32 × Usize) →
      (alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec U32 × alloc.vec.Vec U32 ×
        alloc.vec.Vec Usize × U32 × Usize) → Prop :=
    fun (d1, f1, c1, e1) (d2, dr2, rr2, f2, c2, e2) =>
      d2 = d1 ∧ f2 = f1 ∧ c2 = c1 ∧ e2 = e1
      ∧ DirCountState d1 rows dr2 rr2 f1 pins
      ∧ (c1 ≠ 0#u32 → SingleLinkLive d1.val rows c1)
      ∧ (∀ l ∈ entries, l ≠ c1)
      ∧ (∀ l ∈ entries, SingleLinkLive d1.val rows l ∧ radixReferences d1.val pins l = 0)
      ∧ Spike.radix.rebuild_path_loop d1 f1 path c1 e1 = Result.ok (resRoot, dirs', freeDirs')
      ∧ (∀ l, SingleLinkLive dirs.val rows l → SingleLinkLive d1.val rows l)
  let post :
      (U32 × alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec Usize) →
      (U32 × alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec U32 ×
        alloc.vec.Vec U32 × alloc.vec.Vec Usize) → Prop :=
    fun (r1, d1, f1) (r2, d2, dr2, rr2, f2) =>
      r2 = r1 ∧ d2 = d1 ∧ f2 = f1
      ∧ DirCountState d1 rows dr2 rr2 f1 pins
      ∧ (r1 ≠ 0#u32 → SingleLinkLive d1.val rows r1)
      ∧ (∀ l ∈ entries, l ≠ r1)
      ∧ (∀ l ∈ entries, SingleLinkLive d1.val rows l ∧ radixReferences d1.val pins l = 0)
      ∧ (∀ l, SingleLinkLive dirs.val rows l → SingleLinkLive d1.val rows l)
  apply loop_lockstep
    (fun (d1, f1, c1, e1) => Spike.radix.rebuild_path_loop.body path d1 f1 c1 e1)
    (fun (d2, dr2, rr2, f2, c2, e2) =>
      Spike.radix.rebuild_path_counted_loop.body path d2 dr2 rr2 f2 c2 e2)
    rel post ?_ ?_ hreb
  · rintro ⟨d1, f1, c1, e1⟩ ⟨d2, dr2, rr2, f2, c2, e2⟩
      ⟨rfl, rfl, rfl, rfl, st1, hc1Live, hc1NotQ, hq1, hrem1, hkeep1⟩ r1 hb1
    dsimp only at hb1 ⊢
    have hlenCur : d2.val.length ≤ dirs'.val.length :=
      rebuild_path_loop_len_mono path d2 f2 c2 e2 (resRoot, dirs', freeDirs') hrem1
    have hspec1 : WP.spec (Spike.radix.rebuild_path_loop.body path d2 f2 c2 e2) (· = r1) := by
      rw [hb1, WP.spec_ok]
    have hremStep : (match r1 with
      | .done z => Result.ok z
      | .cont next => Spike.radix.rebuild_path_loop next.1 next.2.1 path next.2.2.1 next.2.2.2) =
        Result.ok (resRoot, dirs', freeDirs') := by
      unfold Spike.radix.rebuild_path_loop at hrem1 ⊢
      rw [loop.eq_1] at hrem1
      dsimp only at hrem1
      rw [hb1, bind_ok] at hrem1
      cases r1 <;> exact hrem1
    unfold Spike.radix.rebuild_path_loop.body at hb1 hspec1
    unfold Spike.radix.rebuild_path_counted_loop.body
    by_cases hpos : e2 > 0#usize
    · rw [ite_eq_left hpos] at hb1 hspec1 ⊢
      have hposVal : 0 < e2.val := hpos
      have hone : (1#usize : Usize).val = 1 := rfl
      obtain ⟨end1, hendRun, hendVal⟩ := wp_spec_exists (Usize.sub_spec (x := e2) (y := 1#usize) (by omega))
      rw [hendRun, bind_ok] at hb1 hspec1 ⊢
      cases hpRun : Slice.index_usize path end1 using Result.cases with
      | div => rw [hpRun] at hspec1; simp at hspec1
      | vis _ _ => rw [hpRun] at hspec1; simp at hspec1
      | ret p =>
          obtain ⟨parent, slot⟩ := p
          change Slice.index_usize path end1 = Result.ok (parent, slot) at hpRun
          rw [hpRun] at hb1 hspec1
          simp only [bind_ok] at hb1 hspec1 ⊢
          change (do
            let (child1, dirs1, free1) ← Spike.radix.copy_parent d2 f2 parent slot c2
            Result.ok (ControlFlow.cont (dirs1, free1, child1, end1))) = Result.ok r1 at hb1
          change WP.spec (do
            let (child1, dirs1, free1) ← Spike.radix.copy_parent d2 f2 parent slot c2
            Result.ok (ControlFlow.cont (dirs1, free1, child1, end1))) (· = r1) at hspec1
          change WP.spec (do
            let (child1, dirs1, dir_refs1, row_refs1, free1) ←
              Spike.radix.copy_parent_counted d2 dr2 rr2 f2 parent slot c2
            Result.ok (ControlFlow.cont (dirs1, dir_refs1, row_refs1, free1, child1, end1))) _
          cases hcpRun : Spike.radix.copy_parent d2 f2 parent slot c2
            using Result.cases with
          | div => rw [hcpRun] at hspec1; simp at hspec1
          | vis _ _ => rw [hcpRun] at hspec1; simp at hspec1
          | ret cpRes =>
              obtain ⟨cNext, dNext, fNext⟩ := cpRes
              change Spike.radix.copy_parent d2 f2 parent slot c2 = Result.ok (cNext, dNext, fNext) at hcpRun
              rw [hcpRun, bind_ok] at hb1
              change Result.ok (ControlFlow.cont (dNext, fNext, cNext, end1)) = Result.ok r1 at hb1
              rw [Result.ok.injEq] at hb1
              subst hb1
              apply WP.spec_bind
                (copy_parent_counted_lockstep d2 rows dr2 rr2 f2 parent slot c2 pins
                  entries cNext dNext fNext hcpRun st1 hc1Live hc1NotQ hq1 (by omega))
              rintro ⟨c2', d2', dr2', rr2', f2'⟩
                ⟨hcEq, hdEq, hfEq, st2, hc2Live, hc2NotQ, hq2, _, hkeep2⟩
              subst hcEq hdEq hfEq
              change WP.spec (Result.ok (ControlFlow.cont (d2', dr2', rr2', f2', c2', end1))) _
              rw [WP.spec_ok]
              exact ⟨rfl, rfl, rfl, rfl, st2, hc2Live, hc2NotQ, hq2, hremStep,
                fun l hl => hkeep2 l (hkeep1 l hl)⟩
    · rw [ite_eq_right hpos] at hb1 ⊢
      rw [Result.ok.injEq] at hb1
      subst hb1
      rw [WP.spec_ok]
      exact ⟨rfl, rfl, rfl, st1, hc1Live, hc1NotQ, hq1, hkeep1⟩
  · exact ⟨rfl, rfl, rfl, rfl, st, hchildLive, hchildNotQ, hqZero, hrebLoop, fun _ h => h⟩

private theorem directory_ok_mem (dirs : Slice (Option Spike.radix.RadixDir)) (node : U32)
    (dir : Spike.radix.RadixDir)
    (h : Spike.radix.directory dirs node = Result.ok dir)
    : dir ∈ dirs.val.filterMap id := by
  have hds : WP.spec (Spike.radix.directory dirs node) (· = dir) := by rw [h, WP.spec_ok]
  unfold Spike.radix.directory at hds
  cases hsub : node - 1#u32 using Result.cases with
  | div => rw [hsub] at hds; simp at hds
  | vis _ _ => rw [hsub] at hds; simp at hds
  | ret sub =>
      change node - 1#u32 = Result.ok sub at hsub
      simp only [hsub, lift, bind_ok] at hds
      cases hidx : Slice.index_usize dirs (UScalar.cast .Usize sub)
        using Result.cases with
      | div => rw [hidx] at hds; simp at hds
      | vis _ _ => rw [hidx] at hds; simp at hds
      | ret opt =>
          change Slice.index_usize dirs (UScalar.cast .Usize sub) = Result.ok opt at hidx
          simp only [hidx, bind_ok] at hds
          cases opt with
          | none => simp at hds
          | some d0 =>
              simp only [WP.spec_ok] at hds; subst d0
              have hget : dirs.val[(UScalar.cast .Usize sub).val]? = some (some dir) := by
                unfold Slice.index_usize at hidx
                rw [Slice.getElem?_Usize_eq] at hidx
                cases hge : dirs.val[(UScalar.cast .Usize sub).val]? with
                | none => rw [hge] at hidx; exact absurd hidx (by simp [Result.fail])
                | some v => rw [hge, Result.ok.injEq] at hidx; rw [hidx]
              exact List.mem_filterMap.mpr
                ⟨some dir, List.mem_iff_getElem?.mpr ⟨_, hget⟩, rfl⟩

private theorem array_index_usize_mem {α : Type} {n : Usize} (a : Array α n) (i : Usize)
    (x : α) (h : Array.index_usize a i = Result.ok x)
    : x ∈ a.val := by
  unfold Array.index_usize at h
  rw [Array.getElem?_Usize_eq] at h
  cases hge : a.val[i.val]? with
  | none => rw [hge] at h; exact absurd h (by simp [Result.fail])
  | some v =>
      rw [hge, Result.ok.injEq] at h
      subst h
      exact List.mem_iff_getElem?.mpr ⟨i.val, hge⟩

private theorem record_path_tip_mem (dirs : Slice (Option Spike.radix.RadixDir))
    (path : alloc.vec.Vec (U32 × Usize)) (root : U32) (key : Slice U8)
    (stop : Option Usize) (tip : U32) (path' : alloc.vec.Vec (U32 × Usize))
    (h : Spike.radix.record_path dirs path root key stop = Result.ok (tip, path'))
    : tip = 0#u32 ∨ tip = root ∨ tip ∈ arenaEdges dirs.val := by
  unfold Spike.radix.record_path at h
  have hs0 : WP.spec (do
      let path1 ← alloc.vec.Vec.resize (BuiltinClone (U32 × Usize)) path 0#usize (0#u32, 0#usize)
      Spike.radix.record_path_loop dirs path1 key stop root) (· = (tip, path')) := by
    rw [h, WP.spec_ok]
  cases hres
        : alloc.vec.Vec.resize (BuiltinClone (U32 × Usize)) path 0#usize (0#u32, 0#usize)
    using Result.cases with
  | div => rw [hres] at hs0; simp at hs0
  | vis _ _ => rw [hres] at hs0; simp at hs0
  | ret p0 =>
      change alloc.vec.Vec.resize _ path 0#usize (0#u32, 0#usize) = Result.ok p0 at hres
      rw [hres, bind_ok] at h
      unfold Spike.radix.record_path_loop at h
      refine loop_invariant_of_ok
        (fun (p1, s1, n1) => Spike.radix.record_path_loop.body dirs key p1 s1 n1)
        (fun a z => z.1 = 0#u32 ∨ z.1 = a.2.2 ∨ z.1 ∈ arenaEdges dirs.val)
        ?_ h
      rintro ⟨p1, s1, n1⟩ r hb
      dsimp only at hb
      have hs : WP.spec (Spike.radix.record_path_loop.body dirs key p1 s1 n1) (· = r) := by
        rw [hb, WP.spec_ok]
      unfold Spike.radix.record_path_loop.body at hb hs
      by_cases hnz : n1 != 0#u32
      · rw [ite_eq_left hnz] at hb hs
        by_cases hlt : n1 < Spike.radix.RADIX_LEAF_TAG
        · rw [ite_eq_left hlt] at hb hs
          cases hd : Spike.radix.directory dirs n1 using Result.cases with
          | div => rw [hd] at hs; simp at hs
          | vis _ _ => rw [hd] at hs; simp at hs
          | ret dir =>
              change Spike.radix.directory dirs n1 = Result.ok dir at hd
              have hdirMem := directory_ok_mem dirs n1 dir hd
              rw [hd, bind_ok] at hb hs
              cases s1 with
              | none =>
                  simp only at hb hs
                  cases hsym : Spike.radix.symbol key dir.digit using Result.cases with
                  | div => rw [hsym] at hs; simp at hs
                  | vis _ _ => rw [hsym] at hs; simp at hs
                  | ret slot =>
                      change Spike.radix.symbol key dir.digit = Result.ok slot at hsym
                      rw [hsym, bind_ok] at hb hs
                      cases hp : alloc.vec.Vec.push p1 (n1, slot) using Result.cases with
                      | div => rw [hp] at hs; simp at hs
                      | vis _ _ => rw [hp] at hs; simp at hs
                      | ret p2 =>
                          change alloc.vec.Vec.push p1 (n1, slot) = Result.ok p2 at hp
                          rw [hp, bind_ok] at hb hs
                          cases hc : Array.index_usize dir.children slot
                            using Result.cases with
                          | div => rw [hc] at hs; simp at hs
                          | vis _ _ => rw [hc] at hs; simp at hs
                          | ret n2 =>
                              change Array.index_usize dir.children slot = Result.ok n2 at hc
                              have hn2Edge : n2 ∈ arenaEdges dirs.val :=
                                List.mem_flatMap.mpr ⟨dir, hdirMem, array_index_usize_mem dir.children slot n2 hc⟩
                              rw [hc, bind_ok, Result.ok.injEq] at hb
                              subst hb
                              rintro z (hz0 | rfl | hzE)
                              · exact Or.inl hz0
                              · exact Or.inr (Or.inr hn2Edge)
                              · exact Or.inr (Or.inr hzE)
              | some digit =>
                  simp only at hb hs
                  by_cases hge : dir.digit >= digit
                  · rw [ite_eq_left hge, Result.ok.injEq] at hb
                    subst hb
                    exact Or.inr (Or.inl rfl)
                  · rw [ite_eq_right hge] at hb hs
                    cases hsym : Spike.radix.symbol key dir.digit using Result.cases with
                    | div => rw [hsym] at hs; simp at hs
                    | vis _ _ => rw [hsym] at hs; simp at hs
                    | ret slot =>
                        change Spike.radix.symbol key dir.digit = Result.ok slot at hsym
                        rw [hsym, bind_ok] at hb hs
                        cases hp : alloc.vec.Vec.push p1 (n1, slot)
                          using Result.cases with
                        | div => rw [hp] at hs; simp at hs
                        | vis _ _ => rw [hp] at hs; simp at hs
                        | ret p2 =>
                            change alloc.vec.Vec.push p1 (n1, slot) = Result.ok p2 at hp
                            rw [hp, bind_ok] at hb hs
                            cases hc : Array.index_usize dir.children slot
                              using Result.cases with
                            | div => rw [hc] at hs; simp at hs
                            | vis _ _ => rw [hc] at hs; simp at hs
                            | ret n2 =>
                                change Array.index_usize dir.children slot = Result.ok n2 at hc
                                have hn2Edge : n2 ∈ arenaEdges dirs.val :=
                                  List.mem_flatMap.mpr ⟨dir, hdirMem, array_index_usize_mem dir.children slot n2 hc⟩
                                rw [hc, bind_ok, Result.ok.injEq] at hb
                                subst hb
                                rintro z (hz0 | rfl | hzE)
                                · exact Or.inl hz0
                                · exact Or.inr (Or.inr hn2Edge)
                                · exact Or.inr (Or.inr hzE)
        · rw [ite_eq_right hlt, Result.ok.injEq] at hb
          subst hb
          exact Or.inr (Or.inl rfl)
      · rw [ite_eq_right hnz, Result.ok.injEq] at hb
        subst hb
        exact Or.inr (Or.inl rfl)

private theorem prepare_insert_stem_mem {V : Type}
    (dirs : Slice (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V))) (path : alloc.vec.Vec (U32 × Usize))
    (root : U32) (key : Slice U8) (stem : U32) (split : Option Spike.radix.InsertionSplit)
    (path' : alloc.vec.Vec (U32 × Usize))
    (h
      : Spike.radix.prepare_insert dirs rows path root key
        = Result.ok ((stem, split), path'))
    : stem = 0#u32 ∨ stem = root ∨ stem ∈ arenaEdges dirs.val := by
  have hs : WP.spec (Spike.radix.prepare_insert dirs rows path root key) (· = ((stem, split), path')) := by
    rw [h, WP.spec_ok]
  unfold Spike.radix.prepare_insert at hs
  cases hrep : Spike.radix.representative dirs root key using Result.cases with
  | div => rw [hrep] at hs; simp at hs
  | vis _ _ => rw [hrep] at hs; simp at hs
  | ret rep =>
      change Spike.radix.representative dirs root key = Result.ok rep at hrep
      rw [hrep, bind_ok] at hs
      cases hrow : Spike.radix.row_at rows rep using Result.cases with
      | div => rw [hrow] at hs; simp at hs
      | vis _ _ => rw [hrow] at hs; simp at hs
      | ret prev =>
          change Spike.radix.row_at rows rep = Result.ok prev at hrow
          rw [hrow, bind_ok] at hs
          dsimp only at hs
          cases hdiff : Spike.radix.first_difference (alloc.vec.Vec.deref prev.key) key
            using Result.cases with
          | div => rw [hdiff] at hs; simp at hs
          | vis _ _ => rw [hdiff] at hs; simp at hs
          | ret diff =>
              change Spike.radix.first_difference _ key = Result.ok diff at hdiff
              rw [hdiff, bind_ok] at hs
              cases hrec : Spike.radix.record_path dirs path root key diff
                using Result.cases with
              | div => rw [hrec] at hs; simp at hs
              | vis _ _ => rw [hrec] at hs; simp at hs
              | ret recRes =>
                  obtain ⟨s0, p0⟩ := recRes
                  change Spike.radix.record_path dirs path root key diff = Result.ok (s0, p0) at hrec
                  have hmem := record_path_tip_mem dirs path root key diff s0 p0 hrec
                  rw [hrec, bind_ok] at hs
                  cases diff with
                  | none =>
                      change WP.spec (Result.ok ((s0, none), p0)) (· = ((stem, split), path')) at hs
                      rw [WP.spec_ok] at hs
                      obtain ⟨hs1, _⟩ := Prod.mk.inj hs
                      obtain ⟨hseq, _⟩ := Prod.mk.inj hs1
                      rwa [← hseq]
                  | some digit =>
                      change WP.spec (do
                        let i1 ← Spike.radix.symbol (alloc.vec.Vec.deref prev.key) digit
                        let i2 ← Spike.radix.symbol key digit
                        Result.ok ((s0, some ({ digit, old_slot := i1, new_slot := i2 } : Spike.radix.InsertionSplit)), p0))
                        (· = ((stem, split), path')) at hs
                      cases h1 : Spike.radix.symbol (alloc.vec.Vec.deref prev.key) digit
                        using Result.cases with
                      | div => rw [h1] at hs; simp at hs
                      | vis _ _ => rw [h1] at hs; simp at hs
                      | ret i1 =>
                          change Spike.radix.symbol _ digit = Result.ok i1 at h1
                          rw [h1, bind_ok] at hs
                          cases h2 : Spike.radix.symbol key digit using Result.cases with
                          | div => rw [h2] at hs; simp at hs
                          | vis _ _ => rw [h2] at hs; simp at hs
                          | ret i2 =>
                              change Spike.radix.symbol _ digit = Result.ok i2 at h2
                              rw [h2, bind_ok, WP.spec_ok] at hs
                              obtain ⟨hs1, _⟩ := Prod.mk.inj hs
                              obtain ⟨hseq, _⟩ := Prod.mk.inj hs1
                              rwa [← hseq]

private theorem set_child_children_mem (dir : Spike.radix.RadixDir) (slot : Usize)
    (child : U32) (dir1 : Spike.radix.RadixDir)
    (h : Spike.radix.RadixDir.set_child dir slot child = Result.ok dir1)
    : ∀ c ∈ dir1.children.val, c = child ∨ c ∈ dir.children.val := by
  have hslotLt : slot.val < 17 := by
    by_contra hge
    have hs : WP.spec (Spike.radix.RadixDir.set_child dir slot child) (· = dir1) := by
      rw [h, WP.spec_ok]
    unfold Spike.radix.RadixDir.set_child at hs
    have hnone : dir.children.val[slot.val]? = none := List.getElem?_eq_none (by simp; omega)
    simp [Array.index_mut_usize, Array.index_usize, Array.getElem?_Usize_eq, hnone] at hs
  have hspec := radix_set_child_matches dir slot child hslotLt
  rw [h, WP.spec_ok] at hspec
  intro c hc
  rw [hspec.2.2.1] at hc
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hc
  by_cases hjs : j = slot.val
  · rw [hjs, List.getElem?_set_self (by simp; omega)] at hj
    exact Or.inl (Option.some.inj hj).symm
  · rw [List.getElem?_set_ne (Ne.symm hjs)] at hj
    exact Or.inr (List.mem_iff_getElem?.mpr ⟨j, hj⟩)

private theorem split_directory_children_mem (dirs : Slice (Option Spike.radix.RadixDir))
    (stem : U32) (split : Spike.radix.InsertionSplit) (dir : Spike.radix.RadixDir)
    (h : Spike.radix.split_directory dirs stem split = Result.ok dir)
    : ∀ c ∈ dir.children.val, c = 0#u32 ∨ c = stem ∨ c ∈ arenaEdges dirs.val := by
  have hs : WP.spec (Spike.radix.split_directory dirs stem split) (· = dir) := by
    rw [h, WP.spec_ok]
  unfold Spike.radix.split_directory at hs
  have hempty : ∀ (d0 : Spike.radix.RadixDir),
      Spike.radix.RadixDir.empty split.digit = Result.ok d0 →
      ∀ c ∈ d0.children.val, c = 0#u32 := by
    intro d0 he0 c hc
    unfold Spike.radix.RadixDir.empty at he0
    rw [Result.ok.injEq] at he0
    subst he0
    simp only [Array.repeat_val, List.mem_replicate] at hc
    exact hc.2
  by_cases hlt : stem < Spike.radix.RADIX_LEAF_TAG
  · rw [ite_eq_left hlt] at hs
    cases hd : Spike.radix.directory dirs stem using Result.cases with
    | div => rw [hd] at hs; simp at hs
    | vis _ _ => rw [hd] at hs; simp at hs
    | ret existing =>
        change Spike.radix.directory dirs stem = Result.ok existing at hd
        have hexMem := directory_ok_mem dirs stem existing hd
        rw [hd, bind_ok] at hs
        by_cases hdig : existing.digit = split.digit
        · rw [ite_eq_left hdig, WP.spec_ok] at hs
          subst hs
          intro c hc
          exact Or.inr (Or.inr (List.mem_flatMap.mpr ⟨existing, hexMem, hc⟩))
        · rw [ite_eq_right hdig] at hs
          cases he0 : Spike.radix.RadixDir.empty split.digit using Result.cases with
          | div => rw [he0] at hs; simp at hs
          | vis _ _ => rw [he0] at hs; simp at hs
          | ret d0 =>
              change Spike.radix.RadixDir.empty split.digit = Result.ok d0 at he0
              rw [he0, bind_ok] at hs
              cases hset : Spike.radix.RadixDir.set_child d0 split.old_slot stem
                using Result.cases with
              | div => rw [hset] at hs; simp at hs
              | vis _ _ => rw [hset] at hs; simp at hs
              | ret d1 =>
                  change Spike.radix.RadixDir.set_child d0 split.old_slot stem = Result.ok d1 at hset
                  rw [hset, WP.spec_ok] at hs
                  subst hs
                  intro c hc
                  rcases set_child_children_mem d0 split.old_slot stem d1 hset c hc with rfl | hc0
                  · exact Or.inr (Or.inl rfl)
                  · exact Or.inl (hempty d0 he0 c hc0)
  · rw [ite_eq_right hlt] at hs
    cases he0 : Spike.radix.RadixDir.empty split.digit using Result.cases with
    | div => rw [he0] at hs; simp at hs
    | vis _ _ => rw [he0] at hs; simp at hs
    | ret d0 =>
        change Spike.radix.RadixDir.empty split.digit = Result.ok d0 at he0
        rw [he0, bind_ok] at hs
        cases hset : Spike.radix.RadixDir.set_child d0 split.old_slot stem
          using Result.cases with
        | div => rw [hset] at hs; simp at hs
        | vis _ _ => rw [hset] at hs; simp at hs
        | ret d1 =>
            change Spike.radix.RadixDir.set_child d0 split.old_slot stem = Result.ok d1 at hset
            rw [hset, WP.spec_ok] at hs
            subst hs
            intro c hc
            rcases set_child_children_mem d0 split.old_slot stem d1 hset c hc with rfl | hc0
            · exact Or.inr (Or.inl rfl)
            · exact Or.inl (hempty d0 he0 c hc0)

private theorem single_link_live_ne_zero {V : Type}
    {dirs : List (Option Spike.radix.RadixDir)}
    {rows : List (Option (Spike.radix.RadixRow V))} {l : U32}
    (h : SingleLinkLive dirs rows l)
    : l ≠ 0#u32 := by
  intro rfl
  simp [SingleLinkLive] at h

private theorem erase_pairwise {α β : Type} [DecidableEq α] {R : α × β → α × β → Prop}
    {xs : List (α × β)} (h : xs.Pairwise R) (k : α)
    : (Kv.Model.erase xs k).Pairwise R :=
  h.filter _

theorem single_preserves_pins_of_arena_keeps {V : Type}
    {before after : Spike.radix.SingleRadix V} {pins : List U32}
    (hkeeps : ArenaKeeps before.values after.values)
    : SinglePreservesPins before after pins :=
  fun root _ bindings hview =>
    single_retains_views before after hkeeps root bindings hview

private theorem single_liveness_retain_next {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (freeDirs freeRows : alloc.vec.Vec Usize)
    (path : alloc.vec.Vec (U32 × Usize))
    (retired : Spike.retire_queue.RetireQueue)
    (dirRefs rowRefs : alloc.vec.Vec U32) (pins entries : List U32) (next : U32)
    (hvalid : ArenaValid ⟨dirs, rows, freeDirs, freeRows, path⟩)
    (hrowsBound : rows.val.length ≤ 2147483647)
    (hfreeRowsNd : freeRows.val.Nodup)
    (st : DirCountState dirs rows.val dirRefs rowRefs freeDirs pins)
    (hqv : RetirementQueueView retired entries)
    (hqnd : entries.Nodup)
    (hqZero
      : ∀ l ∈ entries,
          SingleLinkLive dirs.val rows.val l ∧ radixReferences dirs.val pins l = 0)
    (hnextLive : next ≠ 0#u32 → SingleLinkLive dirs.val rows.val next)
    (hnextNotQ : ∀ l ∈ entries, l ≠ next)
    (hrefRoom : pins.length + 17 * dirs.val.length + 1 ≤ U32.max)
    : WP.spec (Spike.radix.retain_link dirRefs rowRefs next)
        (fun (dr', rr') =>
          SingleLiveness
            ⟨⟨dirs, rows, freeDirs, freeRows, path⟩, dr', rr', retired⟩
            (if next = 0#u32 then pins else next :: pins)) := by
  have hnextRoom : next ≠ 0#u32 → (pins ++ arenaEdges dirs.val).count next < U32.max := by
    intro _
    have := owners_count_le_bound dirs.val pins next
    omega
  apply WP.spec_mono
    (retain_link_refines dirs.val rows.val dirRefs rowRefs (pins ++ arenaEdges dirs.val)
      next st.counts hnextLive hnextRoom)
  rintro ⟨dr', rr'⟩ hcnt'
  by_cases hnz : next = 0#u32
  · simp only [hnz, ite_true] at hcnt' ⊢
    exact ⟨hvalid, st.dirsBound, hrowsBound, st.freeNd, hfreeRowsNd,
      st.pinsLive, st.childrenLive, hcnt', entries, hqv, hqnd, hqZero⟩
  · simp only [hnz, ite_false] at hcnt' ⊢
    refine ⟨hvalid, st.dirsBound, hrowsBound, st.freeNd, hfreeRowsNd, ?_, st.childrenLive,
      hcnt', entries, hqv, hqnd, ?_⟩
    · intro p hp
      rcases List.mem_cons.mp hp with rfl | old
      · exact hnextLive hnz
      · exact st.pinsLive p old
    · intro l hl
      obtain ⟨hliv, hz⟩ := hqZero l hl
      refine ⟨hliv, ?_⟩
      rw [radixReferences_eq] at hz ⊢
      have hne : next ≠ l := Ne.symm (hnextNotQ l hl)
      simpa [List.count_cons, beq_eq_false_iff_ne.mpr hne] using hz

theorem single_remove_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (root : Spike.radix.RadixRoot) (key : Slice U8)
    (bindings : List (List U8 × U32)) (pins : List U32)
    (view : SingleView arena root bindings)
    (live : SingleLiveness arena pins)
    (rootRef
      : root ≠ 0#u32
        → SingleLinkLive arena.values.dirs.val arena.values.rows.val root
          ∧ radixReferences arena.values.dirs.val pins root > 0)
    (dirRoom : arena.values.dirs.val.length + bindings.length ≤ 2147483647)
    (refRoom
      : pins.length + 17 * (arena.values.dirs.val.length + bindings.length + 1) + 1
        ≤ U32.max)
    : WP.spec (Spike.radix.SingleRadix.remove arena root key)
        (fun (next, after) =>
          SingleLiveness after (if next = 0#u32 then pins else next :: pins)
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaGrowth arena.values after.values bindings.length 0
          ∧ SingleView after next (Kv.Model.erase bindings key.val)
          ∧ singleBindings after (Kv.Model.erase bindings key.val)
            = Kv.Model.erase (singleBindings arena bindings) key.val) := by
  obtain ⟨height, tree⟩ := view.lookup
  have tree' := (radix_tree_binding_bound arena.values.dirs live.valid.directories tree).1
  obtain ⟨⟨next0, dirs', freeDirs', path'⟩, hremRun, hremPost⟩ := wp_spec_exists
    (radix_remove_refines arena.values.dirs arena.values.free_dirs
      (alloc.vec.Vec.deref arena.values.rows) arena.values.path root key bindings.length bindings
      tree' (by simpa [alloc.vec.Vec.deref] using view.values) live.valid.dirs live.valid.directories
      (by
        simpa [alloc.vec.Vec.deref] using
          radix_compressed_of_knowledge arena.values.dirs _ live.valid.knowledge)
      dirRoom)
  obtain ⟨hkeptDirs, hfreeDirs', hdirInv', hknowFn, hdirsGrowth, h', htree', hrows', hbind'⟩ := hremPost
  have hknow' : RadixKnowledge dirs' (radixKeyOf arena.values.rows.val) := by
    simpa [alloc.vec.Vec.deref]
      using hknowFn (by simpa [alloc.vec.Vec.deref] using live.valid.knowledge)
  have hvalidAfter : ArenaValid ⟨dirs', arena.values.rows, freeDirs', arena.values.free_rows, path'⟩ :=
    ⟨hfreeDirs', live.valid.rows, hdirInv', hknow'⟩
  have hkeepsAfter : ArenaKeeps arena.values ⟨dirs', arena.values.rows, freeDirs', arena.values.free_rows, path'⟩ :=
    ⟨hkeptDirs, fun _ _ h => h⟩
  have hgrowthAfter : ArenaGrowth arena.values
      ⟨dirs', arena.values.rows, freeDirs', arena.values.free_rows, path'⟩ bindings.length 0 :=
    ⟨hdirsGrowth, by simp⟩
  have hsortedAfter : (Kv.Model.erase bindings key.val).Pairwise radixKeyLt :=
    erase_pairwise view.sorted key.val
  obtain ⟨entries, hqv, hqnd, hqZero⟩ := live.queue
  have st0 : DirCountState arena.values.dirs arena.values.rows.val arena.dir_refs arena.row_refs
      arena.values.free_dirs pins :=
    ⟨live.valid.dirs, live.freeDirsNodup, live.dirsBound, live.pinsLive, live.childrenLive, live.counts⟩
  have hrootNotQ : ∀ l ∈ entries, l ≠ root := by
    intro l hl heq
    subst heq
    by_cases h0 : l = 0#u32
    · exact single_link_live_ne_zero (hqZero l hl).1 h0
    · have := (rootRef h0).2
      have := (hqZero l hl).2
      omega
  have hremSpec : WP.spec
      (Spike.radix.remove arena.values.dirs arena.values.free_dirs
        (alloc.vec.Vec.deref arena.values.rows) arena.values.path root key)
      (· = (next0, dirs', freeDirs', path')) := by rw [hremRun, WP.spec_ok]
  unfold Spike.radix.remove at hremRun hremSpec
  unfold Spike.radix.SingleRadix.remove
  dsimp only at hremRun hremSpec ⊢
  cases hrec
        : Spike.radix.record_path (alloc.vec.Vec.deref arena.values.dirs)
            arena.values.path root key none
    using Result.cases with
  | div => rw [hrec] at hremSpec; simp at hremSpec
  | vis _ _ => rw [hrec] at hremSpec; simp at hremSpec
  | ret recRes =>
      obtain ⟨leaf, path1⟩ := recRes
      change Spike.radix.record_path _ arena.values.path root key none = Result.ok (leaf, path1) at hrec
      rw [hrec, bind_ok] at hremRun hremSpec
      simp only [bind_ok]
      change (if leaf = 0#u32 then Result.ok (root, arena.values.dirs, arena.values.free_dirs, path1)
        else do
          let v ← Spike.radix.check_leaf (alloc.vec.Vec.deref arena.values.rows) leaf key
          if core.option.Option.is_none v then
            Result.ok (root, arena.values.dirs, arena.values.free_dirs, path1)
          else do
            let (n, d, f) ← Spike.radix.rebuild_path arena.values.dirs arena.values.free_dirs
              (alloc.vec.Vec.deref path1) 0#u32
            Result.ok (n, d, f, path1)) = Result.ok (next0, dirs', freeDirs', path') at hremRun
      change WP.spec (if leaf = 0#u32 then Result.ok (root, arena.values.dirs, arena.values.free_dirs, path1)
        else do
          let v ← Spike.radix.check_leaf (alloc.vec.Vec.deref arena.values.rows) leaf key
          if core.option.Option.is_none v then
            Result.ok (root, arena.values.dirs, arena.values.free_dirs, path1)
          else do
            let (n, d, f) ← Spike.radix.rebuild_path arena.values.dirs arena.values.free_dirs
              (alloc.vec.Vec.deref path1) 0#u32
            Result.ok (n, d, f, path1)) (· = (next0, dirs', freeDirs', path')) at hremSpec
      let av := arena.values
      change WP.spec (if leaf = 0#u32 then do
          let (v1, v2) ← Spike.radix.retain_link arena.dir_refs arena.row_refs root
          Result.ok (root, { arena with values := { av with path := path1 }, dir_refs := v1, row_refs := v2 })
        else do
          let o ← Spike.radix.check_leaf (alloc.vec.Vec.deref arena.values.rows) leaf key
          if core.option.Option.is_none o then do
            let (v1, v2) ← Spike.radix.retain_link arena.dir_refs arena.row_refs root
            Result.ok (root, { arena with values := { av with path := path1 }, dir_refs := v1, row_refs := v2 })
          else do
            let (next, v1, v2, v3, v4) ← Spike.radix.rebuild_path_counted arena.values.dirs
              arena.dir_refs arena.row_refs arena.values.free_dirs (alloc.vec.Vec.deref path1) 0#u32
            let (v5, v6) ← Spike.radix.retain_link v2 v3 next
            Result.ok (next, { arena with values := { av with dirs := v1, free_dirs := v4, path := path1 }, dir_refs := v5, row_refs := v6 })) _
      by_cases hlz : leaf = 0#u32
      · rw [ite_eq_left hlz] at hremRun ⊢
        rw [Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq, Prod.mk.injEq] at hremRun
        obtain ⟨rfl, rfl, rfl, rfl⟩ := hremRun
        apply WP.spec_bind
          (single_liveness_retain_next arena.values.dirs arena.values.rows arena.values.free_dirs
            arena.values.free_rows path1 arena.retired arena.dir_refs arena.row_refs pins entries root
            hvalidAfter live.rowsBound live.freeRowsNodup st0 hqv hqnd hqZero
            (fun h => (rootRef h).1) hrootNotQ (by omega))
        rintro ⟨dr', rr'⟩ hlive'
        change WP.spec (Result.ok _) _
        rw [WP.spec_ok]
        exact ⟨hlive', hkeepsAfter, hgrowthAfter,
          ⟨⟨h', htree'⟩, by simpa [alloc.vec.Vec.deref] using hrows', hsortedAfter⟩,
          by simpa [singleBindings, alloc.vec.Vec.deref] using hbind'⟩
      · rw [ite_eq_right hlz] at hremRun hremSpec ⊢
        cases hchk
              : Spike.radix.check_leaf (alloc.vec.Vec.deref arena.values.rows) leaf key
          using Result.cases with
        | div => rw [hchk] at hremSpec; simp at hremSpec
        | vis _ _ => rw [hchk] at hremSpec; simp at hremSpec
        | ret opt =>
            change Spike.radix.check_leaf _ leaf key = Result.ok opt at hchk
            rw [hchk, bind_ok] at hremRun hremSpec
            simp only [bind_ok]
            by_cases hnone : core.option.Option.is_none opt = true
            · rw [ite_eq_left hnone] at hremRun ⊢
              rw [Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq, Prod.mk.injEq] at hremRun
              obtain ⟨rfl, rfl, rfl, rfl⟩ := hremRun
              apply WP.spec_bind
                (single_liveness_retain_next arena.values.dirs arena.values.rows arena.values.free_dirs
                  arena.values.free_rows path1 arena.retired arena.dir_refs arena.row_refs pins entries root
                  hvalidAfter live.rowsBound live.freeRowsNodup st0 hqv hqnd hqZero
                  (fun h => (rootRef h).1) hrootNotQ (by omega))
              rintro ⟨dr', rr'⟩ hlive'
              change WP.spec (Result.ok _) _
              rw [WP.spec_ok]
              exact ⟨hlive', hkeepsAfter, hgrowthAfter,
                ⟨⟨h', htree'⟩, by simpa [alloc.vec.Vec.deref] using hrows', hsortedAfter⟩,
                by simpa [singleBindings, alloc.vec.Vec.deref] using hbind'⟩
            · rw [ite_eq_right hnone] at hremRun hremSpec ⊢
              cases hreb
                    : Spike.radix.rebuild_path arena.values.dirs arena.values.free_dirs
                        (alloc.vec.Vec.deref path1) 0#u32
                using Result.cases with
              | div => rw [hreb] at hremSpec; simp at hremSpec
              | vis _ _ => rw [hreb] at hremSpec; simp at hremSpec
              | ret rebRes =>
                  obtain ⟨n1, d1, f1⟩ := rebRes
                  change Spike.radix.rebuild_path _ _ _ 0#u32 = Result.ok (n1, d1, f1) at hreb
                  rw [hreb, bind_ok] at hremRun
                  change Result.ok (n1, d1, f1, path1) = Result.ok (next0, dirs', freeDirs', path') at hremRun
                  rw [Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq, Prod.mk.injEq] at hremRun
                  obtain ⟨rfl, rfl, rfl, rfl⟩ := hremRun
                  apply WP.spec_bind
                    (rebuild_path_counted_lockstep arena.values.dirs arena.values.rows.val
                      arena.dir_refs arena.row_refs arena.values.free_dirs
                      (alloc.vec.Vec.deref path1) 0#u32 pins entries n1 d1 f1 hreb st0
                      (fun h => (h rfl).elim)
                      (fun l hl h0 => single_link_live_ne_zero (hqZero l hl).1 h0)
                      hqZero (by omega))
                  rintro ⟨n2, d2, dr2, rr2, f2⟩
                    ⟨hnEq, hdEq, hfEq, st2, hn2Live, hn2NotQ, hq2, _⟩
                  subst hnEq hdEq hfEq
                  apply WP.spec_bind
                    (single_liveness_retain_next d2 arena.values.rows f2
                      arena.values.free_rows path1 arena.retired dr2 rr2 pins entries n2
                      hvalidAfter live.rowsBound live.freeRowsNodup st2 hqv hqnd hq2
                      hn2Live hn2NotQ (by omega))
                  rintro ⟨dr3, rr3⟩ hlive'
                  change WP.spec (Result.ok _) _
                  rw [WP.spec_ok]
                  exact ⟨
                    hlive',
                    hkeepsAfter,
                    hgrowthAfter,
                    ⟨
                      ⟨h', htree'⟩,
                      by simpa [alloc.vec.Vec.deref] using hrows',
                      hsortedAfter
                    ⟩,
                    by simpa [singleBindings, alloc.vec.Vec.deref] using hbind'
                  ⟩

private theorem not_lt_leaf_tag {l : U32} (h : 2147483648 < l.val)
    : ¬ l < 2147483648#u32 := by
  intro hlt
  have hlt' : l.val < (2147483648#u32 : U32).val := hlt
  have hval : (2147483648#u32 : U32).val = 2147483648 := by scalar_tac
  omega

private theorem vacant_row_ref_zero {V : Type} {arena : Spike.radix.SingleRadix V}
    {pins : List U32} (live : SingleLiveness arena pins)
    : ∀ (i : Nat) (c : U32),
        arena.values.rows.val[i]? = some none
        → arena.row_refs.val[i]? = some c
        → c.val = 0 := by
  intro i c hnone hc
  have hi : i < arena.values.rows.val.length := (List.getElem?_eq_some_iff.mp hnone).1
  let l : U32 := UScalar.ofNatCore (2147483648 + i + 1) (by have := live.rowsBound; scalar_tac)
  have hlVal : l.val = 2147483648 + i + 1 := by simp [l]
  have hsub : l.val - 2147483649 = i := by omega
  have hgt : 2147483648#u32 < l := by scalar_tac
  have hzero := live.counts.rowVal l c hgt (by rw [hsub]; exact hc)
  simpa [hsub, hnone] using hzero

theorem single_put_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (root : Spike.radix.RadixRoot) (row : Spike.radix.RadixRow V)
    (bindings : List (List U8 × U32)) (pins : List U32)
    (view : SingleView arena root bindings)
    (live : SingleLiveness arena pins)
    (rootRef
      : root ≠ 0#u32
        → SingleLinkLive arena.values.dirs.val arena.values.rows.val root
          ∧ radixReferences arena.values.dirs.val pins root > 0)
    (dirRoom : arena.values.dirs.val.length + bindings.length + 1 ≤ 2147483647)
    (rowRoom : arena.values.rows.val.length < 2147483647)
    (keyRoom : 2 * row.key.val.length + 1 ≤ Usize.max)
    (refRoom
      : pins.length + 17 * (arena.values.dirs.val.length + bindings.length + 2) + 1
        ≤ U32.max)
    : WP.spec (Spike.radix.SingleRadix.put arena root row)
        (fun (next, after) =>
          SingleLiveness after (if next = 0#u32 then pins else next :: pins)
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaGrowth arena.values after.values (bindings.length + 1) 1
          ∧ ∃ sorted,
              SingleView after next sorted
              ∧ (singleBindings after sorted).Perm
                  (Kv.Model.set (singleBindings arena bindings) row.key.val
                    row.value)) := by
  have hptrRoom : 2147483647 < Usize.max := by scalar_tac
  obtain ⟨height, tree⟩ := view.lookup
  have tree' := (radix_tree_binding_bound arena.values.dirs live.valid.directories tree).1
  obtain ⟨⟨⟨next0, leaf0, replaced0⟩, dirs', freeDirs', rows', freeRows', path'⟩, hputRun, hputPost⟩ :=
    wp_spec_exists
      (radix_put_refines arena.values.dirs arena.values.free_dirs arena.values.rows
        arena.values.free_rows arena.values.path root row bindings.length bindings
        tree' view.values (radix_compressed_of_knowledge arena.values.dirs _ live.valid.knowledge)
        live.valid.directories live.valid.dirs live.valid.rows dirRoom rowRoom keyRoom)
  obtain ⟨hkeptDirs, hfreeDirs', hdirInv', hknowFn, hfreeRows', hkeptRows, _, _, hdirsGrowth,
    hrowsGrowth, h', htree', hrows', hbind'⟩ := hputPost
  have hknow' : RadixKnowledge dirs' (radixKeyOf rows'.val) := hknowFn live.valid.knowledge
  have hvalidAfter : ArenaValid ⟨dirs', rows', freeDirs', freeRows', path'⟩ :=
    ⟨hfreeDirs', hfreeRows', hdirInv', hknow'⟩
  have hkeepsAfter : ArenaKeeps arena.values ⟨dirs', rows', freeDirs', freeRows', path'⟩ :=
    ⟨hkeptDirs, hkeptRows⟩
  have hgrowthAfter : ArenaGrowth arena.values
      ⟨dirs', rows', freeDirs', freeRows', path'⟩ (bindings.length + 1) 1 :=
    ⟨hdirsGrowth, hrowsGrowth⟩
  let sorted := insertSorted bindings row.key.val leaf0
  have hsortedPerm : sorted.Perm (Kv.Model.set bindings row.key.val leaf0) :=
    insertSorted_perm bindings row.key.val leaf0
  have hsortedOrd : sorted.Pairwise radixKeyLt :=
    insertSorted_pairwise view.sorted row.key.val leaf0
  have htreeSorted : RadixTree dirs'.val h' next0 sorted := radix_tree_perm htree' hsortedPerm.symm
  have hrowsSorted : RadixRows rows'.val sorted := fun e he => hrows' e (hsortedPerm.subset he)
  have hbindSorted : (radixBindings rows'.val sorted).Perm
      (Kv.Model.set (singleBindings arena bindings) row.key.val row.value) := by
    unfold singleBindings
    rw [← hbind']
    unfold radixBindings
    exact hsortedPerm.filterMap _
  obtain ⟨entries, hqv, hqnd, hqZero⟩ := live.queue
  have hputSpec : WP.spec
      (Spike.radix.put arena.values.dirs arena.values.free_dirs arena.values.rows
        arena.values.free_rows arena.values.path root row)
      (· = ((next0, leaf0, replaced0), dirs', freeDirs', rows', freeRows', path')) := by
    rw [hputRun, WP.spec_ok]
  unfold Spike.radix.put at hputRun hputSpec
  unfold Spike.radix.SingleRadix.put
  dsimp only at hputRun hputSpec ⊢
  have hvacRowsZero := vacant_row_ref_zero live
  have howners0 : OwnersLive arena.values.dirs.val arena.values.rows.val
      (pins ++ arenaEdges arena.values.dirs.val) := by
    intro l hl hnz
    rcases List.mem_append.mp hl with hp | he
    · exact live.pinsLive l hp
    · obtain ⟨d, hd, hc⟩ := List.mem_flatMap.mp he
      exact live.childrenLive d hd l hc hnz
  by_cases hrz : root = 0#u32
  · rw [ite_eq_left hrz] at hputRun hputSpec ⊢
    cases hal : Spike.radix.allocate arena.values.rows arena.values.free_rows row
      using Result.cases with
    | div => rw [hal] at hputSpec; simp at hputSpec
    | vis _ _ => rw [hal] at hputSpec; simp at hputSpec
    | ret ar =>
        obtain ⟨idx, r1, fr1⟩ := ar
        change Spike.radix.allocate arena.values.rows arena.values.free_rows row =
          Result.ok (idx, r1, fr1) at hal
        rw [hal, bind_ok] at hputRun hputSpec
        change (do
          let leaf ← Spike.radix.link_at idx true
          Result.ok ((leaf, leaf, none), arena.values.dirs, arena.values.free_dirs, r1, fr1,
            arena.values.path)) = Result.ok _ at hputRun
        change WP.spec (do
          let leaf ← Spike.radix.link_at idx true
          Result.ok ((leaf, leaf, none), arena.values.dirs, arena.values.free_dirs, r1, fr1,
            arena.values.path)) _ at hputSpec
        cases hlk : Spike.radix.link_at idx true using Result.cases with
        | div => rw [hlk] at hputSpec; simp at hputSpec
        | vis _ _ => rw [hlk] at hputSpec; simp at hputSpec
        | ret lf =>
            change Spike.radix.link_at idx true = Result.ok lf at hlk
            have hidxLt := link_at_ok_lt idx true lf hlk
            have hlkSpec := radix_link_matches idx true hidxLt
            rw [hlk, WP.spec_ok] at hlkSpec
            rw [hlk, bind_ok, Result.ok.injEq] at hputRun
            obtain ⟨hs1, hs2⟩ := Prod.mk.inj hputRun
            obtain ⟨hnextEq, hs1b⟩ := Prod.mk.inj hs1
            obtain ⟨hlfEq, _⟩ := Prod.mk.inj hs1b
            obtain ⟨hdEq, hs3⟩ := Prod.mk.inj hs2
            obtain ⟨hfdEq, hs4⟩ := Prod.mk.inj hs3
            obtain ⟨hrEq, hs5⟩ := Prod.mk.inj hs4
            obtain ⟨hfrEq, hpEq⟩ := Prod.mk.inj hs5
            subst next0 leaf0 dirs' freeDirs' rows' freeRows' path'
            apply WP.spec_bind
              (alloc_counted_lockstep arena.values.rows arena.row_refs
                arena.values.free_rows row idx r1 fr1 hal live.valid.rows
                live.freeRowsNodup live.counts.rowLen hvacRowsZero (fun _ => by omega))
            rintro ⟨idx2, r2, rr2, fr2⟩ ⟨hidxEq, hr2Eq, hfr2Eq, hfreeRowsNd', hrrLen', hnewRow, happ, hreu⟩
            subst idx2 r2 fr2
            have hidxLe : idx.val ≤ arena.values.rows.val.length := by
              by_cases h : idx.val = arena.values.rows.val.length
              · exact Nat.le_of_eq h
              · have : idx.val < r1.val.length := (List.getElem?_eq_some_iff.mp hnewRow).1
                have : r1.val.length ≤ arena.values.rows.val.length + 1 := hrowsGrowth
                omega
            obtain ⟨hcnt1, hkeepLive1, hlfSpec⟩ := alloc_row_counts live.counts howners0 hrrLen'
              happ hreu hidxLe
            have hlfVal : lf.val = idx.val + 1 + 2147483648 := by simpa using hlkSpec
            have hlfVal2 : lf.val = idx.val + 2147483649 := hlfVal.trans (Nat.add_assoc _ _ _)
            have hlfTag : 2147483648 < lf.val := by rw [hlfVal2]; exact Nat.lt_add_left _ (by decide)
            have hlfFresh : ¬ SingleLinkLive arena.values.dirs.val arena.values.rows.val lf := by
              intro hliv
              have hnot := not_lt_leaf_tag hlfTag
              simp only [SingleLinkLive, hnot, ite_false] at hliv
              obtain ⟨_, v0, hv0⟩ := hliv
              have hsub : lf.val - 2147483649 = idx.val := by omega
              rw [hsub] at hv0
              rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
              · rw [(hreu hlt).1] at hv0; cases hv0
              · rw [heq, List.getElem?_eq_none (Nat.le_refl _)] at hv0; cases hv0
            have hst1 : DirCountState arena.values.dirs r1.val arena.dir_refs rr2
                arena.values.free_dirs pins :=
              ⟨live.valid.dirs, live.freeDirsNodup, live.dirsBound,
                fun p hp => hkeepLive1 p (live.pinsLive p hp),
                fun d hd c hc hnz => hkeepLive1 c (live.childrenLive d hd c hc hnz), hcnt1⟩
            change WP.spec (do
              let leaf ← Spike.radix.link_at idx true
              let (v3, v4) ← Spike.radix.retain_link arena.dir_refs rr2 leaf
              Result.ok (leaf, { arena with
                values := { (arena.values) with rows := r1, free_rows := fr1 },
                dir_refs := v3, row_refs := v4 })) _
            rw [hlk, bind_ok]
            apply WP.spec_bind
              (single_liveness_retain_next arena.values.dirs r1 arena.values.free_dirs fr1
                arena.values.path arena.retired arena.dir_refs rr2 pins entries lf
                hvalidAfter (by omega) hfreeRowsNd' hst1 hqv hqnd
                (fun l hl => ⟨hkeepLive1 l (hqZero l hl).1, (hqZero l hl).2⟩)
                (fun _ => (hlfSpec lf hlfVal2).1)
                (fun l hl heq => hlfFresh (heq ▸ (hqZero l hl).1))
                (by omega))
            rintro ⟨dr3, rr3⟩ hlive'
            change WP.spec (Result.ok _) _
            rw [WP.spec_ok]
            exact ⟨hlive', hkeepsAfter, hgrowthAfter, sorted,
              ⟨⟨h', htreeSorted⟩, hrowsSorted, hsortedOrd⟩, hbindSorted⟩
  · rw [ite_eq_right hrz] at hputRun hputSpec ⊢
    cases hprep
          : Spike.radix.prepare_insert (alloc.vec.Vec.deref arena.values.dirs)
              (alloc.vec.Vec.deref arena.values.rows) arena.values.path root
              (alloc.vec.Vec.deref row.key)
      using Result.cases with
    | div => rw [hprep] at hputSpec; simp at hputSpec
    | vis _ _ => rw [hprep] at hputSpec; simp at hputSpec
    | ret prepRes =>
        obtain ⟨⟨stem, split⟩, path1⟩ := prepRes
        change Spike.radix.prepare_insert _ _ _ _ _ = Result.ok ((stem, split), path1) at hprep
        have hstemMem := prepare_insert_stem_mem _ _ _ _ _ stem split path1 hprep
        rw [hprep, bind_ok] at hputRun hputSpec
        simp only [bind_ok]
        change (do
          let (i, r1, fr1) ← Spike.radix.allocate arena.values.rows arena.values.free_rows row
          let leaf ← Spike.radix.link_at i true
          let (d1, fd1, child, rep) ← match split with
            | none => Result.ok (arena.values.dirs, arena.values.free_dirs, leaf, some stem)
            | some split1 => do
                let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref arena.values.dirs) stem split1
                let dir1 ← Spike.radix.RadixDir.set_child dir split1.new_slot leaf
                let (c1, d2, fd2) ← Spike.radix.add_directory arena.values.dirs arena.values.free_dirs dir1
                Result.ok (d2, fd2, c1, none)
          let (n1, d3, fd3) ← Spike.radix.rebuild_path d1 fd1 (alloc.vec.Vec.deref path1) child
          Result.ok ((n1, leaf, rep), d3, fd3, r1, fr1, path1)) = Result.ok _ at hputRun
        change WP.spec (do
          let (i, r1, fr1) ← Spike.radix.allocate arena.values.rows arena.values.free_rows row
          let leaf ← Spike.radix.link_at i true
          let (d1, fd1, child, rep) ← match split with
            | none => Result.ok (arena.values.dirs, arena.values.free_dirs, leaf, some stem)
            | some split1 => do
                let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref arena.values.dirs) stem split1
                let dir1 ← Spike.radix.RadixDir.set_child dir split1.new_slot leaf
                let (c1, d2, fd2) ← Spike.radix.add_directory arena.values.dirs arena.values.free_dirs dir1
                Result.ok (d2, fd2, c1, none)
          let (n1, d3, fd3) ← Spike.radix.rebuild_path d1 fd1 (alloc.vec.Vec.deref path1) child
          Result.ok ((n1, leaf, rep), d3, fd3, r1, fr1, path1)) _ at hputSpec
        change WP.spec (do
          let (i, r1, rr1, fr1) ← Spike.radix.alloc_counted arena.values.rows arena.row_refs
            arena.values.free_rows row
          let leaf ← Spike.radix.link_at i true
          let (d1, fd1, dr1, rr2, child) ← match split with
            | none => Result.ok (arena.values.dirs, arena.values.free_dirs, arena.dir_refs, rr1, leaf)
            | some split1 => do
                let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref arena.values.dirs) stem split1
                let dir1 ← Spike.radix.RadixDir.set_child dir split1.new_slot leaf
                let (c1, d2, dr2, rr3, fd2) ← Spike.radix.add_directory_counted arena.values.dirs
                  arena.dir_refs rr1 arena.values.free_dirs dir1
                Result.ok (d2, fd2, dr2, rr3, c1)
          let (n1, d3, dr3, rr4, fd3) ← Spike.radix.rebuild_path_counted d1 dr1 rr2 fd1
            (alloc.vec.Vec.deref path1) child
          let (dr4, rr5) ← Spike.radix.retain_link dr3 rr4 n1
          Result.ok (n1, { arena with
            values := { dirs := d3, rows := r1, free_dirs := fd3, free_rows := fr1, path := path1 },
            dir_refs := dr4, row_refs := rr5 })) _
        cases hal : Spike.radix.allocate arena.values.rows arena.values.free_rows row
          using Result.cases with
        | div => rw [hal] at hputSpec; simp at hputSpec
        | vis _ _ => rw [hal] at hputSpec; simp at hputSpec
        | ret ar =>
            obtain ⟨idx, r1, fr1⟩ := ar
            change Spike.radix.allocate _ _ _ = Result.ok (idx, r1, fr1) at hal
            rw [hal, bind_ok] at hputRun hputSpec
            change (do
              let leaf ← Spike.radix.link_at idx true
              let (d1, fd1, child, rep) ← match split with
                | none => Result.ok (arena.values.dirs, arena.values.free_dirs, leaf, some stem)
                | some split1 => do
                    let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref arena.values.dirs) stem split1
                    let dir1 ← Spike.radix.RadixDir.set_child dir split1.new_slot leaf
                    let (c1, d2, fd2) ← Spike.radix.add_directory arena.values.dirs arena.values.free_dirs dir1
                    Result.ok (d2, fd2, c1, none)
              let (n1, d3, fd3) ← Spike.radix.rebuild_path d1 fd1 (alloc.vec.Vec.deref path1) child
              Result.ok ((n1, leaf, rep), d3, fd3, r1, fr1, path1)) = Result.ok _ at hputRun
            change WP.spec (do
              let leaf ← Spike.radix.link_at idx true
              let (d1, fd1, child, rep) ← match split with
                | none => Result.ok (arena.values.dirs, arena.values.free_dirs, leaf, some stem)
                | some split1 => do
                    let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref arena.values.dirs) stem split1
                    let dir1 ← Spike.radix.RadixDir.set_child dir split1.new_slot leaf
                    let (c1, d2, fd2) ← Spike.radix.add_directory arena.values.dirs arena.values.free_dirs dir1
                    Result.ok (d2, fd2, c1, none)
              let (n1, d3, fd3) ← Spike.radix.rebuild_path d1 fd1 (alloc.vec.Vec.deref path1) child
              Result.ok ((n1, leaf, rep), d3, fd3, r1, fr1, path1)) _ at hputSpec
            cases hlk : Spike.radix.link_at idx true using Result.cases with
            | div => rw [hlk] at hputSpec; simp at hputSpec
            | vis _ _ => rw [hlk] at hputSpec; simp at hputSpec
            | ret lf =>
                change Spike.radix.link_at idx true = Result.ok lf at hlk
                have hidxLt := link_at_ok_lt idx true lf hlk
                have hlkSpec := radix_link_matches idx true hidxLt
                rw [hlk, WP.spec_ok] at hlkSpec
                rw [hlk, bind_ok] at hputRun hputSpec
                apply WP.spec_bind
                  (alloc_counted_lockstep arena.values.rows arena.row_refs
                    arena.values.free_rows row idx r1 fr1 hal live.valid.rows
                    live.freeRowsNodup live.counts.rowLen hvacRowsZero
                    (fun _ => by omega))
                rintro ⟨idx2, r2, rr1, fr2⟩ ⟨hidxEq, hr2Eq, hfr2Eq, hfreeRowsNd', hrrLen', hnewRow, happ, hreu⟩
                subst idx2 r2 fr2
                have hidxLe : idx.val ≤ arena.values.rows.val.length := by
                  by_cases h : idx.val = arena.values.rows.val.length
                  · exact Nat.le_of_eq h
                  · have hltNew : idx.val < r1.val.length := (List.getElem?_eq_some_iff.mp hnewRow).1
                    have hleLen : r1.val.length ≤ arena.values.rows.val.length + 1 := by
                      have := wp_spec_exists (radix_allocate_matches arena.values.rows arena.values.free_rows
                        row live.valid.rows (fun _ => by omega))
                      obtain ⟨⟨idx3, r3, fr3⟩, h3, hs3⟩ := this
                      rw [hal, Result.ok.injEq] at h3
                      obtain ⟨_, h32⟩ := Prod.mk.inj h3
                      obtain ⟨hr3, _⟩ := Prod.mk.inj h32
                      rw [hr3]; exact hs3.2.2.2.2.1
                    omega
                obtain ⟨hcnt1, hkeepLive1, hlfSpec⟩ := alloc_row_counts live.counts howners0 hrrLen'
                  happ hreu hidxLe
                have hlfVal : lf.val = idx.val + 1 + 2147483648 := by simpa using hlkSpec
                have hlfVal2 : lf.val = idx.val + 2147483649 := hlfVal.trans (Nat.add_assoc _ _ _)
                have hlfTag : 2147483648 < lf.val := by rw [hlfVal2]; exact Nat.lt_add_left _ (by decide)
                have hlfLive : SingleLinkLive arena.values.dirs.val r1.val lf :=
                  (hlfSpec lf hlfVal2).1
                have hlfFresh : ¬ SingleLinkLive arena.values.dirs.val arena.values.rows.val lf := by
                  intro hliv
                  have hnot := not_lt_leaf_tag hlfTag
                  simp only [SingleLinkLive, hnot, ite_false] at hliv
                  obtain ⟨_, v0, hv0⟩ := hliv
                  have hsub : lf.val - 2147483649 = idx.val := by omega
                  rw [hsub] at hv0
                  rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
                  · rw [(hreu hlt).1] at hv0; cases hv0
                  · rw [heq, List.getElem?_eq_none (Nat.le_refl _)] at hv0; cases hv0
                have hst1 : DirCountState arena.values.dirs r1.val arena.dir_refs rr1
                    arena.values.free_dirs pins :=
                  ⟨live.valid.dirs, live.freeDirsNodup, live.dirsBound,
                    fun p hp => hkeepLive1 p (live.pinsLive p hp),
                    fun d hd c hc hnz => hkeepLive1 c (live.childrenLive d hd c hc hnz), hcnt1⟩
                have hq1 : ∀ l ∈ entries, SingleLinkLive arena.values.dirs.val r1.val l
                    ∧ radixReferences arena.values.dirs.val pins l = 0 :=
                  fun l hl => ⟨hkeepLive1 l (hqZero l hl).1, (hqZero l hl).2⟩
                change WP.spec (do
                  let leaf ← Spike.radix.link_at idx true
                  let (d1, fd1, dr1, rr2, child) ← match split with
                    | none => Result.ok (arena.values.dirs, arena.values.free_dirs, arena.dir_refs, rr1, leaf)
                    | some split1 => do
                        let dir ← Spike.radix.split_directory (alloc.vec.Vec.deref arena.values.dirs) stem split1
                        let dir1 ← Spike.radix.RadixDir.set_child dir split1.new_slot leaf
                        let (c1, d2, dr2, rr3, fd2) ← Spike.radix.add_directory_counted arena.values.dirs
                          arena.dir_refs rr1 arena.values.free_dirs dir1
                        Result.ok (d2, fd2, dr2, rr3, c1)
                  let (n1, d3, dr3, rr4, fd3) ← Spike.radix.rebuild_path_counted d1 dr1 rr2 fd1
                    (alloc.vec.Vec.deref path1) child
                  let (dr4, rr5) ← Spike.radix.retain_link dr3 rr4 n1
                  Result.ok (n1, { arena with values := { dirs := d3, rows := r1, free_dirs := fd3, free_rows := fr1, path := path1 }, dir_refs := dr4, row_refs := rr5 })) _
                rw [hlk, bind_ok]
                have hstemMem' : stem = 0#u32 ∨ stem = root ∨ stem ∈ arenaEdges arena.values.dirs.val := by
                  simpa [alloc.vec.Vec.deref] using hstemMem
                have hstemLive : stem ≠ 0#u32 → SingleLinkLive arena.values.dirs.val r1.val stem := by
                  intro hsnz
                  rcases hstemMem' with rfl | hsr | he
                  · exact (hsnz rfl).elim
                  · rw [hsr]; exact hkeepLive1 root (rootRef hrz).1
                  · exact hkeepLive1 stem (howners0 stem (List.mem_append_right pins he) hsnz)
                have hstemNotQ : ∀ l ∈ entries, l ≠ stem := by
                  intro l hl heq
                  subst heq
                  rcases hstemMem' with h0 | hsr | he
                  · exact single_link_live_ne_zero (hqZero l hl).1 h0
                  · have h1 := (rootRef hrz).2; have h2 := (hqZero l hl).2; rw [hsr] at h2; omega
                  · have hpos := List.count_pos_iff.mpr (List.mem_append_right pins he)
                    have hz := (hqZero l hl).2
                    rw [radixReferences_eq] at hz
                    omega
                cases split with
                | none =>
                    simp only [bind_ok] at hputRun hputSpec ⊢
                    change (do
                      let (n1, d3, fd3) ← Spike.radix.rebuild_path arena.values.dirs
                        arena.values.free_dirs (alloc.vec.Vec.deref path1) lf
                      Result.ok ((n1, lf, some stem), d3, fd3, r1, fr1, path1)) =
                        Result.ok ((next0, leaf0, replaced0), dirs', freeDirs', rows', freeRows', path') at hputRun
                    change WP.spec (do
                      let (n1, d3, fd3) ← Spike.radix.rebuild_path arena.values.dirs
                        arena.values.free_dirs (alloc.vec.Vec.deref path1) lf
                      Result.ok ((n1, lf, some stem), d3, fd3, r1, fr1, path1))
                        (· = ((next0, leaf0, replaced0), dirs', freeDirs', rows', freeRows', path')) at hputSpec
                    change WP.spec (do
                      let (n1, d3, dr3, rr4, fd3) ← Spike.radix.rebuild_path_counted arena.values.dirs
                        arena.dir_refs rr1 arena.values.free_dirs (alloc.vec.Vec.deref path1) lf
                      let (dr4, rr5) ← Spike.radix.retain_link dr3 rr4 n1
                      Result.ok (n1, { arena with values := { dirs := d3, rows := r1, free_dirs := fd3, free_rows := fr1, path := path1 }, dir_refs := dr4, row_refs := rr5 })) _
                    cases hreb
                          : Spike.radix.rebuild_path arena.values.dirs
                              arena.values.free_dirs (alloc.vec.Vec.deref path1) lf
                      using Result.cases with
                    | div => rw [hreb] at hputSpec; simp at hputSpec
                    | vis _ _ => rw [hreb] at hputSpec; simp at hputSpec
                    | ret rebRes =>
                        obtain ⟨n1, d3, fd3⟩ := rebRes
                        change Spike.radix.rebuild_path _ _ _ lf = Result.ok (n1, d3, fd3) at hreb
                        rw [hreb, bind_ok] at hputRun
                        change Result.ok ((n1, lf, some stem), d3, fd3, r1, fr1, path1) =
                          Result.ok ((next0, leaf0, replaced0), dirs', freeDirs', rows', freeRows', path') at hputRun
                        rw [Result.ok.injEq] at hputRun
                        obtain ⟨hs1, hs2⟩ := Prod.mk.inj hputRun
                        obtain ⟨hnextEq, hs1b⟩ := Prod.mk.inj hs1
                        obtain ⟨hlfEq, _⟩ := Prod.mk.inj hs1b
                        obtain ⟨hdEq, hs3⟩ := Prod.mk.inj hs2
                        obtain ⟨hfdEq, hs4⟩ := Prod.mk.inj hs3
                        obtain ⟨hrEq, hs5⟩ := Prod.mk.inj hs4
                        obtain ⟨hfrEq, hpEq⟩ := Prod.mk.inj hs5
                        subst next0 leaf0 dirs' freeDirs' rows' freeRows' path'
                        apply WP.spec_bind
                          (rebuild_path_counted_lockstep arena.values.dirs r1.val
                            arena.dir_refs rr1 arena.values.free_dirs
                            (alloc.vec.Vec.deref path1) lf pins entries n1 d3 fd3 hreb
                            hst1 (fun _ => hlfLive)
                            (fun l hl heq => hlfFresh (heq ▸ (hqZero l hl).1)) hq1
                            (by omega))
                        rintro ⟨n2, d2, dr2, rr2, fd2⟩
                          ⟨hnEq, hd2Eq, hf2Eq, st2, hn2Live, hn2NotQ, hq2, _⟩
                        subst n2 d2 fd2
                        apply WP.spec_bind
                          (single_liveness_retain_next d3 r1 fd3 fr1 path1 arena.retired
                            dr2 rr2 pins entries n1 hvalidAfter (by omega) hfreeRowsNd'
                            st2 hqv hqnd hq2 hn2Live hn2NotQ (by omega))
                        rintro ⟨dr3, rr3⟩ hlive'
                        change WP.spec (Result.ok _) _
                        rw [WP.spec_ok]
                        exact ⟨hlive', hkeepsAfter, hgrowthAfter, sorted,
                          ⟨⟨h', htreeSorted⟩, hrowsSorted, hsortedOrd⟩, hbindSorted⟩
                | some split1 =>
                    dsimp only at hputRun hputSpec ⊢
                    cases hsp
                          : Spike.radix.split_directory
                              (alloc.vec.Vec.deref arena.values.dirs) stem split1
                      using Result.cases with
                    | div => rw [hsp] at hputSpec; simp at hputSpec
                    | vis _ _ => rw [hsp] at hputSpec; simp at hputSpec
                    | ret dir0 =>
                        change Spike.radix.split_directory _ stem split1 = Result.ok dir0 at hsp
                        have hdir0Mem := split_directory_children_mem _ stem split1 dir0 hsp
                        rw [hsp, bind_ok] at hputRun hputSpec
                        simp only [bind_ok]
                        cases hset
                              : Spike.radix.RadixDir.set_child dir0 split1.new_slot lf
                          using Result.cases with
                        | div => rw [hset] at hputSpec; simp at hputSpec
                        | vis _ _ => rw [hset] at hputSpec; simp at hputSpec
                        | ret dir1 =>
                            change Spike.radix.RadixDir.set_child dir0 split1.new_slot lf = Result.ok dir1 at hset
                            have hdir1Mem := set_child_children_mem dir0 split1.new_slot lf dir1 hset
                            rw [hset, bind_ok] at hputRun hputSpec
                            simp only [bind_ok]
                            cases hadd
                                  : Spike.radix.add_directory arena.values.dirs
                                      arena.values.free_dirs dir1
                              using Result.cases with
                            | div => rw [hadd] at hputSpec; simp at hputSpec
                            | vis _ _ => rw [hadd] at hputSpec; simp at hputSpec
                            | ret addRes =>
                                obtain ⟨c1, d2, fd2⟩ := addRes
                                change Spike.radix.add_directory _ _ dir1 = Result.ok (c1, d2, fd2) at hadd
                                rw [hadd, bind_ok] at hputRun hputSpec
                                change (Result.ok (d2, fd2, c1, none) >>= fun (d1, fd1, child, rep) => do
                                  let (n1, d3, fd3) ← Spike.radix.rebuild_path d1 fd1 (alloc.vec.Vec.deref path1) child
                                  Result.ok ((n1, lf, rep), d3, fd3, r1, fr1, path1)) =
                                    Result.ok ((next0, leaf0, replaced0), dirs', freeDirs', rows', freeRows', path') at hputRun
                                change WP.spec (Result.ok (d2, fd2, c1, none) >>= fun (d1, fd1, child, rep) => do
                                  let (n1, d3, fd3) ← Spike.radix.rebuild_path d1 fd1 (alloc.vec.Vec.deref path1) child
                                  Result.ok ((n1, lf, rep), d3, fd3, r1, fr1, path1))
                                    (· = ((next0, leaf0, replaced0), dirs', freeDirs', rows', freeRows', path')) at hputSpec
                                rw [bind_tc_ok] at hputRun hputSpec
                                dsimp only at hputRun hputSpec
                                cases hreb
                                      : Spike.radix.rebuild_path d2 fd2
                                          (alloc.vec.Vec.deref path1) c1
                                  using Result.cases with
                                | div => rw [hreb] at hputSpec; simp at hputSpec
                                | vis _ _ => rw [hreb] at hputSpec; simp at hputSpec
                                | ret rebRes =>
                                    obtain ⟨n1, d3, fd3⟩ := rebRes
                                    change Spike.radix.rebuild_path d2 fd2 _ c1 = Result.ok (n1, d3, fd3) at hreb
                                    rw [hreb, bind_ok] at hputRun
                                    change Result.ok ((n1, lf, none), d3, fd3, r1, fr1, path1) =
                                      Result.ok ((next0, leaf0, replaced0), dirs', freeDirs', rows', freeRows', path') at hputRun
                                    rw [Result.ok.injEq] at hputRun
                                    obtain ⟨hs1, hs2⟩ := Prod.mk.inj hputRun
                                    obtain ⟨hnextEq, hs1b⟩ := Prod.mk.inj hs1
                                    obtain ⟨hlfEq, _⟩ := Prod.mk.inj hs1b
                                    obtain ⟨hdEq, hs3⟩ := Prod.mk.inj hs2
                                    obtain ⟨hfdEq, hs4⟩ := Prod.mk.inj hs3
                                    obtain ⟨hrEq, hs5⟩ := Prod.mk.inj hs4
                                    obtain ⟨hfrEq, hpEq⟩ := Prod.mk.inj hs5
                                    subst next0 leaf0 dirs' freeDirs' rows' freeRows' path'
                                    have hdir0Mem' : ∀ c ∈ dir0.children.val,
                                        c = 0#u32 ∨ c = stem ∨ c ∈ arenaEdges arena.values.dirs.val := by
                                      simpa [alloc.vec.Vec.deref] using hdir0Mem
                                    have hdir1Live : ∀ c ∈ dir1.children.val, c ≠ 0#u32 →
                                        SingleLinkLive arena.values.dirs.val r1.val c := by
                                      intro c hc hnz
                                      rcases hdir1Mem c hc with rfl | hc0
                                      · exact hlfLive
                                      · rcases hdir0Mem' c hc0 with rfl | rfl | he
                                        · exact (hnz rfl).elim
                                        · exact hstemLive hnz
                                        · exact hkeepLive1 c (howners0 c (List.mem_append_right pins he) hnz)
                                    have hdir1NotQ : ∀ l ∈ entries, dir1.children.val.count l = 0 := by
                                      intro l hl
                                      rw [List.count_eq_zero]
                                      intro hmem
                                      rcases hdir1Mem l hmem with rfl | hc0
                                      · exact hlfFresh (hqZero l hl).1
                                      · rcases hdir0Mem' l hc0 with h0 | hls | he
                                        · exact single_link_live_ne_zero (hqZero l hl).1 h0
                                        · exact hstemNotQ l hl hls
                                        · have hpos := List.count_pos_iff.mpr (List.mem_append_right pins he)
                                          have hz := (hqZero l hl).2
                                          rw [radixReferences_eq] at hz
                                          omega
                                    have haddBind : WP.spec
                                        (do
                                          let (c1, d2, dr2, rr3, fd2) ← Spike.radix.add_directory_counted
                                            arena.values.dirs arena.dir_refs rr1 arena.values.free_dirs dir1
                                          Result.ok (d2, fd2, dr2, rr3, c1))
                                        (fun (d1, fd1, dr1, rr2, child) =>
                                          d1 = d2 ∧ fd1 = fd2 ∧ child = c1
                                          ∧ DirCountState d2 r1.val dr1 rr2 fd2 pins
                                          ∧ SingleLinkLive d2.val r1.val c1
                                          ∧ ¬ SingleLinkLive arena.values.dirs.val r1.val c1
                                          ∧ (∀ l, SingleLinkLive arena.values.dirs.val r1.val l →
                                              SingleLinkLive d2.val r1.val l)
                                          ∧ ∀ target,
                                              radixReferences arena.values.dirs.val pins target = 0
                                              → dir1.children.val.count target = 0
                                              → radixReferences d2.val pins target = 0) := by
                                      apply WP.spec_bind
                                        (add_directory_counted_lockstep arena.values.dirs r1.val
                                          arena.dir_refs rr1 arena.values.free_dirs dir1 pins
                                          c1 d2 fd2 hadd hst1 hdir1Live (by omega))
                                      rintro ⟨c2, d2', dr2, rr2, fd2'⟩
                                        ⟨hcEq, hd2Eq, hf2Eq, st2, hc2Live, hc2Fresh, _, _, hkeep2, hzero2⟩
                                      subst c2 d2' fd2'
                                      change WP.spec (Result.ok _) _
                                      rw [WP.spec_ok]
                                      exact ⟨rfl, rfl, rfl, st2, hc2Live, hc2Fresh, hkeep2, hzero2⟩
                                    apply WP.spec_bind haddBind
                                    rintro ⟨d2', fd2', dr2, rr2, c2⟩
                                      ⟨hd2Eq, hf2Eq, hcEq, st2, hc2Live, hc2Fresh, hkeep2, hzero2⟩
                                    subst d2' fd2' c2
                                    have hq2 : ∀ l ∈ entries, SingleLinkLive d2.val r1.val l
                                        ∧ radixReferences d2.val pins l = 0 :=
                                      fun l hl => ⟨hkeep2 l (hq1 l hl).1, hzero2 l (hq1 l hl).2 (hdir1NotQ l hl)⟩
                                    apply WP.spec_bind
                                      (rebuild_path_counted_lockstep d2 r1.val dr2 rr2 fd2
                                        (alloc.vec.Vec.deref path1) c1 pins entries n1 d3
                                        fd3 hreb st2 (fun _ => hc2Live)
                                        (fun l hl heq => hc2Fresh (heq ▸ (hq1 l hl).1))
                                        hq2 (by omega))
                                    rintro ⟨n2, d3', dr3, rr3, fd3'⟩
                                      ⟨hnEq, hd3Eq, hf3Eq, st3, hn2Live, hn2NotQ, hq3, _⟩
                                    subst n2 d3' fd3'
                                    apply WP.spec_bind
                                      (single_liveness_retain_next d3 r1 fd3 fr1 path1
                                        arena.retired dr3 rr3 pins entries n1 hvalidAfter
                                        (by omega) hfreeRowsNd' st3 hqv hqnd hq3 hn2Live
                                        hn2NotQ (by omega))
                                    rintro ⟨dr4, rr4⟩ hlive'
                                    change WP.spec (Result.ok _) _
                                    rw [WP.spec_ok]
                                    exact ⟨
                                      hlive',
                                      hkeepsAfter,
                                      hgrowthAfter,
                                      sorted,
                                      ⟨⟨h', htreeSorted⟩, hrowsSorted, hsortedOrd⟩,
                                      hbindSorted
                                    ⟩

theorem single_stage_batch_leaf_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (row : Spike.radix.RadixRow V) (pins : List U32)
    (live : SingleLiveness arena pins)
    (rowRoom : arena.values.rows.val.length < 2147483647)
    : WP.spec (Spike.radix.SingleRadix.stage_batch_leaf arena row)
        (fun (leaf, after) =>
          SingleLiveness after pins
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaGrowth arena.values after.values 0 1
          ∧ after.values.dirs = arena.values.dirs
          ∧ after.retired = arena.retired
          ∧ 2147483648 < leaf.val
          ∧ SingleLinkLive after.values.dirs.val after.values.rows.val leaf
          ∧ ¬ SingleLinkLive arena.values.dirs.val arena.values.rows.val leaf
          ∧ radixRow after.values.rows.val leaf = some row) := by
  have ptrRoom : 2147483647 < Usize.max := by scalar_tac
  obtain ⟨⟨idx, r1, fr1⟩, halRun, halSpec⟩ := wp_spec_exists
    (radix_allocate_matches arena.values.rows arena.values.free_rows row live.valid.rows
      (fun _ => by omega))
  obtain ⟨hnewRow0, hkeptRows, _, hidxBound, hrowsGrowth, hfreeRows', _⟩ := halSpec
  have hvacRowsZero := vacant_row_ref_zero live
  have howners0 : OwnersLive arena.values.dirs.val arena.values.rows.val
      (pins ++ arenaEdges arena.values.dirs.val) := by
    intro l hl hnz
    rcases List.mem_append.mp hl with hp | he
    · exact live.pinsLive l hp
    · obtain ⟨d, hd, hc⟩ := List.mem_flatMap.mp he
      exact live.childrenLive d hd l hc hnz
  unfold Spike.radix.SingleRadix.stage_batch_leaf
  apply WP.spec_bind
    (alloc_counted_lockstep arena.values.rows arena.row_refs arena.values.free_rows row
      idx r1 fr1 halRun live.valid.rows live.freeRowsNodup live.counts.rowLen hvacRowsZero
      (fun _ => by omega))
  rintro ⟨idx2, r2, rr2, fr2⟩ ⟨hidxEq, hrEq, hfrEq, hfreeRowsNd', hrrLen', hnewRow, happ, hreu⟩
  subst idx2 r2 fr2
  apply WP.spec_bind (radix_link_matches idx true (by omega))
  intro leaf hleaf
  rw [WP.spec_ok]
  have hidxLe : idx.val ≤ arena.values.rows.val.length := by omega
  obtain ⟨hcnt1, hkeepLive1, hlfSpec⟩ := alloc_row_counts live.counts howners0 hrrLen'
    happ hreu hidxLe
  have hlfVal : leaf.val = idx.val + 1 + 2147483648 := by simpa using hleaf
  have hlfVal2 : leaf.val = idx.val + 2147483649 := hlfVal.trans (Nat.add_assoc _ _ _)
  have hlfTag : 2147483648 < leaf.val := by rw [hlfVal2]; exact Nat.lt_add_left _ (by decide)
  have hlfFresh : ¬ SingleLinkLive arena.values.dirs.val arena.values.rows.val leaf := by
    intro hliv
    have hnot := not_lt_leaf_tag hlfTag
    simp only [SingleLinkLive, hnot, ite_false] at hliv
    obtain ⟨_, v0, hv0⟩ := hliv
    have hsub : leaf.val - 2147483649 = idx.val := by omega
    rw [hsub] at hv0
    rcases Nat.lt_or_eq_of_le hidxLe with hlt | heq
    · rw [(hreu hlt).1] at hv0; cases hv0
    · rw [heq, List.getElem?_eq_none (Nat.le_refl _)] at hv0; cases hv0
  have hknow1 : RadixKnowledge arena.values.dirs (radixKeyOf r1.val) := by
    intro j d hd
    obtain ⟨rt, h, bs, hrt, hlt, htree, hkey, hpref⟩ := live.valid.knowledge j d hd
    exact ⟨rt, h, bs, hrt, hlt, htree,
      fun b hb => radix_keys_kept arena.values.rows.val r1.val hkeptRows b.2 b.1 (hkey b hb),
      hpref⟩
  obtain ⟨entries, hqv, hqnd, hqZero⟩ := live.queue
  have hr1Bound : r1.val.length ≤ 2147483647 := by
    have : r1.val.length ≤ arena.values.rows.val.length + 1 := hrowsGrowth
    omega
  refine ⟨
    ⟨
      ⟨live.valid.dirs, hfreeRows', live.valid.directories, hknow1⟩,
      live.dirsBound,
      hr1Bound,
      live.freeDirsNodup,
      hfreeRowsNd',
      fun p hp => hkeepLive1 p (live.pinsLive p hp),
      fun d hd c hc hnz => hkeepLive1 c (live.childrenLive d hd c hc hnz),
      hcnt1,
      entries,
      hqv,
      hqnd,
      fun l hl => ⟨hkeepLive1 l (hqZero l hl).1, (hqZero l hl).2⟩
    ⟩,
    ⟨fun _ _ h => h, hkeptRows⟩,
    ⟨Nat.le_refl _, hrowsGrowth⟩,
    rfl,
    rfl,
    hlfTag,
    (hlfSpec leaf hlfVal2).1,
    hlfFresh,
    ?_
  ⟩
  have hsub : leaf.val - 2147483648 - 1 = idx.val := by omega
  simp [radixRow, hlfTag, hsub, hnewRow0]

private theorem slice_index_usize_mem {α : Type} (s : Slice α) (i : Usize) (x : α)
    (h : Slice.index_usize s i = Result.ok x)
    : x ∈ s.val := by
  unfold Slice.index_usize at h
  rw [Slice.getElem?_Usize_eq] at h
  cases hge : s.val[i.val]? with
  | none => rw [hge] at h; exact absurd h (by simp [Result.fail])
  | some v =>
      rw [hge, Result.ok.injEq] at h
      subst h
      exact List.mem_iff_getElem?.mpr ⟨i.val, hge⟩

private theorem vec_index_mem {α : Type} (v : alloc.vec.Vec α) (i : Usize) (x : α)
    (h : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = Result.ok x)
    : x ∈ v.val := by
  rw [alloc.vec.Vec.index_slice_index] at h
  have hlt : i.val < v.val.length := by
    by_contra hge
    unfold alloc.vec.Vec.index_usize at h
    have hnone : v.val[i.val]? = none := List.getElem?_eq_none (Nat.le_of_not_gt hge)
    simp [hnone] at h
  have hsp := alloc.vec.Vec.index_usize_spec v i hlt
  rw [h, WP.spec_ok] at hsp
  rw [hsp]
  exact List.getElem_mem hlt

private theorem sorted_frame_empty_children {V : Type}
    (rows : Slice (Option (Spike.radix.RadixRow V)))
    (sorted : Slice U32) (begin «end» parentSlot : Usize)
    (frame : Spike.radix.BuildFrame)
    (h : Spike.radix.sorted_frame rows sorted begin «end» parentSlot = Result.ok frame)
    : ∀ c ∈ frame.dir.children.val, c = 0#u32 := by
  have hs : WP.spec (Spike.radix.sorted_frame rows sorted begin «end» parentSlot) (· = frame) := by
    rw [h, WP.spec_ok]
  unfold Spike.radix.sorted_frame at hs
  cases hi : Slice.index_usize sorted begin using Result.cases with
  | div => rw [hi] at hs; simp at hs
  | vis _ _ => rw [hi] at hs; simp at hs
  | ret i =>
      change Slice.index_usize sorted begin = Result.ok i at hi
      rw [hi, bind_ok] at hs
      cases hf : Spike.radix.row_at rows i using Result.cases with
      | div => rw [hf] at hs; simp at hs
      | vis _ _ => rw [hf] at hs; simp at hs
      | ret first =>
          change Spike.radix.row_at rows i = Result.ok first at hf
          rw [hf, bind_ok] at hs
          cases hsub : «end» - 1#usize using Result.cases with
          | div => rw [hsub] at hs; simp at hs
          | vis _ _ => rw [hsub] at hs; simp at hs
          | ret i1 =>
              change «end» - 1#usize = Result.ok i1 at hsub
              rw [hsub, bind_ok] at hs
              cases hi2 : Slice.index_usize sorted i1 using Result.cases with
              | div => rw [hi2] at hs; simp at hs
              | vis _ _ => rw [hi2] at hs; simp at hs
              | ret i2 =>
                  change Slice.index_usize sorted i1 = Result.ok i2 at hi2
                  rw [hi2, bind_ok] at hs
                  cases hl : Spike.radix.row_at rows i2 using Result.cases with
                  | div => rw [hl] at hs; simp at hs
                  | vis _ _ => rw [hl] at hs; simp at hs
                  | ret last =>
                      change Spike.radix.row_at rows i2 = Result.ok last at hl
                      rw [hl, bind_ok] at hs
                      dsimp only at hs
                      cases hd
                            : Spike.radix.first_difference (alloc.vec.Vec.deref first.key)
                                (alloc.vec.Vec.deref last.key)
                        using Result.cases with
                      | div => rw [hd] at hs; simp at hs
                      | vis _ _ => rw [hd] at hs; simp at hs
                      | ret o =>
                          change Spike.radix.first_difference _ _ = Result.ok o at hd
                          rw [hd, bind_ok] at hs
                          cases o with
                          | none => simp at hs
                          | some digit =>
                              simp only at hs
                              unfold Spike.radix.RadixDir.empty at hs
                              rw [bind_ok, WP.spec_ok] at hs
                              subst hs
                              intro c hc
                              simp only [Array.repeat_val, List.mem_replicate] at hc
                              exact hc.2

private theorem build_sorted_loop_len_mono {V : Type}
    (rows : Slice (Option (Spike.radix.RadixRow V))) (sorted : Slice U32)
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir)) (free : alloc.vec.Vec Usize)
    (parents : alloc.vec.Vec Spike.radix.BuildFrame) (frame : Spike.radix.BuildFrame)
    (res : U32 × alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec Usize)
    (h
      : Spike.radix.build_sorted_loop dirs free rows sorted parents frame = Result.ok res)
    : dirs.val.length ≤ res.2.1.val.length := by
  unfold Spike.radix.build_sorted_loop at h
  refine loop_invariant_of_ok
    (fun (d, f, ps, fr) => Spike.radix.build_sorted_loop.body rows sorted d f ps fr)
    (fun a z => a.1.val.length ≤ z.2.1.val.length) ?_ h
  rintro ⟨d1, f1, ps1, fr1⟩ r hb
  dsimp only at hb
  have hs : WP.spec (Spike.radix.build_sorted_loop.body rows sorted d1 f1 ps1 fr1) (· = r) := by
    rw [hb, WP.spec_ok]
  unfold Spike.radix.build_sorted_loop.body at hb hs
  by_cases hdone : fr1.cursor = fr1.end
  · rw [ite_eq_left hdone] at hb hs
    cases hadd : Spike.radix.add_directory d1 f1 fr1.dir using Result.cases with
    | div => rw [hadd] at hs; simp at hs
    | vis _ _ => rw [hadd] at hs; simp at hs
    | ret ar =>
        obtain ⟨comp, d2, f2⟩ := ar
        change Spike.radix.add_directory d1 f1 fr1.dir = Result.ok (comp, d2, f2) at hadd
        have hle := add_directory_len_le d1 f1 fr1.dir comp d2 f2 hadd
        rw [hadd, bind_ok] at hb hs
        change (do
          let b ← alloc.vec.Vec.is_empty ps1
          if b then Result.ok (ControlFlow.done (comp, d2, f2))
          else do
            let depth ← alloc.vec.Vec.len ps1 - 1#usize
            let parent ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Spike.radix.BuildFrame) ps1 depth
            let ps2 ← alloc.vec.Vec.resize Spike.radix.BuildFrame.Insts.CoreCloneClone ps1 depth fr1
            let rd ← Spike.radix.RadixDir.set_child parent.dir fr1.parent_slot comp
            Result.ok (ControlFlow.cont (d2, f2, ps2, { parent with dir := rd }))) = Result.ok r at hb
        change WP.spec (do
          let b ← alloc.vec.Vec.is_empty ps1
          if b then Result.ok (ControlFlow.done (comp, d2, f2))
          else do
            let depth ← alloc.vec.Vec.len ps1 - 1#usize
            let parent ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Spike.radix.BuildFrame) ps1 depth
            let ps2 ← alloc.vec.Vec.resize Spike.radix.BuildFrame.Insts.CoreCloneClone ps1 depth fr1
            let rd ← Spike.radix.RadixDir.set_child parent.dir fr1.parent_slot comp
            Result.ok (ControlFlow.cont (d2, f2, ps2, { parent with dir := rd }))) (· = r) at hs
        cases hemp : alloc.vec.Vec.is_empty ps1 using Result.cases with
        | div => rw [hemp] at hs; simp at hs
        | vis _ _ => rw [hemp] at hs; simp at hs
        | ret b =>
            change alloc.vec.Vec.is_empty ps1 = Result.ok b at hemp
            rw [hemp, bind_ok] at hb hs
            cases b with
            | true =>
                simp only [ite_true, Result.ok.injEq] at hb
                subst hb
                exact hle
            | false =>
                simp only [Bool.false_eq_true, ite_false] at hb hs
                cases hsub : alloc.vec.Vec.len ps1 - 1#usize using Result.cases with
                | div => rw [hsub] at hs; simp at hs
                | vis _ _ => rw [hsub] at hs; simp at hs
                | ret depth =>
                    change alloc.vec.Vec.len ps1 - 1#usize = Result.ok depth at hsub
                    rw [hsub, bind_ok] at hb hs
                    cases hpar
                          : alloc.vec.Vec.index
                              (core.slice.index.SliceIndexUsizeSlice
                                Spike.radix.BuildFrame)
                              ps1 depth
                      using Result.cases with
                    | div => rw [hpar] at hs; simp at hs
                    | vis _ _ => rw [hpar] at hs; simp at hs
                    | ret parent =>
                        change alloc.vec.Vec.index _ ps1 depth = Result.ok parent at hpar
                        rw [hpar, bind_ok] at hb hs
                        cases hres
                              : alloc.vec.Vec.resize
                                  Spike.radix.BuildFrame.Insts.CoreCloneClone ps1 depth
                                  fr1
                          using Result.cases with
                        | div => rw [hres] at hs; simp at hs
                        | vis _ _ => rw [hres] at hs; simp at hs
                        | ret ps2 =>
                            change alloc.vec.Vec.resize _ ps1 depth fr1 = Result.ok ps2 at hres
                            rw [hres, bind_ok] at hb hs
                            cases hset
                                  : Spike.radix.RadixDir.set_child parent.dir
                                      fr1.parent_slot comp
                              using Result.cases with
                            | div => rw [hset] at hs; simp at hs
                            | vis _ _ => rw [hset] at hs; simp at hs
                            | ret rd =>
                                change Spike.radix.RadixDir.set_child parent.dir fr1.parent_slot comp = Result.ok rd at hset
                                rw [hset, bind_ok, Result.ok.injEq] at hb
                                subst hb
                                intro z hz
                                exact Nat.le_trans hle hz
  · rw [ite_eq_right hdone] at hb hs
    cases hi : Slice.index_usize sorted fr1.cursor using Result.cases with
    | div => rw [hi] at hs; simp at hs
    | vis _ _ => rw [hi] at hs; simp at hs
    | ret i =>
        change Slice.index_usize sorted fr1.cursor = Result.ok i at hi
        rw [hi, bind_ok] at hb hs
        cases hrr : Spike.radix.row_at rows i using Result.cases with
        | div => rw [hrr] at hs; simp at hs
        | vis _ _ => rw [hrr] at hs; simp at hs
        | ret rr =>
            change Spike.radix.row_at rows i = Result.ok rr at hrr
            rw [hrr, bind_ok] at hb hs
            dsimp only at hb hs
            cases hsym : Spike.radix.symbol (alloc.vec.Vec.deref rr.key) fr1.dir.digit
              using Result.cases with
            | div => rw [hsym] at hs; simp at hs
            | vis _ _ => rw [hsym] at hs; simp at hs
            | ret slot =>
                change Spike.radix.symbol _ fr1.dir.digit = Result.ok slot at hsym
                rw [hsym, bind_ok] at hb hs
                cases hend
                      : Spike.radix.sorted_group_end rows sorted fr1.cursor fr1.end
                          fr1.dir.digit slot
                  using Result.cases with
                | div => rw [hend] at hs; simp at hs
                | vis _ _ => rw [hend] at hs; simp at hs
                | ret e =>
                    change Spike.radix.sorted_group_end rows sorted fr1.cursor fr1.end fr1.dir.digit slot = Result.ok e at hend
                    rw [hend, bind_ok] at hb hs
                    cases hadd1 : fr1.cursor + 1#usize using Result.cases with
                    | div => rw [hadd1] at hs; simp at hs
                    | vis _ _ => rw [hadd1] at hs; simp at hs
                    | ret i1 =>
                        change fr1.cursor + 1#usize = Result.ok i1 at hadd1
                        rw [hadd1, bind_ok] at hb hs
                        by_cases hsingle : e = i1
                        · rw [ite_eq_left hsingle] at hb hs
                          cases hset : Spike.radix.RadixDir.set_child fr1.dir slot i
                            using Result.cases with
                          | div => rw [hset] at hs; simp at hs
                          | vis _ _ => rw [hset] at hs; simp at hs
                          | ret rd =>
                              change Spike.radix.RadixDir.set_child fr1.dir slot i = Result.ok rd at hset
                              rw [hset, bind_ok, Result.ok.injEq] at hb
                              subst hb
                              intro z hz; exact hz
                        · rw [ite_eq_right hsingle] at hb hs
                          cases hpush : alloc.vec.Vec.push ps1 { fr1 with cursor := e }
                            using Result.cases with
                          | div => rw [hpush] at hs; simp at hs
                          | vis _ _ => rw [hpush] at hs; simp at hs
                          | ret ps2 =>
                              change alloc.vec.Vec.push ps1 _ = Result.ok ps2 at hpush
                              rw [hpush, bind_ok] at hb hs
                              cases hfr
                                    : Spike.radix.sorted_frame rows sorted fr1.cursor e
                                        slot
                                using Result.cases with
                              | div => rw [hfr] at hs; simp at hs
                              | vis _ _ => rw [hfr] at hs; simp at hs
                              | ret fr2 =>
                                  change Spike.radix.sorted_frame rows sorted fr1.cursor e slot = Result.ok fr2 at hfr
                                  rw [hfr, bind_ok, Result.ok.injEq] at hb
                                  subst hb
                                  intro z hz; exact hz

private theorem build_sorted_counted_lockstep {V : Type}
    (dirs : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (rows : Slice (Option (Spike.radix.RadixRow V)))
    (dirRefs rowRefs : alloc.vec.Vec U32) (freeDirs : alloc.vec.Vec Usize)
    (sorted : Slice U32) (pins entries : List U32)
    (resRoot : U32) (dirs' : alloc.vec.Vec (Option Spike.radix.RadixDir))
    (freeDirs' : alloc.vec.Vec Usize)
    (hbuild
      : Spike.radix.build_sorted dirs freeDirs rows sorted
        = Result.ok (resRoot, dirs', freeDirs'))
    (st : DirCountState dirs rows.val dirRefs rowRefs freeDirs pins)
    (hsortedLive
      : ∀ l ∈ sorted.val, SingleLinkLive dirs.val rows.val l ∧ ∀ q ∈ entries, q ≠ l)
    (hqZero
      : ∀ l ∈ entries,
          SingleLinkLive dirs.val rows.val l ∧ radixReferences dirs.val pins l = 0)
    (hrefRoom : pins.length + 17 * (dirs'.val.length + 1) ≤ U32.max)
    : WP.spec (Spike.radix.build_sorted_counted dirs dirRefs rowRefs freeDirs rows sorted)
        (fun (r2, d2, dr2, rr2, f2) =>
          r2 = resRoot
          ∧ d2 = dirs'
          ∧ f2 = freeDirs'
          ∧ DirCountState dirs' rows.val dr2 rr2 freeDirs' pins
          ∧ (resRoot ≠ 0#u32 → SingleLinkLive dirs'.val rows.val resRoot)
          ∧ (∀ l ∈ entries, l ≠ resRoot)
          ∧ (∀ l ∈ entries,
              SingleLinkLive dirs'.val rows.val l
              ∧ radixReferences dirs'.val pins l = 0)) := by
  have hbuildSpec : WP.spec (Spike.radix.build_sorted dirs freeDirs rows sorted)
      (· = (resRoot, dirs', freeDirs')) := by rw [hbuild, WP.spec_ok]
  unfold Spike.radix.build_sorted at hbuild hbuildSpec
  unfold Spike.radix.build_sorted_counted
  dsimp only at hbuild hbuildSpec ⊢
  by_cases h0 : Slice.len sorted = 0#usize
  · rw [ite_eq_left h0] at hbuild ⊢
    rw [Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq] at hbuild
    obtain ⟨rfl, rfl, rfl⟩ := hbuild
    rw [WP.spec_ok]
    exact ⟨rfl, rfl, rfl, st, fun h => (h rfl).elim,
      fun l hl h0 => single_link_live_ne_zero (hqZero l hl).1 h0, hqZero⟩
  · rw [ite_eq_right h0] at hbuild hbuildSpec ⊢
    by_cases h1 : Slice.len sorted = 1#usize
    · rw [ite_eq_left h1] at hbuild hbuildSpec ⊢
      cases hi : Slice.index_usize sorted 0#usize using Result.cases with
      | div => rw [hi] at hbuildSpec; simp at hbuildSpec
      | vis _ _ => rw [hi] at hbuildSpec; simp at hbuildSpec
      | ret comp =>
          change Slice.index_usize sorted 0#usize = Result.ok comp at hi
          have hmem := slice_index_usize_mem sorted 0#usize comp hi
          rw [hi, bind_ok] at hbuild
          simp only [bind_ok]
          rw [Result.ok.injEq, Prod.mk.injEq, Prod.mk.injEq] at hbuild
          obtain ⟨rfl, rfl, rfl⟩ := hbuild
          rw [WP.spec_ok]
          exact ⟨rfl, rfl, rfl, st, fun _ => (hsortedLive comp hmem).1,
            (hsortedLive comp hmem).2, hqZero⟩
    · rw [ite_eq_right h1] at hbuild hbuildSpec ⊢
      cases hfr0 : Spike.radix.sorted_frame rows sorted 0#usize (Slice.len sorted) 0#usize
        using Result.cases with
      | div => rw [hfr0] at hbuildSpec; simp at hbuildSpec
      | vis _ _ => rw [hfr0] at hbuildSpec; simp at hbuildSpec
      | ret frame0 =>
          change Spike.radix.sorted_frame rows sorted 0#usize (Slice.len sorted) 0#usize = Result.ok frame0 at hfr0
          have hfr0Empty := sorted_frame_empty_children rows sorted 0#usize (Slice.len sorted) 0#usize frame0 hfr0
          rw [hfr0, bind_ok] at hbuild
          simp only [bind_ok]
          have hloopRun := hbuild
          unfold Spike.radix.build_sorted_loop at hbuild
          unfold Spike.radix.build_sorted_counted_loop
          let FrameOk (d : List (Option Spike.radix.RadixDir)) (fr : Spike.radix.BuildFrame) : Prop :=
            ∀ c ∈ fr.dir.children.val, (c ≠ 0#u32 → SingleLinkLive d rows.val c) ∧ ∀ l ∈ entries, l ≠ c
          let rel :
              (alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec Usize ×
                alloc.vec.Vec Spike.radix.BuildFrame × Spike.radix.BuildFrame) →
              (alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec U32 × alloc.vec.Vec U32 ×
                alloc.vec.Vec Usize × alloc.vec.Vec Spike.radix.BuildFrame × Spike.radix.BuildFrame) → Prop :=
            fun (d1, f1, ps1, fr1) (d2, dr2, rr2, f2, ps2, fr2) =>
              d2 = d1 ∧ f2 = f1 ∧ ps2 = ps1 ∧ fr2 = fr1
              ∧ DirCountState d1 rows.val dr2 rr2 f1 pins
              ∧ (∀ p ∈ ps1.val, FrameOk d1.val p)
              ∧ FrameOk d1.val fr1
              ∧ (∀ l ∈ entries, SingleLinkLive d1.val rows.val l ∧ radixReferences d1.val pins l = 0)
              ∧ Spike.radix.build_sorted_loop d1 f1 rows sorted ps1 fr1 = Result.ok (resRoot, dirs', freeDirs')
              ∧ (∀ l, SingleLinkLive dirs.val rows.val l → SingleLinkLive d1.val rows.val l)
          let post :
              (U32 × alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec Usize) →
              (U32 × alloc.vec.Vec (Option Spike.radix.RadixDir) × alloc.vec.Vec U32 ×
                alloc.vec.Vec U32 × alloc.vec.Vec Usize) → Prop :=
            fun (r1, d1, f1) (r2, d2, dr2, rr2, f2) =>
              r2 = r1 ∧ d2 = d1 ∧ f2 = f1
              ∧ DirCountState d1 rows.val dr2 rr2 f1 pins
              ∧ (r1 ≠ 0#u32 → SingleLinkLive d1.val rows.val r1)
              ∧ (∀ l ∈ entries, l ≠ r1)
              ∧ (∀ l ∈ entries, SingleLinkLive d1.val rows.val l ∧ radixReferences d1.val pins l = 0)
          apply loop_lockstep
            (fun (d1, f1, ps1, fr1) =>
              Spike.radix.build_sorted_loop.body rows sorted d1 f1 ps1 fr1)
            (fun (d2, dr2, rr2, f2, ps2, fr2) =>
              Spike.radix.build_sorted_counted_loop.body rows sorted d2 dr2 rr2 f2 ps2
                fr2)
            rel post ?_ ?_ hbuild
          · rintro ⟨d1, f1, ps1, fr1⟩ ⟨d2, dr2, rr2, f2, ps2, fr2⟩
              ⟨rfl, rfl, rfl, rfl, st1, hps1, hfr1, hq1, hrem1, hkeep1⟩ r1 hb1
            dsimp only at hb1 ⊢
            have hlenCur : d2.val.length ≤ dirs'.val.length :=
              build_sorted_loop_len_mono rows sorted d2 f2 ps2 fr2 (resRoot, dirs', freeDirs') hrem1
            have hspec1 : WP.spec (Spike.radix.build_sorted_loop.body rows sorted d2 f2 ps2 fr2) (· = r1) := by
              rw [hb1, WP.spec_ok]
            have hremStep : (match r1 with
              | .done z => Result.ok z
              | .cont next => Spike.radix.build_sorted_loop next.1 next.2.1 rows sorted next.2.2.1 next.2.2.2) =
                Result.ok (resRoot, dirs', freeDirs') := by
              unfold Spike.radix.build_sorted_loop at hrem1 ⊢
              rw [loop.eq_1] at hrem1
              dsimp only at hrem1
              rw [hb1, bind_ok] at hrem1
              cases r1 <;> exact hrem1
            unfold Spike.radix.build_sorted_loop.body at hb1 hspec1
            unfold Spike.radix.build_sorted_counted_loop.body
            by_cases hdone : fr2.cursor = fr2.end
            · rw [ite_eq_left hdone] at hb1 hspec1 ⊢
              cases hadd : Spike.radix.add_directory d2 f2 fr2.dir using Result.cases with
              | div => rw [hadd] at hspec1; simp at hspec1
              | vis _ _ => rw [hadd] at hspec1; simp at hspec1
              | ret ar =>
                  obtain ⟨comp, dNext, fNext⟩ := ar
                  change Spike.radix.add_directory d2 f2 fr2.dir = Result.ok (comp, dNext, fNext) at hadd
                  rw [hadd, bind_ok] at hb1 hspec1
                  have hfrNotQ : ∀ l ∈ entries, fr2.dir.children.val.count l = 0 := by
                    intro l hl
                    rw [List.count_eq_zero]
                    intro hc
                    exact (hfr1 l hc).2 l hl rfl
                  apply WP.spec_bind
                    (add_directory_counted_lockstep d2 rows.val dr2 rr2 f2 fr2.dir pins
                      comp dNext fNext hadd st1 (fun c hc => (hfr1 c hc).1) (by omega))
                  rintro ⟨comp2, dNext2, drNext, rrNext, fNext2⟩
                    ⟨hcEq, hdEq, hfEq, st2, hcompLive, hcompFresh, _, _, hkeep2, hzero2⟩
                  subst comp2 dNext2 fNext2
                  have hq2 : ∀ l ∈ entries, SingleLinkLive dNext.val rows.val l
                      ∧ radixReferences dNext.val pins l = 0 :=
                    fun l hl => ⟨hkeep2 l (hq1 l hl).1, hzero2 l (hq1 l hl).2 (hfrNotQ l hl)⟩
                  have hcompNotQ : ∀ l ∈ entries, l ≠ comp :=
                    fun l hl heq => hcompFresh (heq ▸ (hq1 l hl).1)
                  change (do
                    let b ← alloc.vec.Vec.is_empty ps2
                    if b then Result.ok (ControlFlow.done (comp, dNext, fNext))
                    else do
                      let depth ← alloc.vec.Vec.len ps2 - 1#usize
                      let parent ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Spike.radix.BuildFrame) ps2 depth
                      let ps3 ← alloc.vec.Vec.resize Spike.radix.BuildFrame.Insts.CoreCloneClone ps2 depth fr2
                      let rd ← Spike.radix.RadixDir.set_child parent.dir fr2.parent_slot comp
                      Result.ok (ControlFlow.cont (dNext, fNext, ps3, { parent with dir := rd }))) = Result.ok r1 at hb1
                  change WP.spec (do
                    let b ← alloc.vec.Vec.is_empty ps2
                    if b then Result.ok (ControlFlow.done (comp, dNext, fNext))
                    else do
                      let depth ← alloc.vec.Vec.len ps2 - 1#usize
                      let parent ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Spike.radix.BuildFrame) ps2 depth
                      let ps3 ← alloc.vec.Vec.resize Spike.radix.BuildFrame.Insts.CoreCloneClone ps2 depth fr2
                      let rd ← Spike.radix.RadixDir.set_child parent.dir fr2.parent_slot comp
                      Result.ok (ControlFlow.cont (dNext, fNext, ps3, { parent with dir := rd }))) (· = r1) at hspec1
                  change WP.spec (do
                    let b ← alloc.vec.Vec.is_empty ps2
                    if b then Result.ok (ControlFlow.done (comp, dNext, drNext, rrNext, fNext))
                    else do
                      let depth ← alloc.vec.Vec.len ps2 - 1#usize
                      let parent ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice Spike.radix.BuildFrame) ps2 depth
                      let ps3 ← alloc.vec.Vec.resize Spike.radix.BuildFrame.Insts.CoreCloneClone ps2 depth fr2
                      let rd ← Spike.radix.RadixDir.set_child parent.dir fr2.parent_slot comp
                      Result.ok (ControlFlow.cont (dNext, drNext, rrNext, fNext, ps3, { parent with dir := rd }))) _
                  cases hemp : alloc.vec.Vec.is_empty ps2 using Result.cases with
                  | div => rw [hemp] at hspec1; simp at hspec1
                  | vis _ _ => rw [hemp] at hspec1; simp at hspec1
                  | ret b =>
                      change alloc.vec.Vec.is_empty ps2 = Result.ok b at hemp
                      rw [hemp, bind_ok] at hb1 hspec1
                      simp only [bind_ok]
                      cases b with
                      | true =>
                          simp only [ite_true, Result.ok.injEq] at hb1
                          subst hb1
                          simp only [ite_true, WP.spec_ok]
                          exact ⟨rfl, rfl, rfl, st2, fun _ => hcompLive, hcompNotQ, hq2⟩
                      | false =>
                          simp only [Bool.false_eq_true, ite_false] at hb1 hspec1 ⊢
                          cases hsub : alloc.vec.Vec.len ps2 - 1#usize
                            using Result.cases with
                          | div => rw [hsub] at hspec1; simp at hspec1
                          | vis _ _ => rw [hsub] at hspec1; simp at hspec1
                          | ret depth =>
                              change alloc.vec.Vec.len ps2 - 1#usize = Result.ok depth at hsub
                              rw [hsub, bind_ok] at hb1 hspec1
                              simp only [bind_ok]
                              cases hpar
                                    : alloc.vec.Vec.index
                                        (core.slice.index.SliceIndexUsizeSlice
                                          Spike.radix.BuildFrame)
                                        ps2 depth
                                using Result.cases with
                              | div => rw [hpar] at hspec1; simp at hspec1
                              | vis _ _ => rw [hpar] at hspec1; simp at hspec1
                              | ret parent =>
                                  change alloc.vec.Vec.index _ ps2 depth = Result.ok parent at hpar
                                  have hparMem := vec_index_mem ps2 depth parent hpar
                                  rw [hpar, bind_ok] at hb1 hspec1
                                  simp only [bind_ok]
                                  have hdepthLe : depth.val ≤ ps2.val.length := by
                                    have hlt : depth.val < ps2.val.length := by
                                      by_contra hge
                                      rw [alloc.vec.Vec.index_slice_index] at hpar
                                      unfold alloc.vec.Vec.index_usize at hpar
                                      have hnone : ps2.val[depth.val]? = none :=
                                        List.getElem?_eq_none (Nat.le_of_not_gt hge)
                                      simp [hnone] at hpar
                                    omega
                                  obtain ⟨ps3, hres, hresVal⟩ := wp_spec_exists
                                    (alloc.vec.Vec.resize_spec Spike.radix.BuildFrame.Insts.CoreCloneClone
                                      ps2 depth fr2 rfl)
                                  rw [hres, bind_ok] at hb1 hspec1 ⊢
                                  cases hset
                                        : Spike.radix.RadixDir.set_child parent.dir
                                            fr2.parent_slot comp
                                    using Result.cases with
                                  | div => rw [hset] at hspec1; simp at hspec1
                                  | vis _ _ => rw [hset] at hspec1; simp at hspec1
                                  | ret rd =>
                                      change Spike.radix.RadixDir.set_child parent.dir fr2.parent_slot comp = Result.ok rd at hset
                                      have hrdMem := set_child_children_mem parent.dir fr2.parent_slot comp rd hset
                                      rw [hset, bind_ok, Result.ok.injEq] at hb1
                                      subst hb1
                                      simp only [bind_ok, WP.spec_ok]
                                      have hps3Sub : ∀ p ∈ ps3.val, p ∈ ps2.val := by
                                        intro p hp
                                        rw [hresVal, List.resize, Nat.sub_eq_zero_of_le hdepthLe,
                                          List.replicate_zero, List.append_nil] at hp
                                        exact List.mem_of_mem_take hp
                                      refine ⟨
                                        rfl,
                                        rfl,
                                        rfl,
                                        rfl,
                                        st2,
                                        ?_,
                                        ?_,
                                        hq2,
                                        hremStep,
                                        fun l hl => hkeep2 l (hkeep1 l hl)
                                      ⟩
                                      · intro p hp c hc
                                        have := hps1 p (hps3Sub p hp) c hc
                                        exact ⟨fun hnz => hkeep2 c (this.1 hnz), this.2⟩
                                      · intro c hc
                                        rcases hrdMem c hc with rfl | hc0
                                        · exact ⟨fun _ => hcompLive, hcompNotQ⟩
                                        · have := hps1 parent hparMem c hc0
                                          exact ⟨fun hnz => hkeep2 c (this.1 hnz), this.2⟩
            · rw [ite_eq_right hdone] at hb1 hspec1 ⊢
              cases hi : Slice.index_usize sorted fr2.cursor using Result.cases with
              | div => rw [hi] at hspec1; simp at hspec1
              | vis _ _ => rw [hi] at hspec1; simp at hspec1
              | ret i =>
                  change Slice.index_usize sorted fr2.cursor = Result.ok i at hi
                  have hiMem := slice_index_usize_mem sorted fr2.cursor i hi
                  rw [hi, bind_ok] at hb1 hspec1
                  simp only [bind_ok]
                  cases hrr : Spike.radix.row_at rows i using Result.cases with
                  | div => rw [hrr] at hspec1; simp at hspec1
                  | vis _ _ => rw [hrr] at hspec1; simp at hspec1
                  | ret rr =>
                      change Spike.radix.row_at rows i = Result.ok rr at hrr
                      rw [hrr, bind_ok] at hb1 hspec1
                      simp only [bind_ok]
                      dsimp only at hb1 hspec1 ⊢
                      cases hsym
                            : Spike.radix.symbol (alloc.vec.Vec.deref rr.key)
                                fr2.dir.digit
                        using Result.cases with
                      | div => rw [hsym] at hspec1; simp at hspec1
                      | vis _ _ => rw [hsym] at hspec1; simp at hspec1
                      | ret slot =>
                          change Spike.radix.symbol _ fr2.dir.digit = Result.ok slot at hsym
                          rw [hsym, bind_ok] at hb1 hspec1
                          simp only [bind_ok]
                          cases hend
                                : Spike.radix.sorted_group_end rows sorted fr2.cursor
                                    fr2.end fr2.dir.digit slot
                            using Result.cases with
                          | div => rw [hend] at hspec1; simp at hspec1
                          | vis _ _ => rw [hend] at hspec1; simp at hspec1
                          | ret e =>
                              change Spike.radix.sorted_group_end rows sorted fr2.cursor fr2.end fr2.dir.digit slot = Result.ok e at hend
                              rw [hend, bind_ok] at hb1 hspec1
                              simp only [bind_ok]
                              cases hadd1 : fr2.cursor + 1#usize using Result.cases with
                              | div => rw [hadd1] at hspec1; simp at hspec1
                              | vis _ _ => rw [hadd1] at hspec1; simp at hspec1
                              | ret i1 =>
                                  change fr2.cursor + 1#usize = Result.ok i1 at hadd1
                                  rw [hadd1, bind_ok] at hb1 hspec1
                                  simp only [bind_ok]
                                  by_cases hsingle : e = i1
                                  · rw [ite_eq_left hsingle] at hb1 hspec1 ⊢
                                    cases hset
                                          : Spike.radix.RadixDir.set_child fr2.dir slot i
                                      using Result.cases with
                                    | div => rw [hset] at hspec1; simp at hspec1
                                    | vis _ _ => rw [hset] at hspec1; simp at hspec1
                                    | ret rd =>
                                        change Spike.radix.RadixDir.set_child fr2.dir slot i = Result.ok rd at hset
                                        have hrdMem := set_child_children_mem fr2.dir slot i rd hset
                                        rw [hset, bind_ok, Result.ok.injEq] at hb1
                                        subst hb1
                                        simp only [bind_ok, WP.spec_ok]
                                        refine ⟨rfl, rfl, rfl, rfl, st1, hps1, ?_, hq1, hremStep, hkeep1⟩
                                        intro c hc
                                        rcases hrdMem c hc with hci | hc0
                                        · rw [hci]
                                          exact ⟨fun _ => hkeep1 i (hsortedLive i hiMem).1, (hsortedLive i hiMem).2⟩
                                        · exact hfr1 c hc0
                                  · rw [ite_eq_right hsingle] at hb1 hspec1 ⊢
                                    cases hpush
                                          : alloc.vec.Vec.push ps2
                                              { fr2 with cursor := e }
                                      using Result.cases with
                                    | div => rw [hpush] at hspec1; simp at hspec1
                                    | vis _ _ => rw [hpush] at hspec1; simp at hspec1
                                    | ret ps3 =>
                                        change alloc.vec.Vec.push ps2 { fr2 with cursor := e } = Result.ok ps3 at hpush
                                        have hpushVal : ps3.val = ps2.val ++ [{ fr2 with cursor := e }] := by
                                          unfold alloc.vec.Vec.push at hpush
                                          dsimp only at hpush
                                          split at hpush
                                          · rw [Result.ok.injEq] at hpush
                                            rw [← hpush]
                                            simp [List.concat_eq_append]
                                          · exact absurd hpush (by simp [Result.fail])
                                        rw [hpush, bind_ok] at hb1 hspec1
                                        simp only [bind_ok]
                                        cases hfr
                                              : Spike.radix.sorted_frame rows sorted
                                                  fr2.cursor e slot
                                          using Result.cases with
                                        | div => rw [hfr] at hspec1; simp at hspec1
                                        | vis _ _ => rw [hfr] at hspec1; simp at hspec1
                                        | ret fr3 =>
                                            change Spike.radix.sorted_frame rows sorted fr2.cursor e slot = Result.ok fr3 at hfr
                                            have hfr3Empty := sorted_frame_empty_children rows sorted fr2.cursor e slot fr3 hfr
                                            rw [hfr, bind_ok, Result.ok.injEq] at hb1
                                            subst hb1
                                            simp only [bind_ok, WP.spec_ok]
                                            refine ⟨rfl, rfl, rfl, rfl, st1, ?_, ?_, hq1, hremStep, hkeep1⟩
                                            · intro p hp
                                              rw [hpushVal] at hp
                                              rcases List.mem_append.mp hp with old | newly
                                              · exact hps1 p old
                                              · rw [List.mem_singleton.mp newly]
                                                exact hfr1
                                            · intro c hc
                                              have hc0 := hfr3Empty c hc
                                              subst hc0
                                              exact ⟨fun h => (h rfl).elim,
                                                fun l hl h0 => single_link_live_ne_zero (hq1 l hl).1 h0⟩
          · refine ⟨rfl, rfl, rfl, rfl, st, (fun _ h => by cases h), ?_, hqZero, hloopRun, fun _ h => h⟩
            intro c hc
            have hc0 := hfr0Empty c hc
            subst hc0
            exact ⟨fun h => (h rfl).elim,
              fun l hl h0 => single_link_live_ne_zero (hqZero l hl).1 h0⟩

theorem single_publish_batch_leaves_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (lookup : Slice U32) (bindings : List (List U8 × U32)) (pins : List U32)
    (live : SingleLiveness arena pins)
    (lookupRows : BatchLeaves (alloc.vec.Vec.deref arena.values.rows) lookup bindings)
    (sorted : bindings.Pairwise radixKeyLt)
    (ceiling : Nat)
    (depth : ∀ entry ∈ bindings, 2 * entry.1.length ≤ ceiling)
    (keys : ∀ entry ∈ bindings, 2 * entry.1.length + 1 ≤ Usize.max)
    (room
      : arena.values.dirs.val.length + 2 * (bindings.length * (ceiling + 1)) < 2147483647)
    (leavesFresh
      : ∀ l ∈ lookup.val,
          SingleLinkLive arena.values.dirs.val arena.values.rows.val l
          ∧ ∀ q, RetirementQueueView arena.retired q → l ∉ q)
    (refRoom
      : pins.length
          + 17
            * (arena.values.dirs.val.length + 2 * (bindings.length * (ceiling + 1)) + 2)
          + 1
        ≤ U32.max)
    : WP.spec (Spike.radix.SingleRadix.publish_batch_leaves arena lookup)
        (fun (root, after) =>
          SingleView after root bindings
          ∧ singleBindings after bindings = singleBindings arena bindings
          ∧ SingleLiveness after (if root = 0#u32 then pins else root :: pins)
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaGrowth arena.values after.values
              (2 * (bindings.length * (ceiling + 1)) + 1) 0) := by
  obtain ⟨⟨root0, dirs', freeDirs'⟩, hbuildRun, hbuildPost⟩ := wp_spec_exists
    (build_sorted_refines arena.values.dirs arena.values.free_dirs
      (alloc.vec.Vec.deref arena.values.rows) lookup bindings lookupRows sorted ceiling
      depth keys room live.valid.dirs live.valid.directories
      (by simpa [alloc.vec.Vec.deref] using live.valid.knowledge))
  obtain ⟨hkeptDirs, hfreeDirs', hdirInv', hknow', htree', hdirsLen⟩ := hbuildPost
  have hvalidAfter : ArenaValid ⟨dirs', arena.values.rows, freeDirs', arena.values.free_rows, arena.values.path⟩ :=
    ⟨hfreeDirs', live.valid.rows, hdirInv', by simpa [alloc.vec.Vec.deref] using hknow'⟩
  obtain ⟨entries, hqv, hqnd, hqZero⟩ := live.queue
  have st0 : DirCountState arena.values.dirs arena.values.rows.val arena.dir_refs arena.row_refs
      arena.values.free_dirs pins :=
    ⟨live.valid.dirs, live.freeDirsNodup, live.dirsBound, live.pinsLive, live.childrenLive, live.counts⟩
  unfold Spike.radix.SingleRadix.publish_batch_leaves
  dsimp only
  apply WP.spec_bind
    (build_sorted_counted_lockstep arena.values.dirs
      (alloc.vec.Vec.deref arena.values.rows) arena.dir_refs arena.row_refs
      arena.values.free_dirs lookup pins entries root0 dirs' freeDirs' hbuildRun
      (by simpa [alloc.vec.Vec.deref] using st0)
      (fun l hl =>
        ⟨
          by simpa [alloc.vec.Vec.deref] using (leavesFresh l hl).1,
          fun q hq heq => (leavesFresh l hl).2 entries hqv (heq ▸ hq)
        ⟩)
      (by simpa [alloc.vec.Vec.deref] using hqZero) (by omega))
  rintro ⟨root2, d2, dr2, rr2, fd2⟩ ⟨hrEq, hdEq, hfEq, st2, hrootLive, hrootNotQ, hq2⟩
  subst root2 d2 fd2
  apply WP.spec_bind
    (single_liveness_retain_next dirs' arena.values.rows freeDirs' arena.values.free_rows
      arena.values.path arena.retired dr2 rr2 pins entries root0 hvalidAfter
      live.rowsBound live.freeRowsNodup (by simpa [alloc.vec.Vec.deref] using st2) hqv
      hqnd (by simpa [alloc.vec.Vec.deref] using hq2)
      (by simpa [alloc.vec.Vec.deref] using hrootLive) hrootNotQ (by omega))
  rintro ⟨dr3, rr3⟩ hlive'
  change WP.spec (Result.ok _) _
  rw [WP.spec_ok]
  refine ⟨
    ⟨⟨bindings.length, htree'⟩, ?_, sorted⟩,
    rfl,
    hlive',
    ⟨hkeptDirs, fun _ _ hr => hr⟩,
    ⟨hdirsLen, Nat.le_refl _⟩
  ⟩
  simpa [alloc.vec.Vec.deref] using lookupRows.2

theorem single_build_sorted_batch_refines {V : Type} (arena : Spike.radix.SingleRadix V)
    (input : alloc.vec.Vec (Option (Spike.radix.RadixRow V)))
    (rows : List (Spike.radix.RadixRow V)) (pins : List U32)
    (live : SingleLiveness arena pins)
    (owned : input.val = rows.map some)
    (sorted : rows.Pairwise fun a b => a.key.val < b.key.val)
    (ceiling : Nat)
    (depth : ∀ row ∈ rows, 2 * row.key.val.length ≤ ceiling)
    (keys : ∀ row ∈ rows, 2 * row.key.val.length + 1 ≤ Usize.max)
    (dirRoom
      : arena.values.dirs.val.length + 2 * (rows.length * (ceiling + 1)) < 2147483647)
    (rowRoom : arena.values.rows.val.length + rows.length ≤ 2147483647)
    (refRoom
      : pins.length
          + 17 * (arena.values.dirs.val.length + 2 * (rows.length * (ceiling + 1)) + 2)
          + 1
        ≤ U32.max)
    : WP.spec (Spike.radix.SingleRadix.build_sorted_batch arena input)
        (fun (root, after) =>
          SingleLiveness after (if root = 0#u32 then pins else root :: pins)
          ∧ ArenaKeeps arena.values after.values
          ∧ ArenaGrowth arena.values after.values (2 * (rows.length * (ceiling + 1)) + 1)
              rows.length
          ∧ ∃ bindings,
              SingleView after root bindings
              ∧ singleBindings after bindings
                = rows.map fun r => (r.key.val, r.value)) := by
  unfold Spike.radix.SingleRadix.build_sorted_batch
  have nVal : (alloc.vec.Vec.len input).val = rows.length := by
    change input.val.length = rows.length
    rw [owned, List.length_map]
  have nBound : rows.length ≤ Usize.max := by
    have := alloc.vec.Vec.len_ineq input
    rw [owned, List.length_map] at this
    exact this
  let cap := alloc.vec.Vec.with_capacity U32 (alloc.vec.Vec.len input)
  have hStage :
      WP.spec
        (Spike.radix.SingleRadix.build_sorted_batch_loop arena input (alloc.vec.Vec.len input)
          cap 0#usize)
        (fun (mid, lookup) =>
          SingleLiveness mid pins
          ∧ ArenaKeeps arena.values mid.values
          ∧ ArenaGrowth arena.values mid.values 0 rows.length
          ∧ mid.values.dirs = arena.values.dirs
          ∧ mid.retired = arena.retired
          ∧ (∀ l ∈ lookup.val,
              SingleLinkLive mid.values.dirs.val mid.values.rows.val l
              ∧ ¬ SingleLinkLive arena.values.dirs.val arena.values.rows.val l)
          ∧ ∃ bindings,
              BatchLeaves (alloc.vec.Vec.deref mid.values.rows) (alloc.vec.Vec.deref lookup) bindings
              ∧ bindings.map Prod.fst = rows.map (fun r => r.key.val)
              ∧ singleBindings mid bindings = rows.map (fun r => (r.key.val, r.value))) := by
    unfold Spike.radix.SingleRadix.build_sorted_batch_loop
    apply loop.spec_decr_nat
      (fun (_, _, _, i) => rows.length - i.val)
      (fun (cur, rem, lookup, i) =>
        i.val ≤ rows.length
        ∧ SingleLiveness cur pins
        ∧ ArenaKeeps arena.values cur.values
        ∧ ArenaGrowth arena.values cur.values 0 i.val
        ∧ cur.values.dirs = arena.values.dirs
        ∧ cur.retired = arena.retired
        ∧ (∀ l ∈ lookup.val,
            SingleLinkLive cur.values.dirs.val cur.values.rows.val l
            ∧ ¬ SingleLinkLive arena.values.dirs.val arena.values.rows.val l)
        ∧ rem.val.length = rows.length
        ∧ (∀ (j : Nat) (hj : j < rows.length),
            i.val ≤ j → rem.val[j]? = some (some rows[j]))
        ∧ ∃ bindings,
            BatchLeaves (alloc.vec.Vec.deref cur.values.rows) (alloc.vec.Vec.deref lookup)
              bindings
            ∧ bindings.map Prod.fst = (rows.take i.val).map (fun r => r.key.val)
            ∧ singleBindings cur bindings
              = (rows.take i.val).map (fun r => (r.key.val, r.value)))
      _ _ _
    · rintro ⟨cur, rem, lookup, i⟩
        ⟨hi, lCur, kCur, gCur, hDirs, hRet, hFresh, hRemLen, hRem, bindings, hLeaves, hKeys, hBind⟩
      dsimp only at hi lCur kCur gCur hDirs hRet hFresh hRemLen hRem hLeaves hKeys hBind ⊢
      unfold Spike.radix.SingleRadix.build_sorted_batch_loop.body
      by_cases run : i < alloc.vec.Vec.len input
      · have hilt : i.val < rows.length := by rwa [← nVal]
        have one : (1#usize : Usize).val = 1 := rfl
        rw [ite_eq_left run, alloc.vec.Vec.index_mut_slice_index]
        have hremI : rem.val[i.val]? = some (some rows[i.val]) := hRem i.val hilt (Nat.le_refl _)
        apply WP.spec_bind
          (alloc.vec.Vec.index_mut_usize_spec rem i
            (by change i.val < rem.val.length; omega))
        rintro ⟨opt, back⟩ ⟨hopt, hback⟩
        have hoptEq : opt = some rows[i.val] := by
          have := List.getElem?_eq_getElem (by omega : i.val < rem.val.length)
          rw [hremI] at this
          exact hopt.trans (Option.some.inj this.symm)
        rw [hoptEq]
        simp only [core.option.Option.take]
        have hRowRoomCur : cur.values.rows.val.length < 2147483647 := by
          have := gCur.2; omega
        apply WP.spec_bind
          (single_stage_batch_leaf_refines cur rows[i.val] pins lCur hRowRoomCur)
        rintro ⟨leaf, next⟩ ⟨lNext, kNext, gNext, hDirsNext, hRetNext, hTag, hLeafLive, hLeafNotCur, hSaved⟩
        have hKeepLive : ∀ l, SingleLinkLive cur.values.dirs.val cur.values.rows.val l →
            SingleLinkLive next.values.dirs.val next.values.rows.val l := by
          intro l hl
          unfold SingleLinkLive at hl ⊢
          by_cases ht : l < 2147483648#u32
          · simp only [ht, ite_true] at hl ⊢
            obtain ⟨hlp, d, hd⟩ := hl
            exact ⟨hlp, d, kNext.dirs _ d hd⟩
          · simp only [ht, ite_false] at hl ⊢
            obtain ⟨hlt, r, hr⟩ := hl
            exact ⟨hlt, r, kNext.rows _ r hr⟩
        have hKeepFromOrig : ∀ l, SingleLinkLive arena.values.dirs.val arena.values.rows.val l →
            SingleLinkLive cur.values.dirs.val cur.values.rows.val l := by
          intro l hl
          unfold SingleLinkLive at hl ⊢
          by_cases ht : l < 2147483648#u32
          · simp only [ht, ite_true] at hl ⊢
            obtain ⟨hlp, d, hd⟩ := hl
            exact ⟨hlp, d, kCur.dirs _ d hd⟩
          · simp only [ht, ite_false] at hl ⊢
            obtain ⟨hlt, r, hr⟩ := hl
            exact ⟨hlt, r, kCur.rows _ r hr⟩
        have hLookLen : lookup.val.length = i.val := by
          have := hLeaves.1
          have hl : bindings.length = i.val := by
            have := congrArg List.length hKeys
            simpa [List.length_map, List.length_take, Nat.min_eq_left hi] using this
          simpa [alloc.vec.Vec.deref, hl] using congrArg List.length this
        apply WP.spec_bind (alloc.vec.Vec.push_spec lookup leaf (by omega))
        intro lookup1 hpush
        apply WP.spec_bind (Usize.add_spec (x := i) (y := 1#usize) (by omega))
        intro j hj
        rw [WP.spec_ok, hback]
        dsimp only
        refine ⟨
          ⟨
            by omega,
            lNext,
            kCur.trans kNext,
            ⟨
              by have := gCur.1; have := gNext.1; omega,
              by have := gCur.2; have := gNext.2; omega
            ⟩,
            hDirsNext.trans hDirs,
            hRetNext.trans hRet,
            ?_,
            ?_,
            ?_,
            bindings ++ [(rows[i.val].key.val, leaf)],
            ?_,
            ?_,
            ?_
          ⟩,
          by omega
        ⟩
        · intro l hl
          rw [hpush] at hl
          rcases List.mem_append.mp hl with old | newly
          · exact ⟨hKeepLive l (hFresh l old).1, (hFresh l old).2⟩
          · rw [List.mem_singleton.mp newly]
            exact ⟨hLeafLive, fun h0 => hLeafNotCur (hKeepFromOrig leaf h0)⟩
        · simp [alloc.vec.Vec.set_val_eq, hRemLen]
        · intro k hk2 hk1
          rw [alloc.vec.Vec.set_val_eq, List.getElem?_set_ne (by omega : i.val ≠ k)]
          exact hRem k hk2 (by omega)
        · refine ⟨?_, ?_⟩
          · have hl : lookup.val = bindings.map Prod.snd := by
              simpa [alloc.vec.Vec.deref] using hLeaves.1
            simpa [alloc.vec.Vec.deref, hpush, List.map_append, List.map_singleton]
              using congrArg (· ++ [leaf]) hl
          · intro entry hm
            rcases List.mem_append.mp hm with old | newly
            · obtain ⟨t, r, hr, hk⟩ := hLeaves.2 entry old
              have hr' : radixRow cur.values.rows.val entry.2 = some r := by
                simpa [alloc.vec.Vec.deref] using hr
              exact ⟨
                t,
                r,
                by simpa [alloc.vec.Vec.deref] using radix_old_row _ _ kNext.rows _ _ hr',
                hk
              ⟩
            · rw [List.mem_singleton.mp newly]
              exact ⟨hTag, rows[i.val], by simpa [alloc.vec.Vec.deref] using hSaved, rfl⟩
        · rw [List.map_append, List.map_singleton, hKeys, show j.val = i.val + 1 by omega,
            List.take_add_one, List.getElem?_eq_getElem hilt, Option.toList_some, List.map_append,
            List.map_singleton]
        · have hOldBind : singleBindings next bindings = singleBindings cur bindings := by
            unfold singleBindings radixBindings
            apply List.filterMap_congr
            rintro ⟨k, l⟩ hm
            obtain ⟨_, r, hr, _⟩ := hLeaves.2 (k, l) hm
            have hr0 : radixRow cur.values.rows.val l = some r := by
              simpa [alloc.vec.Vec.deref] using hr
            have hr' := radix_old_row _ _ kNext.rows _ _ hr0
            dsimp only
            rw [hr0, hr']
          change radixBindings next.values.rows.val (bindings ++ [(rows[i.val].key.val, leaf)]) = _
          simp only [radixBindings, List.filterMap_append, List.filterMap_cons,
            List.filterMap_nil, hSaved, Option.map_some]
          change singleBindings next bindings ++ [(rows[i.val].key.val, rows[i.val].value)] = _
          rw [hOldBind, hBind, show j.val = i.val + 1 by omega, List.take_add_one,
            List.getElem?_eq_getElem hilt, Option.toList_some, List.map_append, List.map_singleton]
      · have hdone : i.val = rows.length := by
          have : ¬ i.val < (alloc.vec.Vec.len input).val := run
          omega
        rw [ite_eq_right run, WP.spec_ok]
        rw [hdone] at gCur hKeys hBind
        rw [List.take_length] at hKeys hBind
        exact ⟨lCur, kCur, gCur, hDirs, hRet, hFresh, bindings, hLeaves, hKeys, hBind⟩
    · refine ⟨Nat.zero_le _, live, .refl _, ⟨Nat.le_refl _, Nat.le_refl _⟩, rfl, rfl,
        fun _ h => by simp [cap, alloc.vec.Vec.with_capacity] at h,
        by simp [owned], ?_, [], ⟨by simp [cap, alloc.vec.Vec.with_capacity, alloc.vec.Vec.deref],
          (fun _ h => by cases h)⟩, by simp, by simp [singleBindings, radixBindings]⟩
      intro j hj _
      simp [owned, List.getElem?_eq_getElem hj]
  apply WP.spec_bind hStage
  rintro ⟨mid, lookup⟩ ⟨lMid, kMid, gMid, hDirs, hRet, hFresh, bindings, hLeaves, hKeys, hBind⟩
  have hSortedBind : bindings.Pairwise radixKeyLt := by
    have hMapPair : (bindings.map Prod.fst).Pairwise (· < ·) := by
      rw [hKeys]
      exact List.pairwise_map.mpr sorted
    exact List.pairwise_map.mp (hMapPair.imp (fun h => h)) |>.imp (fun h => (radixKeyLt_iff _ _).mpr h)
  have hDepthB : ∀ entry ∈ bindings, 2 * entry.1.length ≤ ceiling := by
    intro entry hm
    have hk : entry.1 ∈ rows.map (fun r => r.key.val) := hKeys ▸ List.mem_map_of_mem hm
    obtain ⟨r, hr, heq⟩ := List.mem_map.mp hk
    rw [← heq]
    exact depth r hr
  have hKeysB : ∀ entry ∈ bindings, 2 * entry.1.length + 1 ≤ Usize.max := by
    intro entry hm
    have hk : entry.1 ∈ rows.map (fun r => r.key.val) := hKeys ▸ List.mem_map_of_mem hm
    obtain ⟨r, hr, heq⟩ := List.mem_map.mp hk
    rw [← heq]
    exact keys r hr
  have hLenB : bindings.length = rows.length := by
    have := congrArg List.length hKeys
    simpa [List.length_map] using this
  obtain ⟨origQ, horigQV, _, horigZero⟩ := live.queue
  have hLeavesFresh : ∀ l ∈ (alloc.vec.Vec.deref lookup).val,
      SingleLinkLive mid.values.dirs.val mid.values.rows.val l
      ∧ ∀ q, RetirementQueueView mid.retired q → l ∉ q := by
    intro l hl
    have hl' : l ∈ lookup.val := by simpa [alloc.vec.Vec.deref] using hl
    refine ⟨(hFresh l hl').1, fun q hqv hmem => ?_⟩
    rw [hRet] at hqv
    have hqEq : q = origQ := by
      apply List.ext_getElem (hqv.size.symm.trans horigQV.size)
      intro j hj1 hj2
      have h1 := hqv.entry j hj1
      have h2 := horigQV.entry j hj2
      have h3 := h1.symm.trans h2
      rw [List.getElem?_eq_getElem hj1, List.getElem?_eq_getElem hj2] at h3
      exact Option.some.inj h3
    rw [hqEq] at hmem
    exact (hFresh l hl').2 (horigZero l hmem).1
  apply WP.spec_mono
    (single_publish_batch_leaves_refines mid
      (alloc.vec.Vec.deref lookup)
      bindings pins lMid hLeaves hSortedBind ceiling hDepthB hKeysB
      (by rw [hDirs, hLenB]; exact dirRoom)
      hLeavesFresh
      (by rw [hDirs, hLenB]; exact refRoom))
  rintro ⟨root, after⟩ ⟨hView, hBindAfter, lAfter, kAfter, gAfter⟩
  refine ⟨lAfter, kMid.trans kAfter, ⟨?_, ?_⟩, bindings, hView, hBindAfter.trans hBind⟩
  · have h1 := gAfter.1; rw [hDirs, hLenB] at h1; exact h1
  · have h1 := gMid.2; have h2 := gAfter.2; omega

end KvRust
