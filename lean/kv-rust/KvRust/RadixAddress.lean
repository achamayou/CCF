-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs
public import KvRust.Keys

import all Aeneas.Data.BitVec
import all Aeneas.Std.Alloc.Vec

@[expose] public section

namespace KvRust

open Aeneas.Std

def addressPrefix (n : Nat) : List U8 :=
  (BitVec.ofNat 64 n).toLEBytes.map (@UScalar.mk .U8)

/-- Byte-level separation of map and key for a shared radix. -/
def addressBytes (map key : List U8) : List U8 :=
  addressPrefix map.length ++ map ++ key

private theorem address_prefix_length (n : Nat) : (addressPrefix n).length = 8 := by
  simp [addressPrefix, BitVec.toLEBytes_length]

private theorem address_prefix_inj (a b : Nat) (ha : a < 2 ^ 64) (hb : b < 2 ^ 64)
    (same : addressPrefix a = addressPrefix b)
    : a = b := by
  have bytes := congrArg (List.map U8.bv) same
  have equal : (BitVec.ofNat 64 a).toLEBytes = (BitVec.ofNat 64 b).toLEBytes := by
    simpa [addressPrefix, List.map_map, Function.comp_def] using bytes
  have get (x : BitVec 64) : (BitVec.fromLEBytes x.toLEBytes).toNat = x.toNat := by
    rw [BitVec.fromLEBytes_toLEBytes (by decide)]
    simp
  have n : (BitVec.ofNat 64 a).toNat = (BitVec.ofNat 64 b).toNat := by
    rw [← get (BitVec.ofNat 64 a), ← get (BitVec.ofNat 64 b)]
    exact congrArg (fun bytes => (BitVec.fromLEBytes bytes).toNat) equal
  change a % 2 ^ 64 = b % 2 ^ 64 at n
  rwa [Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] at n

/-- Encoding addresses cannot alias an arbitrary map/key split or an empty half. -/
theorem address_bytes_injective (a b ka kb : List U8)
    (ha : a.length < 2 ^ 64) (hb : b.length < 2 ^ 64)
    (same : addressBytes a ka = addressBytes b kb)
    : a = b ∧ ka = kb := by
  have split (m k : List U8) : addressBytes m k = addressPrefix m.length ++ (m ++ k) := by
    simp [addressBytes, List.append_assoc]
  have take (m k : List U8) : (addressBytes m k).take 8 = addressPrefix m.length := by
    rw [split, ← address_prefix_length m.length, List.take_left]
  have prefixEq : addressPrefix a.length = addressPrefix b.length := by
    simpa only [take] using congrArg (List.take 8) same
  have len := address_prefix_inj a.length b.length ha hb prefixEq
  rw [split, split, prefixEq, List.append_cancel_left_eq] at same
  have head : a = b := by
    have taken := congrArg (List.take a.length) same
    rw [List.take_left, len, List.take_left] at taken
    exact taken
  subst b
  exact ⟨rfl, List.append_cancel_left same⟩

private theorem append_bytes (v : alloc.vec.Vec U8) (s : Slice U8)
    (room : v.val.length + s.val.length ≤ Usize.max)
    : WP.spec (alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s)
        (fun out => out.val = v.val ++ s.val) := by
  unfold alloc.vec.Vec.extend_from_slice
  have fit : v.length + s.length ≤ Usize.max := room
  rw [dite_eq_left fit]
  apply WP.spec_bind
    (List.clone_spec
      (by intros; rfl : ∀ b ∈ s.val, core.clone.CloneU8.clone b = Result.ok b))
  intro copy equal
  simp [equal]

/-- The extracted bulk-copy path computes exactly the address encoding. -/
theorem native_address_key (map key : Slice U8)
    (room : 8 + map.val.length + key.val.length ≤ Usize.max)
    : WP.spec (Spike.radix.address_key map key)
        (fun out => out.val = addressBytes map.val key.val) := by
  unfold Spike.radix.address_key
  let size := UScalar.cast .U64 (Slice.len map)
  have sizeVal : size.val = map.val.length := by
    unfold size
    rw [UScalar.cast_val_mod_pow_greater_numBits_eq .U64 (Slice.len map)
      (by
        simp only [UScalarTy.Usize_numBits_eq, UScalarTy.U64_numBits_eq]
        rcases System.Platform.numBits_eq with h | h <;> simp [h])]
    exact Slice.len_val _
  simp only [lift, bind_ok]
  let header := Array.to_slice (core.num.U64.to_le_bytes size)
  have hHeader : header.val = addressPrefix map.val.length := by
    rw [Array.val_to_slice]
    have bytes := core.num.U64.to_le_bytes.step_spec size
    simp only [lift, WP.spec_ok] at bytes
    have bitEq : size.bv = BitVec.ofNat 64 map.val.length := by
      apply BitVec.eq_of_toNat_eq
      change size.val = map.val.length % 2 ^ 64
      have small : map.val.length < 2 ^ 64 := by
        rw [← sizeVal]
        scalar_tac
      rw [Nat.mod_eq_of_lt small, sizeVal]
    rw [bytes]
    change size.bv.toLEBytes.map (@UScalar.mk .U8) = _
    rw [bitEq]
    rfl
  have ml : (Slice.len map).val = map.val.length := Slice.len_val _
  have kl : (Slice.len key).val = key.val.length := Slice.len_val _
  have eight : (8#usize : Usize).val = 8 := rfl
  apply WP.spec_bind (Usize.add_spec (x := 8#usize) (y := Slice.len map) (by omega))
  intro first hf
  apply WP.spec_bind (Usize.add_spec (x := first) (y := Slice.len key) (by omega))
  intro capacity _
  have hlen : header.val.length = 8 := hHeader ▸ address_prefix_length _
  apply WP.spec_bind
    (append_bytes (alloc.vec.Vec.with_capacity U8 capacity) header
      (by
        change 0 + header.val.length ≤ Usize.max
        omega))
  intro firstBytes hp
  have headerOnly : firstBytes.val = header.val := by
    simpa [alloc.vec.Vec.with_capacity] using hp
  apply WP.spec_bind (append_bytes firstBytes map (by rw [headerOnly, hlen]; omega))
  intro withMap hmm
  apply WP.spec_mono
    (append_bytes withMap key
      (by
        rw [hmm, List.length_append, headerOnly, hlen]
        exact room))
  intro out complete
  simpa [addressBytes, hmm, headerOnly, hHeader] using complete

private theorem compare_same_bytes (a : List U8) : byteOrder a a = 0#i8 := by
  induction a <;> simp [byteOrder, *]

private theorem compare_append_bytes (a b x y : List U8)
    (sameLength : a.length = b.length)
    : byteOrder (a ++ x) (b ++ y) = if a = b then byteOrder x y else byteOrder a b := by
  induction a generalizing b with
  | nil => cases b <;> simp_all
  | cons a rest ih =>
      cases b with
      | nil => simp at sameLength
      | cons b bs =>
          simp only [List.length_cons, Nat.succ.injEq] at sameLength
          by_cases lt : a < b
          · have diff : a ≠ b := ne_of_lt lt
            simp [byteOrder, lt, diff]
          · by_cases gt : b < a
            · have diff : a ≠ b := ne_of_gt gt
              simp [byteOrder, lt, gt, diff]
            · have eq : a = b := le_antisymm (le_of_not_gt gt) (le_of_not_gt lt)
              subst b
              simpa [byteOrder] using ih bs sameLength

private def beBytes {w : Nat} (x : BitVec w) : List U8 :=
  x.toBEBytes.map (@UScalar.mk .U8)

private theorem be_bytes_lt (w : Nat) (aligned : w % 8 = 0) (a b : BitVec w)
    (lt : a.toNat < b.toNat)
    : byteOrder (beBytes a) (beBytes b) = (-1)#i8 := by
  induction w using Nat.strong_induction_on with
  | ind w ih =>
      have atLeast : 8 ≤ w := by
        by_contra hn
        have zero : w = 0 := by omega
        subst w
        have ha := a.isLt
        have hb := b.isLt
        simp at ha hb
        omega
      let top (k : BitVec w) := (k >>> 8).setWidth (w - 8)
      let low (k : BitVec w) : U8 := UScalar.mk (k.setWidth 8)
      have split (k : BitVec w) : beBytes k = beBytes (top k) ++ [low k] := by
        unfold beBytes BitVec.toBEBytes
        rw [BitVec.toLEBytes, ite_eq_left (show 0 < w by omega)]
        simp [top, low, List.reverse_cons]
      have highVal (k : BitVec w) : (top k).toNat = k.toNat / 256 := by
        unfold top
        rw [BitVec.toNat_setWidth, Nat.mod_eq_of_lt (BitVec.toNat_ushiftRight_lt k 8 atLeast),
          BitVec.toNat_ushiftRight, Nat.shiftRight_eq_div_pow]
      have lowVal (k : BitVec w) : (low k).val = k.toNat % 256 := by
        change (k.setWidth 8).toNat = _
        rw [BitVec.toNat_setWidth]
      have sameLength : (beBytes (top a)).length = (beBytes (top b)).length := by
        simp [beBytes, BitVec.toBEBytes_length]
      rw [split a, split b, compare_append_bytes _ _ _ _ sameLength]
      by_cases high : (top a).toNat < (top b).toNat
      · have result := ih (w - 8) (by omega) (by omega) (top a) (top b) high
        have different : beBytes (top a) ≠ beBytes (top b) := by
          intro eq
          rw [eq, compare_same_bytes] at result
          contradiction
        simp [different, result]
      · have highEq : top a = top b := by
          apply BitVec.eq_of_toNat_eq
          rw [highVal, highVal] at high ⊢
          omega
        have bytesEq : beBytes (top a) = beBytes (top b) := congrArg beBytes highEq
        have lo : low a < low b := by
          change (low a).val < (low b).val
          rw [lowVal, lowVal]
          have eq := congrArg BitVec.toNat highEq
          rw [highVal, highVal] at eq
          omega
        simp [bytesEq, byteOrder, lo]

/-- The order key is fixed-width, complemented, big-endian stamp bytes. -/
def reverseStampBytes (stamp : U64) : List U8 :=
  (core.num.U64.to_be_bytes (~~~stamp)).val

theorem reverse_stamp_key_refines (stamp : U64)
    : WP.spec (Spike.radix.reverse_stamp_key stamp)
        (fun out => out.val = reverseStampBytes stamp) := by
  simp [Spike.radix.reverse_stamp_key, reverseStampBytes, lift, Array.val_to_slice]

/-- The latest stamp compares before every previously issued stamp. -/
theorem reverse_stamp_order (older newer : U64) (lt : older.val < newer.val)
    : byteOrder (reverseStampBytes newer) (reverseStampBytes older) = (-1)#i8 := by
  have header (stamp : U64) : reverseStampBytes stamp = beBytes ((~~~stamp : U64).bv) := by
    change (core.num.U64.to_be_bytes (~~~stamp)).val = _
    have bytes := core.num.U64.to_be_bytes.step_spec (~~~stamp)
    simpa [lift, beBytes] using bytes
  rw [header, header]
  apply be_bytes_lt 64 (by decide)
  change (~~~newer.bv).toNat < (~~~older.bv).toNat
  rw [BitVec.toNat_not, BitVec.toNat_not]
  change 2 ^ 64 - 1 - newer.val < 2 ^ 64 - 1 - older.val
  have bound : newer.val < 2 ^ 64 := by scalar_tac
  omega

theorem reverse_stamp_bytes_inj : Function.Injective reverseStampBytes := by
  intro a b same
  by_contra diff
  have values : a.val ≠ b.val := diff ∘ UScalar.eq_of_val_eq
  rcases Nat.lt_or_gt_of_ne values with lt | gt
  · have eq := reverse_stamp_order a b lt
    rw [same, compare_same_bytes] at eq
    contradiction
  · have eq := reverse_stamp_order b a gt
    rw [same, compare_same_bytes] at eq
    contradiction

end KvRust
