-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Extracted.Funs

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

end KvRust
