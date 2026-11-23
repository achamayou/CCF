-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Relation

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Capacity required for a live attempt to publish a new frame. -/
def FitsApply (n : Spike.engine.Store) (id : U64) : Prop :=
  ∀ t,
    find n.txs.val id = some t
    → ∀ prior head,
        n.history.activeFrames = prior ++ [head] → ApplyCapacity n.history head t

private def nativeCommitting : Spike.engine.Phase → Bool
  | .Committing => true
  | _ => false

private theorem apply_empty {encode : List U8 → String} {sid : Nat} {t : Spike.engine.Tx}
    {history : Spike.engine.History} {tx : Tx}
    (h : AttemptMatches encode sid history t tx)
    : tx.normal.writes.isEmpty = t.pending.val.isEmpty := by
  rw [← h.writes]
  simp [pointWrites, encodeWrites, byteWrites]

private theorem eligibility (encode : List U8 → String) (inj : Function.Injective encode)
    {sid : Nat} {s : Store} {n : Spike.engine.History}
    {tx : Tx} {t : Spike.engine.Tx} (hs : HistoryMatches encode n s)
    (ht : AttemptMatches encode sid n t tx) (prior : List Spike.engine.Frame)
    (head : Spike.engine.Frame) (hf : n.activeFrames = prior ++ [head])
    (hh : s.head = modelFrame encode head)
    : WP.spec (Spike.engine.Tx.can_apply t n) (fun r => r = canApply s tx) := by
  have hmeta : s.history.map onlyMetadata = modelFrames n (modelMetadata (encode ∘ alloc.vec.Vec.val)) := by
    simp only [hs.frames, modelFrames, List.map_map]
    apply List.map_congr_left
    intro f _
    rfl
  have hdeps : tx.normal.deps.reverse = t.deps.val.map (encodeDependency encode ∘ byteDependency) := by
    rw [← ht.deps, pointDeps, List.reverse_reverse]
  have hsnap : tx.snapshot.map Snapshot.term = t.snapshot.map (fun x => x.term.val) := by
    simpa only [snapshotCut, modelSnapshot, List.map_map, Option.map_map,
      Function.comp_def]
      using congrArg (Option.map Prod.snd) ht.snapshot
  exact can_apply_matches_model encode inj n t s tx prior head hf hmeta ht.stamps
    (congrArg Frame.data hh) hdeps hs.term hsnap ht.noSnapshot ht.unavailable hs.valid

/-- Local publication both takes the model's enabled transition and preserves the state relation.
Disabled publication leaves the store unchanged. -/
theorem apply_step_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (sid : Nat) (n : Spike.engine.Store) (w : State) (id : U64)
    (h : StateMatches encode sid n w) (room : FitsApply n id)
    : WP.spec (Spike.engine.Store.execute n (.Apply id))
        (StepMatches encode sid n (execute w (.apply sid id.val))) := by
  obtain ⟨s, hs, hhist⟩ := h.history
  obtain ⟨prior, head, hframes, hhead⟩ := hhist.split
  have bind_some {α β : Type} (x : α) (f : α → Option β) : (some x >>= f) = f x := rfl
  cases hn : find n.txs.val id with
  | none =>
      have hr := apply_rejected_keeps_store n id (by simp [hn])
      have hl : lookupTx w sid id.val = none := by
        simp [lookupTx, hs, h.lookup_missing hn]
      simp [hr, StepMatches, execute, hl]
  | some t =>
      obtain ⟨tx, hl, ht⟩ := h.lookup hs hn
      have hempty := apply_empty ht
      have he : execute w (.apply sid id.val) =
          if tx.phase != .committing || tx.normal.writes.isEmpty then none
          else
            if canApply s tx then
              let next := advance s tx.normal.writes
              some ({ w with stores := Kv.Model.set w.stores sid next
                             txs := Kv.Model.set w.txs id.val { tx with phase := .applied next.head.version } },
                .applied next.head.version s.term tx.normal.writes)
            else none := by
        simp only [execute, hl, bind_some, tryApply]
        split
        · rfl
        · split <;> rfl
      have hp : (tx.phase != .committing) = !nativeCommitting t.phase := by
        rw [ht.phase]
        cases t.phase <;> rfl
      have hp_eq : nativeCommitting t.phase = true ↔ t.phase = .Committing := by
        cases t.phase <;> simp [nativeCommitting]
      have hp_ne (hn : t.phase ≠ .Committing) : nativeCommitting t.phase = false :=
        Bool.eq_false_of_not_eq_true (hn ∘ hp_eq.mp)
      by_cases hPhase : t.phase = .Committing
      · by_cases hWrites : t.pending.val = []
        · have hr := apply_rejected_keeps_store n id (by
            intro other ho
            have : other = t := Option.some.inj (ho.symm.trans hn)
            subst other
            simp [hWrites])
          simp [hr, he, hempty, hWrites, StepMatches]
        · have hw : t.pending.val.isEmpty = false := by simpa using hWrites
          have heligible := eligibility encode inj hhist ht prior head hframes hhead
          by_cases ha : canApply s tx
          · have hw'
                : tx.normal.writes = encodeWrites encode (byteWrites t.pending.val) :=
              ht.writes.symm
            have hOk
                : WP.spec (Spike.engine.Tx.can_apply t n.history) (fun r => r = true) :=
              ha ▸ heligible
            apply WP.spec_mono
              (apply_accepted_matches_model encode inj n id t s prior head hn hPhase
                hWrites hOk hframes hhist.frames hhead hhist.term hhist.global
                hhist.identity (room t hn prior head hframes) hhist.valid)
            rintro ⟨observed, after⟩ ⟨version, writes, index, hout, hv, hterm, hreport, hhist', hg, hterm', hi, hidx, hr, hvalid, kept⟩
            let store := advance s tx.normal.writes
            let next := {tx with phase := .applied store.head.version}
            let w' : State := {w with stores := Kv.Model.set w.stores sid store
                                      txs := Kv.Model.set w.txs id.val next}
            have hstep
                : execute w (.apply sid id.val)
                  = some (w', .applied store.head.version s.term tx.normal.writes) := by
              simp [he, hp, hempty, hPhase, nativeCommitting, hw, ha, w', store, next]
            have reach := reachable_execute h.reachable hstep
            have hstore : find w'.stores sid = some store := by simp [w', find_set_key]
            have hrel : HistoryMatches encode after.history store :=
              history_related reach hstore
                (by simpa only [← hw', store] using hhist'.symm)
                (by simpa only [← hw', store] using hg.symm)
                (by simpa only [← hw', store] using hterm'.symm)
                (by simpa only [← hw', store] using hi.symm)
                hvalid
            have hv' : version.val = store.head.version := by
              simpa only [← hw', store] using hv
            have htx
                : AttemptMatches encode sid after.history {t with phase := .Applied version} next := by
              simpa only [next, modelPhase, hv']
                using (ht.withPhase (.Applied version)).withHistory kept
            have rel :=
              replace_attempt h id index t {t with phase := .Applied version} next hidx hr
                rfl ⟨store, hstore, hrel⟩ htx reach kept
            rw [hstep]
            exact ⟨
              .Applied version n.history.term writes,
              hout,
              by
                simp only [modelOutput, hv', hhist.term, hreport, ← hw'],
              rel
            ⟩
          · have haf : canApply s tx = false := Bool.eq_false_of_not_eq_true ha
            have hr := apply_rejected_keeps_store n id (by
              intro other ho
              have : other = t := Option.some.inj (ho.symm.trans hn)
              subst other
              intro _ _
              exact haf ▸ heligible)
            simp [hr, he, hp, hempty, hPhase, nativeCommitting, hw, ha, StepMatches]
      · have hr := apply_rejected_keeps_store n id (by
          intro other ho
          have : other = t := Option.some.inj (ho.symm.trans hn)
          subst other
          intro contradiction
          exact (hPhase contradiction).elim)
        simp [hr, he, hp, hp_ne hPhase, StepMatches]

end KvRust
