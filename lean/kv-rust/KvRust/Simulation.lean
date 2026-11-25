-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.AcquireRefinement
public import KvRust.ApplyRefinement
public import KvRust.Environment
public import KvRust.LifecycleRefinement
public import KvRust.OperateRefinement

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-- Translate every single-store native input into an action of the original model. -/
def modelAction (encode : List U8 → String) (sid : Nat) : Spike.engine.Action → Action
  | .Begin id => .txCreate sid id.val
  | .End id => .txEnd sid id.val
  | .SetTerm term => .setTerm sid term.val
  | .Snapshot id => .snapshot sid id.val
  | .Acquire id m => .acquire sid id.val (encode (alloc.vec.Vec.val m))
  | .Operate id m op => .operation sid id.val ((operationCase op).model encode m)
  | .CommitBegin id => .commitBegin sid id.val
  | .Apply id => .apply sid id.val
  | .CommitResult id outcome => .commitResult sid id.val (modelOutcome outcome)
  | .Compact cut => .compact sid cut.val
  | .Rollback cut term => .rollback sid cut.val term.val

/-- Exclude overflow of Rust counters and length arithmetic; the reference uses unbounded sizes. -/
def FitsAction (encode : List U8 → String) (sid : Nat)
    (n : Spike.engine.Store) (w : State)
    : Spike.engine.Action → Prop
  | .Begin id => find n.txs.val id = none → n.txs.val.length < Usize.max
  | .Acquire id _ => FitsAcquire n id
  | .Operate id m op => FitsOperate encode sid n w id m (operationCase op)
  | .Apply id => FitsApply n id
  | _ => True

/-- The extracted store takes the same enabled transitions on representable inputs,
returning identical observations except that scans and apply reports may permute their bindings.
A reference rejection leaves the native store unchanged. -/
theorem execute_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (order : PreservesByteOrder encode) (sid : Nat)
    (n : Spike.engine.Store) (w : State) (action : Spike.engine.Action)
    (rel : StateMatches encode sid n w) (room : FitsAction encode sid n w action)
    : WP.spec (Spike.engine.Store.execute n action)
        (StepMatches encode sid (modelAction encode sid action) n
          (execute w (modelAction encode sid action))) := by
  cases action with
  | Begin id => exact begin_step_matches encode sid n w id rel room
  | End id => exact end_step_matches encode sid n w id rel
  | SetTerm term => exact set_term_step_matches encode sid n w term rel
  | Snapshot id => exact snapshot_step_matches encode sid n w id rel
  | Acquire id m => exact acquire_step_matches encode inj sid n w id m rel room
  | Operate id m op =>
      have he : (operationCase op).rust = op := by cases op <;> rfl
      simpa only [modelAction, he]
        using operate_step_matches encode inj order sid n w id m (operationCase op) rel
          room
  | CommitBegin id => exact commit_begin_step_matches encode sid n w id rel
  | Apply id => exact apply_step_matches encode inj sid n w id rel room
  | CommitResult id result =>
      exact commit_result_step_matches encode sid n w id result rel
  | Compact cut => exact compact_step_matches encode sid n w cut rel
  | Rollback cut term => exact rollback_step_matches encode sid n w cut term rel

/-- Relate an optional action result modulo relaxed scan/apply ordering. -/
def OptionOutputMatches (action : Action) : Option Output → Option Output → Prop
  | none, none => True
  | some actual, some expected => OutputMatches action actual expected
  | _, _ => False

/-- Relate two complete trace output lists step by step against their input actions. -/
def TraceOutputsMatch (encode : List U8 → String) (sid : Nat)
    : List Spike.engine.Action → List (Option Output) → List (Option Output) → Prop
  | [], [], [] => True
  | a :: actions, x :: xs, y :: ys =>
      OptionOutputMatches (modelAction encode sid a) x y
      ∧ TraceOutputsMatch encode sid actions xs ys
  | _, _, _ => False

/-- Project an externally visible result, including the rejected-action marker. -/
def observeResult (encode : List U8 → String)
    : core.result.Result Spike.engine.Output Spike.engine.Error → Option Output
  | .Ok out => some (modelOutput encode out)
  | .Err _ => none

/-- An action rejected by the model is observed as `none` and does not advance it. -/
def modelNext (w : State) (result : Option (State × Output)) : State :=
  (result.map Prod.fst).getD w

/-- A sequence is in bounds when each requested transition can be represented.
This predicate does not assume that native steps succeed, or that their outputs or states agree. -/
def FitsTrace (encode : List U8 → String) (sid : Nat)
    : List Spike.engine.Action → Spike.engine.Store → State → Prop
  | [], _, _ => True
  | a :: rest, n, w =>
      FitsAction encode sid n w a
      ∧ ∀ r,
          Spike.engine.Store.execute n a = .ok r
          → FitsTrace encode sid rest r.2
              (modelNext w (execute w (modelAction encode sid a)))

/-- Fold the actual extracted dispatcher, retaining every action's visible result. -/
def runNative (encode : List U8 → String)
    : List Spike.engine.Action → Spike.engine.Store
      → Result (Spike.engine.Store × List (Option Output))
  | [], n => .ok (n, [])
  | a :: rest, n => do
      let (result, next) ← Spike.engine.Store.execute n a
      let (after, outputs) ← runNative encode rest next
      Result.ok (after, observeResult encode result :: outputs)

/-- Fold the original KV model over the same inputs. -/
def runReference (encode : List U8 → String) (sid : Nat)
    : List Spike.engine.Action → State → State × List (Option Output)
  | [], w => (w, [])
  | a :: rest, w =>
      let result := execute w (modelAction encode sid a)
      let (after, outputs) := runReference encode sid rest (modelNext w result)
      (after, result.map Prod.snd :: outputs)

private theorem returned {α : Type} {r : Result α} {p : α → Prop} (h : WP.spec r p)
    : ∃ v, r = .ok v ∧ p v := by
  cases r using Result.cases with
  | ret v => exact ⟨v, rfl, by simpa using h⟩
  | vis _ _ => simp at h
  | div => simp at h

/-- All finite in-bounds runs from related states return matching observations and end related. -/
theorem run_matches (encode : List U8 → String) (inj : Function.Injective encode)
    (order : PreservesByteOrder encode) (sid : Nat)
    (actions : List Spike.engine.Action) (n : Spike.engine.Store) (w : State)
    (rel : StateMatches encode sid n w) (room : FitsTrace encode sid actions n w)
    : WP.spec (runNative encode actions n)
        (fun (after, outputs) =>
          TraceOutputsMatch encode sid actions outputs
            (runReference encode sid actions w).2
          ∧ StateMatches encode sid after (runReference encode sid actions w).1) := by
  induction actions generalizing n w with
  | nil => simp [runNative, runReference, TraceOutputsMatch, rel]
  | cons a rest ih =>
      obtain ⟨fit, fitRest⟩ := room
      let obs := execute w (modelAction encode sid a)
      obtain ⟨⟨result, next⟩, he, hr⟩ :=
        returned (execute_matches encode inj order sid n w a rel fit)
      change StepMatches encode sid (modelAction encode sid a) n obs (result, next) at hr
      have hs
          : StateMatches encode sid next (modelNext w obs)
            ∧ OptionOutputMatches (modelAction encode sid a)
                (observeResult encode result) (obs.map Prod.snd) := by
        cases ho : obs with
        | none =>
            simp only [ho, StepMatches] at hr
            cases hr
            exact ⟨rel, trivial⟩
        | some pair =>
            obtain ⟨state, out⟩ := pair
            simp only [ho, StepMatches] at hr
            obtain ⟨nativeOut, hret, hobs, hrel⟩ := hr
            exact ⟨hrel, by simpa [hret, observeResult, OptionOutputMatches] using hobs⟩
      simp only [runNative, he, bind_ok]
      change WP.spec (do
        let (after, outputs) ← runNative encode rest next
        Result.ok (after, observeResult encode result :: outputs)) _
      apply WP.spec_bind (ih next (modelNext w obs) hs.1 (fitRest _ he))
      rintro ⟨after, outputs⟩ ⟨hout, hrel⟩
      have hstep : runReference encode sid (a :: rest) w =
          ((runReference encode sid rest (modelNext w obs)).1,
            obs.map Prod.snd :: (runReference encode sid rest (modelNext w obs)).2) := by
        change (match runReference encode sid rest (modelNext w obs) with
          | (s, outs) => (s, obs.map Prod.snd :: outs)) = _
        cases runReference encode sid rest (modelNext w obs)
        rfl
      change WP.spec (Result.ok (after, observeResult encode result :: outputs)) _
      rw [WP.spec_ok, hstep]
      exact ⟨⟨hs.2, hout⟩, hrel⟩

/-- Construct a native store and run any finite in-bounds action trace against the original model. -/
theorem initialized_run_matches (sid : Nat) (term : U64)
    (actions : List Spike.engine.Action)
    : WP.spec (Spike.engine.Store.new term)
        (fun n =>
          ∃ w,
            execute {} (.storeCreate sid term.val) = some (w, .unit)
            ∧ (FitsTrace encodeBytes sid actions n w
                → WP.spec (runNative encodeBytes actions n)
                    (fun (after, outputs) =>
                      TraceOutputsMatch encodeBytes sid actions outputs
                        (runReference encodeBytes sid actions w).2
                      ∧ StateMatches encodeBytes sid after
                          (runReference encodeBytes sid actions w).1))) := by
  apply WP.spec_mono (new_matches encodeBytes sid term)
  intro n ⟨w, he, rel⟩
  exact ⟨w, he, run_matches encodeBytes encodeBytes_injective encodeBytes_preservesByteOrder sid actions n w rel⟩

end KvRust
