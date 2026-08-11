-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

set_option autoImplicit false

/-!
# Generic finite trace replay

This file is deliberately independent of the CCF consistency model. It supplies
the parts of implementation-trace validation that any state transition system
can reuse:

* `TraceDomain`, a finite enumeration of a domain. A concrete trace ranges over
  finitely many transactions, views, sequence numbers and events, so the
  quantifiers of a specification can be evaluated by walking that enumeration.
* `Decidable` instances for quantifiers over such a domain. These are what let
  a specification's guards be *evaluated* rather than restated: there is no
  hand-written Boolean mirror of a guard anywhere, so there is nothing to check
  a mirror against.
* `System`, the interface a specification implements to be replayable, and the
  deterministic replay function with its reachability theorems.

A specification supplies only the model-specific half: the guard of each
action, the transition it takes, and a proof that an enabled action preserves
reachability.

See `CCFConsistency/Trace.lean` for the CCF consistency instantiation.
-/

namespace TraceReplay

universe u v

/-- A domain small enough for a trace to enumerate. `complete` is what makes
evaluating a quantifier by walking `values` sound. -/
class TraceDomain (Alpha : Type u) where
  values : List Alpha
  complete : forall value, List.Mem value values

instance finTraceDomain (size : Nat) : TraceDomain (Fin size) where
  values := List.finRange size
  complete value := List.mem_finRange value

/-- Evaluate a universal quantifier by walking the domain. Higher priority than
Mathlib's `Fintype` instance so replay reduces through `List.all`. -/
instance (priority := 2000) decidableForallTraceDomain
    {Alpha : Type u}
    [TraceDomain Alpha]
    (predicate : Alpha -> Prop)
    [DecidablePred predicate] :
    Decidable (forall value, predicate value) :=
  decidable_of_iff
    (((TraceDomain.values : List Alpha).all fun value =>
      decide (predicate value)) = true)
    (by
      constructor
      · intro allTrue value
        exact
          of_decide_eq_true
            (List.all_eq_true.mp allTrue value (TraceDomain.complete value))
      · intro holds
        exact List.all_eq_true.mpr fun value _ => decide_eq_true (holds value))

/-- Evaluate an existential quantifier by walking the domain. -/
instance (priority := 2000) decidableExistsTraceDomain
    {Alpha : Type u}
    [TraceDomain Alpha]
    (predicate : Alpha -> Prop)
    [DecidablePred predicate] :
    Decidable (Exists predicate) :=
  decidable_of_iff
    (((TraceDomain.values : List Alpha).any fun value =>
      decide (predicate value)) = true)
    (by
      constructor
      · intro anyTrue
        cases List.any_eq_true.mp anyTrue with
        | intro value found =>
            exact Exists.intro value (of_decide_eq_true found.2)
      · intro existsValue
        cases existsValue with
        | intro value found =>
            exact
              List.any_eq_true.mpr
                (Exists.intro value
                  (And.intro (TraceDomain.complete value)
                    (decide_eq_true found))))

/-! ## Replayable systems -/

/-- What a specification must provide to be replayable against a trace.

`Enabled` is the guard, which must be decidable so a concrete trace can be
checked by evaluation; `next` is the transition taken when it holds; and
`preserves` is the single proof obligation tying the two to the
specification's own notion of reachability. -/
structure System (State : Type u) (Action : Type v) where
  Reachable : State -> Prop
  enabled : Action -> State -> Bool
  next : Action -> State -> State
  preserves :
    forall action state,
      Reachable state ->
        enabled action state = true ->
          Reachable (next action state)

variable {State : Type u} {Action : Type v}

/-- Deterministic replay. Returns `none` at the first action whose guard is
rejected, so a `some` result witnesses that every action was enabled. -/
def System.replay (system : System State Action) :
    List Action -> State -> Option State
  | [], state => some state
  | action :: remaining, state =>
      match system.enabled action state with
      | true => system.replay remaining (system.next action state)
      | false => none

theorem System.replay_reachable
    (system : System State Action)
    {actions : List Action}
    {state final : State}
    (reachable : system.Reachable state)
    (replayed : system.replay actions state = some final) :
    system.Reachable final := by
  induction actions generalizing state with
  | nil =>
      simp [System.replay] at replayed
      subst final
      exact reachable
  | cons action remaining inductionStep =>
      cases enabled : system.enabled action state with
      | false =>
          simp [System.replay, enabled] at replayed
      | true =>
          simp [System.replay, enabled] at replayed
          exact
            inductionStep
              (system.preserves action state reachable enabled)
              replayed

/-- A successful replay from a reachable start reaches a reachable state. This
is the theorem a generated trace module applies. -/
theorem System.replay_sound
    (system : System State Action)
    {actions : List Action}
    {start : State}
    (reachable : system.Reachable start)
    (success : (system.replay actions start).isSome) :
    Exists fun final =>
      system.replay actions start = some final /\ system.Reachable final := by
  cases Option.isSome_iff_exists.mp success with
  | intro final replayed =>
      exact
        Exists.intro final
          (And.intro replayed (system.replay_reachable reachable replayed))

end TraceReplay
