-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Model

@[expose] public section

namespace KvRust

open Kv.Model

/-- Observable results shared by the two-map Rust and Lean schedules. -/
structure Observation where
  /-- The waiting transaction reads before the writer applies. -/
  before : Option String
  /-- The writer reads from its own pending writes. -/
  own : Option String
  /-- The version assigned to the writer. -/
  version : Nat
  /-- The final committed cell in map A. -/
  a : Option (Cell String)
  /-- The final committed cell in map B. -/
  b : Option (Cell String)
deriving DecidableEq

/-- Run the schedule through the existing KV transitions, requiring the stale application to fail. -/
def modelRun (first second competing : String) : Option Observation := do
  let store := 0
  let stale := 0
  let writer := 1
  let a : Addr String String := ("a", "00")
  let b : Addr String String := ("b", "00")
  let w ← step {} (.storeCreate store 0)
  let w ← step w (.txCreate store stale)
  let w ← step w (.snapshot store stale)
  let w ← step w (.acquire store stale a.1)
  let (w, .value before) ← execute w (.operation store stale (.get a.1 a.2 false)) | none
  let w ← step w (.acquire store stale b.1)
  let w ← step w (.operation store stale (.write b.1 b.2 (some competing)))
  let w ← step w (.txCreate store writer)
  let w ← step w (.snapshot store writer)
  let w ← step w (.acquire store writer a.1)
  let w ← step w (.acquire store writer b.1)
  let w ← step w (.operation store writer (.write a.1 a.2 (some first)))
  let w ← step w (.operation store writer (.write b.1 b.2 (some second)))
  let (w, .value own) ← execute w (.operation store writer (.get b.1 b.2 false)) | none
  let w ← step w (.commitBegin store writer)
  let (w, .applied version _ _) ← execute w (.apply store writer) | none
  let w ← step w (.commitResult store writer .success)
  let w ← step w (.commitBegin store stale)
  if (execute w (.apply store stale)).isSome then
    none
  else
    let (w, .committed .conflict 0) ← execute w (.commitResult store stale .conflict)
    | none
    let s ← find w.stores store
    some { before, own, version, a := find s.head.data a, b := find s.head.data b }

end KvRust
