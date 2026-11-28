-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import KvRust.Backfill
public import KvRust.Detached
public import KvRust.History
public import KvRust.IndexedHistory
public import KvRust.KvIndex
public import KvRust.Lifecycle
public import KvRust.PinnedImage
public import KvRust.RadixSingleReclaim
public import KvRust.ReplayAndSnapshot

@[expose] public section

namespace KvRust

open Aeneas.Std
open Kv.Model

/-! ## Part 1: Verified Aeneas-Extracted Root-Pin and Snapshot-Stub Primitives

These four entry points in `src/rust/ccf-kv/src/engine.rs` are invoked by the C++
`RustStore::sync_hazards_locked()` synchronization pass under `ShardedRwLock::WriteGuard`.
We prove that each preserves `BranchValid`, `HistoryIndexValid`, `IndexLiveness`, and
`IndexPreservesPins` on all remaining pins. -/

private theorem indexPreservesPins_of_values_eq {V : Type}
    {before after : CcfKv.kv_index.AddressIndex V} {pins : List U32}
    (hvals : after.values = before.values)
    : IndexPreservesPins before after pins := by
  intro r _ bindings hview
  refine ⟨⟨?_, ?_, hview.sorted⟩, ?_⟩
  · rw [hvals]; exact hview.lookup
  · rw [hvals]; exact hview.values
  · simp [singleBindings, hvals]

private theorem indexView_of_preserves {V : Type}
    {before after : CcfKv.kv_index.AddressIndex V} {pins : List U32}
    (hpres : IndexPreservesPins before after pins)
    {r : U32} (hr : r ∈ pins) {rows : List (CcfKv.engine.Address × V)}
    (hview : IndexView before r rows)
    : IndexView after r rows := by
  obtain ⟨bindings, hsv, hsb⟩ := hview
  obtain ⟨hsv', hsb'⟩ := hpres r hr bindings hsv
  exact ⟨bindings, hsv', by rw [hsb', hsb]⟩

private theorem historyIndexValid_of_preserves
    {hBefore : CcfKv.engine.History} {ai : CellIndex}
    (hValid : HistoryIndexValid hBefore)
    (haiValid : IndexValid ai)
    (hpres : IndexPreservesPins hBefore.index ai (framePins hBefore.activeFrames))
    : HistoryIndexValid { hBefore with index := ai } := by
  refine ⟨haiValid, ?_, hValid.retainedEmpty⟩
  intro frame hframe
  change frame ∈ hBefore.activeFrames at hframe
  by_cases hz : frame.data = 0#u32
  · have hEmpty : IndexView ai frame.data [] := by
      rw [hz]
      exact ⟨[], ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩, rfl⟩
    exact index_rows_view ⟨[], hEmpty⟩
  · have hmem : frame.data ∈ framePins hBefore.activeFrames :=
      List.mem_filterMap.mpr ⟨frame, hframe, by simp [hz]⟩
    have hv := indexView_of_preserves hpres hmem (hValid.active frame hframe)
    exact index_rows_view ⟨_, hv⟩

/-- `Store::retain_root_raw` retains an additional reference on a root that is already
pinned in `storePins s ++ extraPins`, preserving all frame views and upgrading
`IndexLiveness` to include the extra pin. -/
theorem store_retain_root_raw_refines (s : CcfKv.engine.Store)
    (extraPins : List U32) (root : CcfKv.radix.RadixRoot)
    (valid : BranchValid s.history.log)
    (indexed : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (storePins s ++ extraPins))
    (hRootMem : root ≠ 0#u32 → root ∈ storePins s ++ extraPins)
    (hRoom
      : root ≠ 0#u32
        → radixReferences s.history.index.values.dirs.val (storePins s ++ extraPins) root
          < U32.max)
    : WP.spec (CcfKv.engine.Store.retain_root_raw s root)
        (fun after =>
          after.history.log = s.history.log
          ∧ after.history.retained = s.history.retained
          ∧ after.history.global = s.history.global
          ∧ after.history.term = s.history.term
          ∧ after.history.next_identity = s.history.next_identity
          ∧ after.history.reuse_compacted_images = s.history.reuse_compacted_images
          ∧ after.txs = s.txs
          ∧ after.recovery_views = s.recovery_views
          ∧ after.history.index.values = s.history.index.values
          ∧ BranchValid after.history.log
          ∧ HistoryIndexValid after.history
          ∧ IndexLiveness after.history.index
              (storePins after ++ (if root = 0#u32 then extraPins else root :: extraPins))
          ∧ IndexPreservesPins s.history.index after.history.index
              (storePins s ++ extraPins)) := by
  unfold CcfKv.engine.Store.retain_root_raw
  have hRootRef : root ≠ 0#u32 →
      SingleLinkLive s.history.index.values.dirs.val s.history.index.values.rows.val root
      ∧ radixReferences s.history.index.values.dirs.val (storePins s ++ extraPins) root > 0 := by
    intro hnz
    have hmem := hRootMem hnz
    refine ⟨live.pinsLive root hmem, ?_⟩
    rw [radixReferences_eq]
    exact List.count_pos_iff.mpr (List.mem_append_left _ hmem)
  apply WP.spec_bind
    (index_retain_root_refines s.history.index (storePins s ++ extraPins) root live
      hRootRef hRoom)
  intro ai ⟨hvals, haiLive⟩
  rw [WP.spec_ok]
  have hpres : IndexPreservesPins s.history.index ai (storePins s ++ extraPins) :=
    indexPreservesPins_of_values_eq hvals
  have hpresFrames : IndexPreservesPins s.history.index ai (framePins s.history.activeFrames) :=
    fun r hr => hpres r (List.mem_append_left _ (List.mem_append_left _ hr))
  have hperm :
      (if root = 0#u32 then storePins s ++ extraPins else root :: (storePins s ++ extraPins)).Perm
      (storePins s ++ (if root = 0#u32 then extraPins else root :: extraPins)) := by
    by_cases hz : root = 0#u32
    · simp [hz]
    · simp only [hz, ite_false]
      exact List.perm_middle.symm
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, hvals, valid,
    historyIndexValid_of_preserves indexed haiLive.valid hpresFrames,
    haiLive.perm hperm, hpres⟩

/-- `Store::release_root_raw` releases one copy of `root` from the external hazard pin
multiset, performs bounded reclamation via `retire_budget`, and preserves `BranchValid`,
`HistoryIndexValid`, `IndexLiveness`, and every view of every remaining pin. -/
theorem store_release_root_raw_refines (s : CcfKv.engine.Store)
    (restExtra : List U32) (root : CcfKv.radix.RadixRoot)
    (valid : BranchValid s.history.log)
    (indexed : HistoryIndexValid s.history)
    (live
      : IndexLiveness s.history.index
          (storePins s ++ (if root = 0#u32 then restExtra else root :: restExtra)))
    (queueRoom
      : 2
            * (s.history.index.values.dirs.val.length
                + s.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.release_root_raw s root)
        (fun after =>
          after.history.log = s.history.log
          ∧ after.history.retained = s.history.retained
          ∧ after.history.global = s.history.global
          ∧ after.history.term = s.history.term
          ∧ after.history.next_identity = s.history.next_identity
          ∧ after.history.reuse_compacted_images = s.history.reuse_compacted_images
          ∧ after.txs = s.txs
          ∧ after.recovery_views = s.recovery_views
          ∧ BranchValid after.history.log
          ∧ HistoryIndexValid after.history
          ∧ IndexLiveness after.history.index (storePins after ++ restExtra)
          ∧ IndexPreservesPins s.history.index after.history.index
              (storePins s ++ restExtra)) := by
  unfold CcfKv.engine.Store.release_root_raw
  have hpermIn :
      (storePins s ++ (if root = 0#u32 then restExtra else root :: restExtra)).Perm
      (if root = 0#u32 then storePins s ++ restExtra else root :: (storePins s ++ restExtra)) := by
    by_cases hz : root = 0#u32
    · simp [hz]
    · simp only [hz, ite_false]
      exact List.perm_middle
  apply WP.spec_bind
    (index_release_root_refines s.history.index (storePins s ++ restExtra) root
      (live.perm hpermIn) queueRoom)
  intro ai ⟨hvals, haiLive⟩
  have haiQueue : 2 * (ai.values.dirs.val.length + ai.values.rows.val.length) + 1 ≤ Usize.max := by
    rw [hvals]; exact queueRoom
  apply WP.spec_bind
    (index_retire_budget_refines ai (storePins s ++ restExtra) CcfKv.engine.RETIRE_BUDGET
      haiLive haiQueue)
  rintro ⟨_, ai1⟩ ⟨hai1Live, hai1Pres, _, _⟩
  change WP.spec (Result.ok _) _
  rw [WP.spec_ok]
  have hpresAll : IndexPreservesPins s.history.index ai1 (storePins s ++ restExtra) := by
    intro r hr bindings hview
    have hviewAi : SingleView ai r bindings ∧ singleBindings ai bindings = singleBindings s.history.index bindings :=
      indexPreservesPins_of_values_eq hvals r hr bindings hview
    obtain ⟨hsv1, hsb1⟩ := hai1Pres r hr bindings hviewAi.1
    exact ⟨hsv1, by rw [hsb1, hviewAi.2]⟩
  have hpresFrames : IndexPreservesPins s.history.index ai1 (framePins s.history.activeFrames) :=
    fun r hr => hpresAll r (List.mem_append_left _ (List.mem_append_left _ hr))
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, valid,
    historyIndexValid_of_preserves indexed hai1Live.valid hpresFrames,
    hai1Live, hpresAll⟩

private theorem txsPins_set_fresh_empty
    (rows : List (U64 × CcfKv.engine.Tx)) (id : U64) (t : CcfKv.engine.Tx)
    (hFresh : find rows id = none) (hEmpty : t.views.val = [])
    : txsPins (Kv.Model.set rows id t) = txsPins rows := by
  have herase : Kv.Model.erase rows id = rows := by
    unfold Kv.Model.erase
    apply List.filter_eq_self.mpr
    intro p hp
    have hne : p.1 ≠ id := by
      intro heq
      have hnot : ∀ (l : List (U64 × CcfKv.engine.Tx)),
          find l id = none → ∀ x ∈ l, x.1 ≠ id := by
        intro l
        induction l with
        | nil => intro _ x hx; cases hx
        | cons hd tl ih =>
            intro hf x hx
            simp only [find] at hf
            split at hf
            · cases hf
            · rcases List.mem_cons.mp hx with rfl | htl
              · assumption
              · exact ih hf x htl
      exact hnot rows hFresh p hp heq
    simp [hne]
  unfold Kv.Model.set
  rw [herase]
  simp [txsPins, txPins, hEmpty]

private theorem txsPins_erase_empty
    (rows : List (U64 × CcfKv.engine.Tx)) (id : U64)
    (hAllEmpty : ∀ tx, (id, tx) ∈ rows → tx.views.val = [])
    : txsPins (Kv.Model.erase rows id) = txsPins rows := by
  induction rows with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨k, tx⟩ := hd
      have htlEmpty : ∀ tx', (id, tx') ∈ tl → tx'.views.val = [] :=
        fun tx' hm => hAllEmpty tx' (List.mem_cons_of_mem _ hm)
      by_cases hk : k = id
      · subst hk
        have htxE : tx.views.val = [] := hAllEmpty tx List.mem_cons_self
        have hf : Kv.Model.erase ((k, tx) :: tl) k = Kv.Model.erase tl k := by
          simp [Kv.Model.erase]
        rw [hf, ih htlEmpty]
        simp [txsPins, txPins, htxE]
      · have hf : Kv.Model.erase ((k, tx) :: tl) id = (k, tx) :: Kv.Model.erase tl id := by
          simp [Kv.Model.erase, hk]
        rw [hf]
        change txPins tx ++ txsPins (Kv.Model.erase tl id) = txPins tx ++ txsPins tl
        rw [ih htlEmpty]

/-- `Store::pin_snapshot_stub` registers an empty-view snapshot stub at a fresh `id`
(matching `RustStore::next_hazard_pin_id++`), preserving `storePins`, `BranchValid`,
`HistoryIndexValid`, and `IndexLiveness`. -/
theorem store_pin_snapshot_stub_refines (s : CcfKv.engine.Store)
    (extraPins : List U32) (id : U64) (version : U64)
    (hFresh : find s.txs.val id = none)
    (hRoom : s.txs.val.length < Usize.max)
    (valid : BranchValid s.history.log)
    (indexed : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (storePins s ++ extraPins))
    : WP.spec (CcfKv.engine.Store.pin_snapshot_stub s id version)
        (fun after =>
          after.history = s.history
          ∧ after.recovery_views = s.recovery_views
          ∧ after.txs.val
            = Kv.Model.set s.txs.val id
                {
                  lifecycleNewTx with
                    snapshot := some { version := version, term := s.history.term }
                }
          ∧ storePins after = storePins s
          ∧ BranchValid after.history.log
          ∧ HistoryIndexValid after.history
          ∧ IndexLiveness after.history.index (storePins after ++ extraPins)) := by
  unfold CcfKv.engine.Store.pin_snapshot_stub
  rw [tx_new_lifecycle, bind_ok]
  let stub : CcfKv.engine.Tx :=
    { lifecycleNewTx with snapshot := some { version := version, term := s.history.term } }
  have hSame : ∀ k : U64, CcfKv.U64.Insts.Ccf_kvEngineKey.same k id = Result.ok (decide (k = id)) := by
    intro k
    unfold CcfKv.U64.Insts.Ccf_kvEngineKey.same
    simp
  apply WP.spec_bind
    (assoc_set CcfKv.U64.Insts.Ccf_kvEngineKey core.clone.CloneU64
      CcfKv.engine.Tx.Insts.CoreCloneClone s.txs id stub hSame (fun _ => rfl) clone_tx
      hRoom)
  intro txs' htxs'
  rw [WP.spec_ok]
  have hStubEmpty : stub.views.val = [] := by
    simp [stub, lifecycleNewTx, alloc.vec.Vec.new]
  have hPinsEq : storePins { s with txs := txs' } = storePins s := by
    simp only [storePins, htxs']
    rw [txsPins_set_fresh_empty s.txs.val id stub hFresh hStubEmpty]
  refine ⟨rfl, rfl, htxs', hPinsEq, valid, indexed, ?_⟩
  rw [hPinsEq]
  exact live

/-- `Store::unpin_snapshot_stub` removes an empty-view snapshot stub at `id`, prunes
no-longer-needed retained metadata frames, runs `retire_budget`, and preserves
`BranchValid`, `HistoryIndexValid`, `IndexLiveness`, and all remaining pinned views. -/
theorem store_unpin_snapshot_stub_refines (s : CcfKv.engine.Store)
    (extraPins : List U32) (id : U64)
    (baseFrame : CcfKv.engine.Frame)
    (hbase0 : s.history.activeFrames[0]? = some baseFrame)
    (hAllEmpty : ∀ tx, (id, tx) ∈ s.txs.val → tx.views.val = [])
    (valid : BranchValid s.history.log)
    (indexed : HistoryIndexValid s.history)
    (live : IndexLiveness s.history.index (storePins s ++ extraPins))
    (queueRoom
      : 2
            * (s.history.index.values.dirs.val.length
                + s.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    : WP.spec (CcfKv.engine.Store.unpin_snapshot_stub s id)
        (fun after =>
          after.history.log = s.history.log
          ∧ after.history.global = s.history.global
          ∧ after.history.term = s.history.term
          ∧ after.history.next_identity = s.history.next_identity
          ∧ after.history.reuse_compacted_images = s.history.reuse_compacted_images
          ∧ after.txs.val = Kv.Model.erase s.txs.val id
          ∧ after.recovery_views = s.recovery_views
          ∧ storePins after = storePins s
          ∧ BranchValid after.history.log
          ∧ HistoryIndexValid after.history
          ∧ IndexLiveness after.history.index (storePins after ++ extraPins)
          ∧ IndexPreservesPins s.history.index after.history.index
              (storePins s ++ extraPins)) := by
  unfold CcfKv.engine.Store.unpin_snapshot_stub
  apply WP.spec_bind (erase_attempt_matches s.txs id)
  intro txs' htxs'
  apply WP.spec_bind
    (history_prune_retained_refines s.history txs' baseFrame hbase0 valid)
  rintro h1 ⟨hlog, hidx, hgl, htm, hid, hre, hretSub, _⟩
  have h1Queue : 2 * (h1.index.values.dirs.val.length + h1.index.values.rows.val.length) + 1
      ≤ Usize.max := by
    rw [hidx]; exact queueRoom
  have h1Live : IndexLiveness h1.index (storePins s ++ extraPins) := by
    rw [hidx]; exact live
  apply WP.spec_bind
    (index_retire_budget_refines h1.index (storePins s ++ extraPins)
      CcfKv.engine.RETIRE_BUDGET h1Live h1Queue)
  rintro ⟨_, ai⟩ ⟨haiLive, haiPres, _, _⟩
  change WP.spec (Result.ok _) _
  rw [WP.spec_ok]
  have hPinsEq :
      storePins { history := { h1 with index := ai }, txs := txs', recovery_views := s.recovery_views }
      = storePins s := by
    simp only [storePins, CcfKv.engine.History.activeFrames, hlog, htxs']
    rw [txsPins_erase_empty s.txs.val id hAllEmpty]
  have hPresS : IndexPreservesPins s.history.index ai (storePins s ++ extraPins) := by
    rw [← hidx]; exact haiPres
  have hPresFrames : IndexPreservesPins s.history.index ai (framePins s.history.activeFrames) :=
    fun r hr => hPresS r (List.mem_append_left _ (List.mem_append_left _ hr))
  have hHistValid : HistoryIndexValid { h1 with index := ai } := by
    refine ⟨haiLive.valid, ?_, ?_⟩
    · intro frame hframe
      change frame ∈ branchValues h1.log at hframe
      rw [hlog] at hframe
      by_cases hz : frame.data = 0#u32
      · have hEmpty : IndexView ai frame.data [] := by
          rw [hz]
          exact ⟨[], ⟨⟨0, .empty 0⟩, (fun _ h => by cases h), List.Pairwise.nil⟩, rfl⟩
        exact index_rows_view ⟨[], hEmpty⟩
      · have hmem : frame.data ∈ framePins s.history.activeFrames :=
          List.mem_filterMap.mpr ⟨frame, hframe, by simp [hz]⟩
        have hv := indexView_of_preserves hPresFrames hmem (indexed.active frame hframe)
        exact index_rows_view ⟨_, hv⟩
    · intro frame hframe
      exact indexed.retainedEmpty frame (hretSub frame hframe)
  refine ⟨hlog, hgl, htm, hid, hre, htxs', rfl, hPinsEq, ?_, hHistValid, ?_, hPresS⟩
  · rw [hlog]; exact valid
  · rw [hPinsEq]; exact haiLive

/-! ## Part 2: Formal Concurrent Protocol (`ShardedRwLock` + `HazardSlot` + `sync_hazards_locked`)

This transition system models the exact concurrency protocol implemented by
`ccf::kv::RustStore` in `src/kv/rust_kv_store_impl.h`:
- Multiple concurrent readers hold `ShardedRwLock::ReadGuard` (`lock = .readers n`, `n > 0`),
  execute `Store::snapshot_and_acquire_readonly` on their thread-private `DetachedTx`, and
  publish the resulting non-zero radix roots into their `HazardSlot` before dropping `ReadGuard`.
- Readers may drop their `HazardSlot` lock-free (`dropHazardReader`) in ANY lock state
  (including concurrently with an exclusive writer).
- Writers acquire `ShardedRwLock::WriteGuard` (`lock = .writer`, excluding all readers),
  run `sync_hazards_locked()` (`syncRetainRoot` / `syncReleaseRoot` / `syncPinSnapshot` /
  `syncUnpinSnapshot`, calling the Aeneas-extracted `Store` functions directly), and only
  after every currently published hazard root is retained in `hazardRetained` (`HazardsSynced`)
  perform a mutating `Store` transition (`mutateStoreSynced`).

We prove that every reachable concurrent state preserves `ConcInv`, which guarantees:
1. **Zero use-after-free**: every root held by any active hazard reader remains live in
   `store.history.index` across arbitrary concurrent commits, compactions, rollbacks,
   replays, backfills, and snapshot installations.
2. **Snapshot linearizability**: every root captured by an active hazard reader retains the
   exact `IndexView` (`indexRows`) it observed at snapshot acquisition time for the entire
   lifetime of the transaction. -/

/-- State of `ShardedRwLock`: unlocked, `n > 0` shared readers, or an exclusive writer. -/
inductive LockMode where
  | unlocked
  | readers (n : Nat)
  | writer
deriving DecidableEq

/-- An active thread-private reader holding a `HazardSlot` and a `DetachedTx`. -/
structure HazardReader where
  tx : CcfKv.engine.DetachedTx
  publishedRoots : List U32
  capturedViews : List (U32 × CellRows)

/-- Full concurrent state of `RustStore`: the Rust `Store`, `ShardedRwLock`, active
`HazardSlot` readers, and the `sync_hazards_locked()` tracking vectors. -/
structure ConcState where
  store : CcfKv.engine.Store
  lock : LockMode
  hazardReaders : List (Nat × HazardReader)
  hazardRetained : List U32
  hazardPinIds : List U64

/-- Every root currently published by any active `HazardSlot` is retained in `hazardRetained`.
This is the postcondition established by the retain pass of `sync_hazards_locked()`. -/
def HazardsSynced (cs : ConcState) : Prop :=
  ∀ slot hr,
    (slot, hr) ∈ cs.hazardReaders → ∀ r ∈ hr.publishedRoots, r ∈ cs.hazardRetained

/-- All non-zero roots currently published across all active `HazardSlot`s. -/
def anyHazardUses (readers : List (Nat × HazardReader)) (r : U32) : Prop :=
  ∃ slot hr, (slot, hr) ∈ readers ∧ r ∈ hr.publishedRoots

/-- Core invariant preserved by every concurrent interleaving of `RustStore`. -/
structure ConcInv (cs : ConcState) : Prop where
  branchValid : BranchValid cs.store.history.log
  histValid : HistoryIndexValid cs.store.history
  live : IndexLiveness cs.store.history.index (storePins cs.store ++ cs.hazardRetained)
  lockNonZero : ∀ n, cs.lock = .readers n → 0 < n
  retainedNz : ∀ r ∈ cs.hazardRetained, r ≠ 0#u32
  retainedNodup : cs.hazardRetained.Nodup
  stubsEmpty
    : ∀ id ∈ cs.hazardPinIds, ∀ tx, (id, tx) ∈ cs.store.txs.val → tx.views.val = []
  readersPublishedNz
    : ∀ slot hr, (slot, hr) ∈ cs.hazardReaders → ∀ r ∈ hr.publishedRoots, r ≠ 0#u32
  readersPublishedBacked
    : ∀ slot hr,
        (slot, hr) ∈ cs.hazardReaders
        → ∀ r ∈ hr.publishedRoots,
            r ∈ framePins cs.store.history.activeFrames ∨ r ∈ cs.hazardRetained
  readersTxCovered
    : ∀ slot hr,
        (slot, hr) ∈ cs.hazardReaders → ∀ r ∈ txPins hr.tx.tx, r ∈ hr.publishedRoots
  readersViewsExact
    : ∀ slot hr,
        (slot, hr) ∈ cs.hazardReaders
        → ∀ r rows,
            (r, rows) ∈ hr.capturedViews
            → r ∈ hr.publishedRoots ∧ IndexView cs.store.history.index r rows

/-- Remove the first occurrence of `x` from a `Nodup` list (mirrors swap-pop in
`hazard_retained_roots`). -/
def removeRoot (xs : List U32) (target : U32) : List U32 :=
  xs.filter (· != target)

private theorem removeRoot_perm_cons {xs : List U32} {r : U32}
    (hnd : xs.Nodup) (hmem : r ∈ xs)
    : xs.Perm (r :: removeRoot xs r) := by
  induction xs with
  | nil => cases hmem
  | cons hd tl ih =>
      rw [List.nodup_cons] at hnd
      obtain ⟨hNotIn, htlNd⟩ := hnd
      rcases List.mem_cons.mp hmem with rfl | htl
      · have hfilt : removeRoot (r :: tl) r = tl := by
          unfold removeRoot
          rw [List.filter_cons, bne_self_eq_false, ite_eq_right (by decide)]
          apply List.filter_eq_self.mpr
          intro x hx
          simp [ne_of_mem_of_not_mem hx hNotIn]
        rw [hfilt]
      · have hne : hd ≠ r := fun heq => hNotIn (heq ▸ htl)
        have hfilt : removeRoot (hd :: tl) r = hd :: removeRoot tl r := by
          unfold removeRoot
          rw [List.filter_cons, show (hd != r) = true from by simp [hne], ite_eq_left rfl]
        rw [hfilt]
        exact ((ih htlNd htl).cons hd).trans (List.Perm.swap r hd (removeRoot tl r))

private theorem removeRoot_nodup {xs : List U32} (r : U32) (hnd : xs.Nodup)
    : (removeRoot xs r).Nodup :=
  hnd.filter _

private theorem mem_removeRoot {xs : List U32} {r x : U32}
    : x ∈ removeRoot xs r ↔ x ∈ xs ∧ x ≠ r := by
  simp [removeRoot]

/-- Atomic concurrent transition relation for `RustStore`. -/
inductive ConcStep : ConcState → ConcState → Prop where
  /-- Acquire `ShardedRwLock::ReadGuard` from unlocked state. -/
  | acquireReadUnlocked (cs : ConcState) (hLock : cs.lock = .unlocked)
    : ConcStep cs { cs with lock := .readers 1 }

  /-- Acquire an additional concurrent `ShardedRwLock::ReadGuard`. -/
  | acquireReadMore (cs : ConcState) (n : Nat) (hLock : cs.lock = .readers n)
    : ConcStep cs { cs with lock := .readers (n + 1) }

  /-- Release one `ShardedRwLock::ReadGuard`. -/
  | releaseRead (cs : ConcState) (n : Nat) (hLock : cs.lock = .readers (n + 1))
    : ConcStep cs { cs with lock := if n = 0 then .unlocked else .readers n }

  /-- Acquire exclusive `ShardedRwLock::WriteGuard` (requires zero active readers). -/
  | acquireWrite (cs : ConcState) (hLock : cs.lock = .unlocked)
    : ConcStep cs { cs with lock := .writer }

  /-- Release exclusive `ShardedRwLock::WriteGuard`. -/
  | releaseWrite (cs : ConcState) (hLock : cs.lock = .writer)
    : ConcStep cs { cs with lock := .unlocked }

  /-- Claim a fresh `HazardSlot` for a new empty `DetachedTx` (lock-free CAS on `claimed`). -/
  | claimHazardSlot (cs : ConcState) (slot : Nat) (tx : CcfKv.engine.DetachedTx)
    (hEmptyViews : tx.tx.views.val = [])
    : ConcStep cs
        {
          cs with
            hazardReaders :=
              (slot, { tx := tx, publishedRoots := [], capturedViews := [] })
              :: cs.hazardReaders
        }

  /-- While holding `ReadGuard`, run the Aeneas-extracted `Store::snapshot_and_acquire_readonly`
  on an active hazard reader's `DetachedTx` and publish the returned non-zero roots into its
  `HazardSlot` before releasing `ReadGuard`. -/
  | readSnapshotAndAcquire (cs : ConcState) (n : Nat)
    (slot : Nat) (hr : HazardReader) (before after : List (Nat × HazardReader))
    (map : CcfKv.engine.Bytes)
    (prior : List CcfKv.engine.Frame) (head baseFrame : CcfKv.engine.Frame)
    (res
      : core.result.Result
          (U64
            × U64
            × CcfKv.engine.Output
            × CcfKv.radix.RadixRoot
            × CcfKv.radix.RadixRoot)
          CcfKv.engine.Error)
    (tx' : CcfKv.engine.DetachedTx)
    (sv st : U64) (out : CcfKv.engine.Output) (r0 r1 : CcfKv.radix.RadixRoot)
    (hLock : cs.lock = .readers n)
    (hSplit : cs.hazardReaders = before ++ (slot, hr) :: after)
    (hFrames : cs.store.history.activeFrames = prior ++ [head])
    (hBase0 : cs.store.history.activeFrames[0]? = some baseFrame)
    (hBaseLeGlobal : baseFrame.version.val ≤ cs.store.history.global.val)
    (hRec : cs.store.recovery_views.val = [])
    (hActive : hr.tx.tx.phase = .Active)
    (hUnreg : hr.tx.registered = false)
    (hMissing : find hr.tx.tx.views.val map = none)
    (hViewRoom : hr.tx.tx.views.val.length < Usize.max)
    (hExec
      : CcfKv.engine.Store.snapshot_and_acquire_readonly cs.store hr.tx map
        = Result.ok (res, tx'))
    (hResOk : res = core.result.Result.Ok (sv, st, out, r0, r1))
    : ConcStep cs
        {
          cs with
            hazardReaders :=
              before
              ++ (
                    slot,
                    {
                      tx := tx'
                      publishedRoots := [r0, r1].filter (· != 0#u32) ++ hr.publishedRoots
                      capturedViews :=
                        ([r0, r1].filter (· != 0#u32)).map
                          (fun r => (r, indexRows cs.store.history.index r))
                        ++ hr.capturedViews
                    }
                  )
                  :: after
        }

  /-- Lock-free `release_hazard_slot`: a reader finishes and clears its `HazardSlot`.
  Permitted in ANY lock state (even concurrently with an exclusive writer). -/
  | dropHazardReader (cs : ConcState)
    (slot : Nat) (hr : HazardReader) (before after : List (Nat × HazardReader))
    (hSplit : cs.hazardReaders = before ++ (slot, hr) :: after)
    : ConcStep cs { cs with hazardReaders := before ++ after }

  /-- `sync_hazards_locked()` retain step (under `WriteGuard`): calls extracted
  `Store::retain_root_raw` for a root currently published in a `HazardSlot` and not yet
  in `hazardRetained`. -/
  | syncRetainRoot (cs : ConcState) (root : U32) (store' : CcfKv.engine.Store)
    (hLock : cs.lock = .writer)
    (hUsed : anyHazardUses cs.hazardReaders root)
    (hNotRetained : root ∉ cs.hazardRetained)
    (hRoom
      : root ≠ 0#u32
        → radixReferences cs.store.history.index.values.dirs.val
            (storePins cs.store ++ cs.hazardRetained) root
          < U32.max)
    (hExec : CcfKv.engine.Store.retain_root_raw cs.store root = Result.ok store')
    : ConcStep cs
        {
          cs with
            store := store'
            hazardRetained := root :: cs.hazardRetained
        }

  /-- `sync_hazards_locked()` release step (under `WriteGuard`): calls extracted
  `Store::release_root_raw` for a root in `hazardRetained` no longer referenced by ANY
  active `HazardSlot`. -/
  | syncReleaseRoot (cs : ConcState) (root : U32) (store' : CcfKv.engine.Store)
    (hLock : cs.lock = .writer)
    (hRetained : root ∈ cs.hazardRetained)
    (hUnused : ¬anyHazardUses cs.hazardReaders root)
    (hQueueRoom
      : 2
            * (cs.store.history.index.values.dirs.val.length
                + cs.store.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    (hExec : CcfKv.engine.Store.release_root_raw cs.store root = Result.ok store')
    : ConcStep cs
        {
          cs with
            store := store'
            hazardRetained := removeRoot cs.hazardRetained root
        }

  /-- `sync_hazards_locked()` snapshot-pin step (under `WriteGuard`): calls extracted
  `Store::pin_snapshot_stub` for a fresh pin ID. -/
  | syncPinSnapshot (cs : ConcState) (pinId version : U64) (store' : CcfKv.engine.Store)
    (hLock : cs.lock = .writer)
    (hFresh : find cs.store.txs.val pinId = none)
    (hRoom : cs.store.txs.val.length < Usize.max)
    (hExec
      : CcfKv.engine.Store.pin_snapshot_stub cs.store pinId version = Result.ok store')
    : ConcStep cs
        {
          cs with
            store := store'
            hazardPinIds := pinId :: cs.hazardPinIds
        }

  /-- `sync_hazards_locked()` snapshot-unpin step (under `WriteGuard`): calls extracted
  `Store::unpin_snapshot_stub` for a tracked snapshot stub pin ID. -/
  | syncUnpinSnapshot (cs : ConcState) (pinId : U64) (baseFrame : CcfKv.engine.Frame)
    (store' : CcfKv.engine.Store)
    (hLock : cs.lock = .writer)
    (hTracked : pinId ∈ cs.hazardPinIds)
    (hBase0 : cs.store.history.activeFrames[0]? = some baseFrame)
    (hQueueRoom
      : 2
            * (cs.store.history.index.values.dirs.val.length
                + cs.store.history.index.values.rows.val.length)
          + 1
        ≤ Usize.max)
    (hExec : CcfKv.engine.Store.unpin_snapshot_stub cs.store pinId = Result.ok store')
    : ConcStep cs
        {
          cs with
            store := store'
            hazardPinIds := cs.hazardPinIds.filter (· != pinId)
        }

  /-- Exclusive mutating `Store` transition (commit, compact, rollback, replay,
  `install_snapshot`, backfill, `promote_detached_tx`, `end_detached`, etc.) executed under
  `WriteGuard` AFTER `sync_hazards_locked()` has established `HazardsSynced cs`.
  Because every active hazard root is pinned in `cs.hazardRetained`, any transition
  preserving `IndexLiveness` with `extraPins := cs.hazardRetained` and `IndexPreservesPins`
  on `cs.hazardRetained` keeps every concurrent hazard reader live and exact. -/
  | mutateStoreSynced (cs : ConcState) (store' : CcfKv.engine.Store)
    (hLock : cs.lock = .writer)
    (hSynced : HazardsSynced cs)
    (hBranch : BranchValid store'.history.log)
    (hHist : HistoryIndexValid store'.history)
    (hLive : IndexLiveness store'.history.index (storePins store' ++ cs.hazardRetained))
    (hPres
      : IndexPreservesPins cs.store.history.index store'.history.index cs.hazardRetained)
    (hStubs : ∀ id ∈ cs.hazardPinIds, ∀ tx, (id, tx) ∈ store'.txs.val → tx.views.val = [])
    : ConcStep cs { cs with store := store' }

/-- Multi-step concurrent execution trace (arbitrary interleaving of reader/writer steps). -/
inductive ConcTrace : ConcState → ConcState → Prop where
  | refl (cs : ConcState) : ConcTrace cs cs
  | step {a b c : ConcState} : ConcStep a b → ConcTrace b c → ConcTrace a c

/-- Every concurrent step preserves `ConcInv`. -/
theorem conc_step_preserves_inv {cs cs' : ConcState}
    (hInv : ConcInv cs) (hStep : ConcStep cs cs')
    : ConcInv cs' := by
  cases hStep with
  | acquireReadUnlocked _ =>
      exact { hInv with lockNonZero := fun n hn => by cases hn; omega }
  | acquireReadMore n hLock =>
      exact { hInv with lockNonZero := fun m hm => by cases hm; omega }
  | releaseRead n _ =>
      refine { hInv with lockNonZero := ?_ }
      intro m hm
      by_cases hn : n = 0
      · simp [hn] at hm
      · simp only [hn, ite_false, LockMode.readers.injEq] at hm
        omega
  | acquireWrite _ =>
      exact { hInv with lockNonZero := fun _ h => by cases h }
  | releaseWrite _ =>
      exact { hInv with lockNonZero := fun _ h => by cases h }
  | claimHazardSlot slot tx hEmptyViews =>
      refine {
        hInv with
          readersPublishedNz := ?_
          readersPublishedBacked := ?_
          readersTxCovered := ?_
          readersViewsExact := ?_
      }
      · intro s hr hm r hrP
        rcases List.mem_cons.mp hm with hEq | hOld
        · cases hEq; cases hrP
        · exact hInv.readersPublishedNz s hr hOld r hrP
      · intro s hr hm r hrP
        rcases List.mem_cons.mp hm with hEq | hOld
        · cases hEq; cases hrP
        · exact hInv.readersPublishedBacked s hr hOld r hrP
      · intro s hr hm r hrT
        rcases List.mem_cons.mp hm with hEq | hOld
        · cases hEq
          simp [txPins, hEmptyViews] at hrT
        · exact hInv.readersTxCovered s hr hOld r hrT
      · intro s hr hm r rows hV
        rcases List.mem_cons.mp hm with hEq | hOld
        · cases hEq; cases hV
        · exact hInv.readersViewsExact s hr hOld r rows hV
  | readSnapshotAndAcquire n slot hr before after map prior head baseFrame
      res tx' sv st out r0 r1 hLock hSplit hFrames hBase0 hBaseLeGlobal hRec hActive hUnreg
      hMissing hViewRoom hExec hResOk =>
      have hSpec := snapshot_and_acquire_readonly_refines cs.store hr.tx map prior head baseFrame
        hFrames hBase0 hBaseLeGlobal hRec hActive hUnreg hMissing hViewRoom hInv.branchValid
      rw [hExec, WP.spec_ok, hResOk] at hSpec
      obtain ⟨_, _, _, _, _, _, hOut⟩ := hSpec
      have hOldMem : (slot, hr) ∈ cs.hazardReaders := by rw [hSplit]; simp
      -- Show every root in `newRoots := [r0, r1].filter (· != 0#u32)` is non-zero and in
      -- `framePins cs.store.history.activeFrames`, and `txPins tx'.tx ⊆ newRoots ++ hr.publishedRoots`.
      let newRoots := [r0, r1].filter (· != 0#u32)
      have hNewNz : ∀ r ∈ newRoots, r ≠ 0#u32 := by
        intro r hrM
        simp only [newRoots, List.mem_filter, bne_iff_ne] at hrM
        exact hrM.2
      have hNewInFrames : ∀ r ∈ newRoots, r ∈ framePins cs.store.history.activeFrames := by
        intro r hrM
        cases out with
        | Unavailable =>
            obtain ⟨hr0, hr1, _, _⟩ := hOut
            simp [newRoots, hr0, hr1] at hrM
        | Acquired locRev globRev =>
            obtain ⟨v, _, hPinsEq, _, hInFramesOrRet, _⟩ := hOut
            have hrV : r ∈ viewPins v := hPinsEq ▸ hrM
            obtain ⟨f, hfMem, hfData⟩ := hInFramesOrRet r hrV
            have hrNz : r ≠ 0#u32 := hNewNz r hrM
            rcases List.mem_append.mp hfMem with hfAct | hfRet
            · exact List.mem_filterMap.mpr ⟨f, hfAct, by simp [hfData, hrNz]⟩
            · have hfZero := hInv.histValid.retainedEmpty f hfRet
              exact absurd (hfData.symm.trans hfZero) hrNz
        | _ => exact False.elim hOut
      have hNewTxCov : ∀ r ∈ txPins tx'.tx, r ∈ newRoots ++ hr.publishedRoots := by
        intro r hrT
        cases out with
        | Unavailable =>
            obtain ⟨_, _, _, hViewsEq⟩ := hOut
            have hrOld : r ∈ txPins hr.tx.tx := by simpa [txPins, hViewsEq] using hrT
            exact List.mem_append_right _ (hInv.readersTxCovered slot hr hOldMem r hrOld)
        | Acquired locRev globRev =>
            obtain ⟨v, hViewsEq, hPinsEq, _, _, _⟩ := hOut
            simp only [txPins, hViewsEq, List.flatMap_cons, List.mem_append] at hrT
            rcases hrT with hrNew | hrErased
            · exact List.mem_append_left _ (by change r ∈ [r0, r1].filter (· != 0#u32); rwa [hPinsEq])
            · have hrOld : r ∈ txPins hr.tx.tx := by
                simp only [txPins, List.mem_flatMap] at hrErased ⊢
                obtain ⟨entry, hMemE, hInV⟩ := hrErased
                exact ⟨entry, (List.mem_filter.mp hMemE).1, hInV⟩
              exact List.mem_append_right _ (hInv.readersTxCovered slot hr hOldMem r hrOld)
        | _ => exact False.elim hOut
      refine {
        hInv with
          readersPublishedNz := ?_
          readersPublishedBacked := ?_
          readersTxCovered := ?_
          readersViewsExact := ?_
      }
      · intro s hr1 hm r hrP
        simp only [List.mem_append, List.mem_cons] at hm
        rcases hm with hBef | hEq | hAft
        · exact hInv.readersPublishedNz s hr1 (by rw [hSplit]; simp [hBef]) r hrP
        · obtain ⟨_, rfl⟩ := Prod.mk.inj hEq
          rcases List.mem_append.mp hrP with hNew | hOld
          · exact hNewNz r hNew
          · exact hInv.readersPublishedNz slot hr hOldMem r hOld
        · exact hInv.readersPublishedNz s hr1 (by rw [hSplit]; simp [hAft]) r hrP
      · intro s hr1 hm r hrP
        simp only [List.mem_append, List.mem_cons] at hm
        rcases hm with hBef | hEq | hAft
        · exact hInv.readersPublishedBacked s hr1 (by rw [hSplit]; simp [hBef]) r hrP
        · obtain ⟨_, rfl⟩ := Prod.mk.inj hEq
          rcases List.mem_append.mp hrP with hNew | hOld
          · exact Or.inl (hNewInFrames r hNew)
          · exact hInv.readersPublishedBacked slot hr hOldMem r hOld
        · exact hInv.readersPublishedBacked s hr1 (by rw [hSplit]; simp [hAft]) r hrP
      · intro s hr1 hm r hrT
        simp only [List.mem_append, List.mem_cons] at hm
        rcases hm with hBef | hEq | hAft
        · exact hInv.readersTxCovered s hr1 (by rw [hSplit]; simp [hBef]) r hrT
        · obtain ⟨_, rfl⟩ := Prod.mk.inj hEq
          exact hNewTxCov r hrT
        · exact hInv.readersTxCovered s hr1 (by rw [hSplit]; simp [hAft]) r hrT
      · intro s hr1 hm r rows hV
        simp only [List.mem_append, List.mem_cons] at hm
        rcases hm with hBef | hEq | hAft
        · exact hInv.readersViewsExact s hr1 (by rw [hSplit]; simp [hBef]) r rows hV
        · obtain ⟨_, rfl⟩ := Prod.mk.inj hEq
          rcases List.mem_append.mp hV with hNew | hOld
          · obtain ⟨r', hr'Mem, hPair⟩ := List.mem_map.mp hNew
            obtain ⟨rfl, rfl⟩ := Prod.mk.inj hPair
            refine ⟨List.mem_append_left _ hr'Mem, ?_⟩
            have hInF := hNewInFrames r' hr'Mem
            obtain ⟨f, hfMem, hfOpt⟩ := List.mem_filterMap.mp hInF
            have hfEq : f.data = r' := by
              by_cases hz : f.data = 0#u32
              · simp [hz] at hfOpt
              · simp only [hz, ite_false, Option.some.injEq] at hfOpt
                exact hfOpt
            rw [← hfEq]
            exact hInv.histValid.active f hfMem
          · obtain ⟨hPub, hView⟩ := hInv.readersViewsExact slot hr hOldMem r rows hOld
            exact ⟨List.mem_append_right _ hPub, hView⟩
        · exact hInv.readersViewsExact s hr1 (by rw [hSplit]; simp [hAft]) r rows hV
  | dropHazardReader slot hr before after hSplit =>
      have hSub : ∀ p ∈ before ++ after, p ∈ cs.hazardReaders := by
        intro p hp
        rw [hSplit]
        rcases List.mem_append.mp hp with hb | ha
        · exact List.mem_append_left _ hb
        · exact List.mem_append_right _ (List.mem_cons_of_mem _ ha)
      exact {
        hInv with
          readersPublishedNz := fun s hr1 hm => hInv.readersPublishedNz s hr1 (hSub _ hm)
          readersPublishedBacked :=
            fun s hr1 hm => hInv.readersPublishedBacked s hr1 (hSub _ hm)
          readersTxCovered := fun s hr1 hm => hInv.readersTxCovered s hr1 (hSub _ hm)
          readersViewsExact := fun s hr1 hm => hInv.readersViewsExact s hr1 (hSub _ hm)
      }
  | syncRetainRoot root store' hLock hUsed hNotRetained hRoom hExec =>
      obtain ⟨slot, hr, hHrMem, hRootPub⟩ := hUsed
      have hRootNz : root ≠ 0#u32 := hInv.readersPublishedNz slot hr hHrMem root hRootPub
      have hRootInPins : root ∈ storePins cs.store ++ cs.hazardRetained := by
        rcases hInv.readersPublishedBacked slot hr hHrMem root hRootPub with hf | hret
        · exact List.mem_append_left _ (List.mem_append_left _ hf)
        · exact List.mem_append_right _ hret
      have hSpec := store_retain_root_raw_refines cs.store cs.hazardRetained root
        hInv.branchValid hInv.histValid hInv.live (fun _ => hRootInPins) hRoom
      rw [hExec, WP.spec_ok] at hSpec
      obtain ⟨hlog, _, _, _, _, _, htxs, _, _, hBranch', hHist', hLive', hPres⟩ := hSpec
      simp only [hRootNz, ite_false] at hLive'
      refine {
        branchValid := hBranch'
        histValid := hHist'
        live := hLive'
        lockNonZero := hInv.lockNonZero
        retainedNz :=
          fun r hr => by
            rcases List.mem_cons.mp hr with rfl | hOld
            · exact hRootNz
            · exact hInv.retainedNz r hOld
        retainedNodup := List.nodup_cons.mpr ⟨hNotRetained, hInv.retainedNodup⟩
        stubsEmpty :=
          fun id hId tx hMem => by
            rw [htxs] at hMem; exact hInv.stubsEmpty id hId tx hMem
        readersPublishedNz := hInv.readersPublishedNz
        readersPublishedBacked :=
          fun s hr1 hm r hrP => by
            rcases hInv.readersPublishedBacked s hr1 hm r hrP with hf | hret
            · exact Or.inl (by change r ∈ framePins (branchValues store'.history.log); rw [hlog]; exact hf)
            · exact Or.inr (List.mem_cons_of_mem _ hret)
        readersTxCovered := hInv.readersTxCovered
        readersViewsExact :=
          fun s hr1 hm r rows hV => by
            obtain ⟨hPub, hView⟩ := hInv.readersViewsExact s hr1 hm r rows hV
            have hrInPins : r ∈ storePins cs.store ++ cs.hazardRetained := by
              rcases hInv.readersPublishedBacked s hr1 hm r hPub with hf | hret
              · exact List.mem_append_left _ (List.mem_append_left _ hf)
              · exact List.mem_append_right _ hret
            exact ⟨hPub, indexView_of_preserves hPres hrInPins hView⟩
      }
  | syncReleaseRoot root store' hLock hRetained hUnused hQueueRoom hExec =>
      have hRootNz : root ≠ 0#u32 := hInv.retainedNz root hRetained
      have hPermRet : cs.hazardRetained.Perm (root :: removeRoot cs.hazardRetained root) :=
        removeRoot_perm_cons hInv.retainedNodup hRetained
      have hLiveIn :
          IndexLiveness cs.store.history.index
            (storePins cs.store ++ (if root = 0#u32 then removeRoot cs.hazardRetained root
              else root :: removeRoot cs.hazardRetained root)) := by
        simp only [hRootNz, ite_false]
        exact hInv.live.perm (List.Perm.append_left _ hPermRet)
      have hSpec := store_release_root_raw_refines cs.store (removeRoot cs.hazardRetained root)
        root hInv.branchValid hInv.histValid hLiveIn hQueueRoom
      rw [hExec, WP.spec_ok] at hSpec
      obtain ⟨hlog, _, _, _, _, _, htxs, _, hBranch', hHist', hLive', hPres⟩ := hSpec
      refine {
        branchValid := hBranch'
        histValid := hHist'
        live := hLive'
        lockNonZero := hInv.lockNonZero
        retainedNz := fun r hr => hInv.retainedNz r (mem_removeRoot.mp hr).1
        retainedNodup := removeRoot_nodup root hInv.retainedNodup
        stubsEmpty :=
          fun id hId tx hMem => by
            rw [htxs] at hMem; exact hInv.stubsEmpty id hId tx hMem
        readersPublishedNz := hInv.readersPublishedNz
        readersPublishedBacked :=
          fun s hr1 hm r hrP => by
            have hne : r ≠ root := fun heq => hUnused ⟨s, hr1, hm, heq ▸ hrP⟩
            rcases hInv.readersPublishedBacked s hr1 hm r hrP with hf | hret
            · exact Or.inl (by change r ∈ framePins (branchValues store'.history.log); rw [hlog]; exact hf)
            · exact Or.inr (mem_removeRoot.mpr ⟨hret, hne⟩)
        readersTxCovered := hInv.readersTxCovered
        readersViewsExact :=
          fun s hr1 hm r rows hV => by
            obtain ⟨hPub, hView⟩ := hInv.readersViewsExact s hr1 hm r rows hV
            have hne : r ≠ root := fun heq => hUnused ⟨s, hr1, hm, heq ▸ hPub⟩
            have hrInRem : r ∈ storePins cs.store ++ removeRoot cs.hazardRetained root := by
              rcases hInv.readersPublishedBacked s hr1 hm r hPub with hf | hret
              · exact List.mem_append_left _ (List.mem_append_left _ hf)
              · exact List.mem_append_right _ (mem_removeRoot.mpr ⟨hret, hne⟩)
            exact ⟨hPub, indexView_of_preserves hPres hrInRem hView⟩
      }
  | syncPinSnapshot pinId version store' hLock hFresh hRoom hExec =>
      have hSpec := store_pin_snapshot_stub_refines cs.store cs.hazardRetained pinId version
        hFresh hRoom hInv.branchValid hInv.histValid hInv.live
      rw [hExec, WP.spec_ok] at hSpec
      obtain ⟨hHistEq, _, hTxsEq, _, hBranch', hHist', hLive'⟩ := hSpec
      refine {
        branchValid := hBranch'
        histValid := hHist'
        live := hLive'
        lockNonZero := hInv.lockNonZero
        retainedNz := hInv.retainedNz
        retainedNodup := hInv.retainedNodup
        stubsEmpty :=
          fun id hId tx hMem => by
            rw [hTxsEq] at hMem
            simp only [Kv.Model.set, List.mem_cons, Prod.mk.injEq] at hMem
            rcases hMem with ⟨rfl, rfl⟩ | hErased
            · simp [lifecycleNewTx, alloc.vec.Vec.new]
            · have hInOld : (id, tx) ∈ cs.store.txs.val := (List.mem_filter.mp hErased).1
              rcases List.mem_cons.mp hId with rfl | hOldId
              · have hne := (List.mem_filter.mp hErased).2
                simp at hne
              · exact hInv.stubsEmpty id hOldId tx hInOld
        readersPublishedNz := hInv.readersPublishedNz
        readersPublishedBacked := by rw [hHistEq]; exact hInv.readersPublishedBacked
        readersTxCovered := hInv.readersTxCovered
        readersViewsExact := by rw [hHistEq]; exact hInv.readersViewsExact
      }
  | syncUnpinSnapshot pinId baseFrame store' hLock hTracked hBase0 hQueueRoom hExec =>
      have hAllEmpty : ∀ tx, (pinId, tx) ∈ cs.store.txs.val → tx.views.val = [] :=
        fun tx hm => hInv.stubsEmpty pinId hTracked tx hm
      have hSpec := store_unpin_snapshot_stub_refines cs.store cs.hazardRetained pinId baseFrame
        hBase0 hAllEmpty hInv.branchValid hInv.histValid hInv.live hQueueRoom
      rw [hExec, WP.spec_ok] at hSpec
      obtain ⟨hlog, _, _, _, _, hTxsEq, _, _, hBranch', hHist', hLive', hPres⟩ := hSpec
      refine {
        branchValid := hBranch'
        histValid := hHist'
        live := hLive'
        lockNonZero := hInv.lockNonZero
        retainedNz := hInv.retainedNz
        retainedNodup := hInv.retainedNodup
        stubsEmpty :=
          fun id hId tx hMem => by
            have hOldId : id ∈ cs.hazardPinIds := (List.mem_filter.mp hId).1
            rw [hTxsEq] at hMem
            have hOldMem : (id, tx) ∈ cs.store.txs.val := (List.mem_filter.mp hMem).1
            exact hInv.stubsEmpty id hOldId tx hOldMem
        readersPublishedNz := hInv.readersPublishedNz
        readersPublishedBacked :=
          fun s hr1 hm r hrP => by
            rcases hInv.readersPublishedBacked s hr1 hm r hrP with hf | hret
            · exact Or.inl (by change r ∈ framePins (branchValues store'.history.log); rw [hlog]; exact hf)
            · exact Or.inr hret
        readersTxCovered := hInv.readersTxCovered
        readersViewsExact :=
          fun s hr1 hm r rows hV => by
            obtain ⟨hPub, hView⟩ := hInv.readersViewsExact s hr1 hm r rows hV
            have hrInPins : r ∈ storePins cs.store ++ cs.hazardRetained := by
              rcases hInv.readersPublishedBacked s hr1 hm r hPub with hf | hret
              · exact List.mem_append_left _ (List.mem_append_left _ hf)
              · exact List.mem_append_right _ hret
            exact ⟨hPub, indexView_of_preserves hPres hrInPins hView⟩
      }
  | mutateStoreSynced store' hLock hSynced hBranch hHist hLive hPres hStubs =>
      refine {
        branchValid := hBranch
        histValid := hHist
        live := hLive
        lockNonZero := hInv.lockNonZero
        retainedNz := hInv.retainedNz
        retainedNodup := hInv.retainedNodup
        stubsEmpty := hStubs
        readersPublishedNz := hInv.readersPublishedNz
        readersPublishedBacked :=
          fun s hr1 hm r hrP =>
            Or.inr (hSynced s hr1 hm r hrP)
        readersTxCovered := hInv.readersTxCovered
        readersViewsExact :=
          fun s hr1 hm r rows hV => by
            obtain ⟨hPub, hView⟩ := hInv.readersViewsExact s hr1 hm r rows hV
            have hrRet : r ∈ cs.hazardRetained := hSynced s hr1 hm r hPub
            exact ⟨hPub, indexView_of_preserves hPres hrRet hView⟩
      }

/-- Any multi-step concurrent interleaving preserves `ConcInv`. -/
theorem conc_trace_preserves_inv {cs₀ cs : ConcState}
    (hInv : ConcInv cs₀) (hTrace : ConcTrace cs₀ cs)
    : ConcInv cs := by
  induction hTrace with
  | refl _ => exact hInv
  | step hStep _ ih => exact ih (conc_step_preserves_inv hInv hStep)

/-- **Concurrent Snapshot Linearizability & Zero Use-After-Free**:
In every state reachable via an arbitrary concurrent interleaving of shared `ReadGuard`
acquisitions, lock-free `HazardSlot` drops, `sync_hazards_locked()` synchronization passes,
and exclusive `WriteGuard` store mutations (commit, compact, rollback, replay,
`install_snapshot`, backfill, promote, end):
1. Every active hazard reader's published roots remain live in `cs.store.history.index`
   (zero use-after-free).
2. Every root captured by an active hazard reader retains the exact `IndexView` and
   `indexRows` it observed at snapshot acquisition time. -/
theorem conc_hazard_reads_linearizable_and_no_uaf {cs₀ cs : ConcState}
    (hInv : ConcInv cs₀) (hTrace : ConcTrace cs₀ cs)
    (slot : Nat) (hr : HazardReader) (hActive : (slot, hr) ∈ cs.hazardReaders)
    : (∀ r ∈ hr.publishedRoots,
        SingleLinkLive cs.store.history.index.values.dirs.val
          cs.store.history.index.values.rows.val r)
      ∧ (∀ r rows,
          (r, rows) ∈ hr.capturedViews
          → IndexView cs.store.history.index r rows
            ∧ indexRows cs.store.history.index r = rows) := by
  have hNow := conc_trace_preserves_inv hInv hTrace
  refine ⟨?_, ?_⟩
  · intro r hrP
    have hrInPins : r ∈ storePins cs.store ++ cs.hazardRetained := by
      rcases hNow.readersPublishedBacked slot hr hActive r hrP with hf | hret
      · exact List.mem_append_left _ (List.mem_append_left _ hf)
      · exact List.mem_append_right _ hret
    exact hNow.live.pinsLive r hrInPins
  · intro r rows hV
    obtain ⟨_, hView⟩ := hNow.readersViewsExact slot hr hActive r rows hV
    exact ⟨hView, index_rows_eq hView⟩

end KvRust
