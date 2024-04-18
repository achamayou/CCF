-------------------------------- MODULE TraceMultiNodeReads -------------------------------
EXTENDS MultiNodeReads, Json, IOUtils, Sequences, SequencesExt

\* Trace validation has been designed for TLC running in default model-checking
\* mode, i.e., breadth-first search.
\* The property TraceMatched will be violated if TLC runs with more than a single worker.
ASSUME TLCGet("config").mode = "bfs" /\ TLCGet("config").worker = 1

\* Note the extra /../ necessary to run in the VSCode extension but not a happy CLI default
JsonFile ==
    IF "JSON" \in DOMAIN IOEnv THEN IOEnv.JSON ELSE "../../build/consistency/trace.ndjson"

JsonLog ==
    \* Deserialize the System log as a sequence of records from the log file.
    \* Run TLC from under the tla/ directory with:
    \* $ JSON=../build/consistency/trace.ndjson ./tlc.sh consistency/TraceMultiNodeReads.tla
    \* Traces can be generated by running ./tests.sh -VV -R consistency_trace_validation under build/
    \* The clients execute transactions sequentially, and so the log is ordered by tx
    ndJsonDeserialize(JsonFile)

VARIABLE l

TraceInit ==
    /\ l = 1
    /\ Init

logline ==
    JsonLog[l]

ToTxType ==
    "RwTxRequest" :> RwTxRequest @@
    "RwTxResponse" :>  RwTxResponse @@
    "TxStatusReceived" :> TxStatusReceived @@
    "RoTxRequest" :> RoTxRequest @@
    "RoTxResponse" :>  RoTxResponse

ToStatus ==
    "CommittedStatus" :> CommittedStatus @@
    "InvalidStatus" :>  InvalidStatus

\* Beware to only prime e.g. inbox in inbox'[rcv] and *not* also rcv, i.e.,
 \* inbox[rcv]'.  rcv is defined in terms of TLCGet("level") that correctly
 \* handles priming, which causes rcv' to equal rcv of the next log line.
IsEvent(e) ==
    \* Equals FALSE if we get past the end of the log, causing model checking to stop.
    /\ l \in 1..Len(JsonLog)
    /\ logline.action = e
    /\ l' = l + 1

IsRwTxRequestAction ==
    /\ IsEvent("RwTxRequestAction")
    /\ RwTxRequestAction
    /\ Last(history').type = ToTxType[logline.type]
    /\ Last(history').tx = logline.tx

IsRwTxExecuteAction ==
    /\ IsEvent("RwTxExecuteAction")
    /\ RwTxExecuteAction
    /\ Last(history').tx = logline.tx
    /\ Len(ledgerBranches') = logline.view

IsRwTxResponseAction ==
    /\ IsEvent("RwTxResponseAction")
    /\ RwTxResponseAction
    /\ Last(history').type = ToTxType[logline.type]
    /\ Last(history').tx = logline.tx
    /\ Last(history').status = ToStatus[logline.status]
    /\ Last(history').tx_id = logline.tx_id

IsStatusCommittedResponseAction ==
    /\ IsEvent("StatusCommittedResponseAction")
    /\ StatusCommittedResponseAction
    /\ Last(history').type = ToTxType[logline.type]
    /\ Last(history').status = ToStatus[logline.status]

IsRoTxRequestAction ==
    /\ IsEvent("RoTxRequestAction")
    /\ RoTxRequestAction
    /\ Last(history').type = ToTxType[logline.type]
    /\ Last(history').tx = logline.tx

IsRoTxResponseAction ==
    /\ IsEvent("RoTxResponseAction")
    /\ RoTxResponseAction
    /\ Last(history').type = ToTxType[logline.type]
    /\ Last(history').tx = logline.tx

IsStatusInvalidResponseAction ==
    /\ IsEvent("StatusInvalidResponseAction")
    /\ StatusInvalidResponseAction
    /\ Last(history').type = ToTxType[logline.type]
    /\ Last(history').status = ToStatus[logline.status]

IsNotEvent ==
    l' = l

InsertTruncateLedgerAction ==
    /\ IsNotEvent
    /\ "view" \in DOMAIN logline
    /\ logline.view > Len(ledgerBranches)
    /\ "tx_id" \in DOMAIN logline
    /\ logline.tx_id[1] > Len(ledgerBranches)
    /\ TruncateLedgerAction

InsertOtherTxnAction ==
    /\ IsNotEvent
    /\ "tx_id" \in DOMAIN logline
    /\ logline.tx_id[2] > Len(Last(ledgerBranches))
    /\ AppendOtherTxnAction

TraceNext ==
    \/ IsRwTxRequestAction
    \/ IsRwTxExecuteAction
    \/ IsRwTxResponseAction
    \/ IsStatusCommittedResponseAction
    \/ IsRoTxRequestAction
    \/ IsRoTxResponseAction
    \/ IsStatusInvalidResponseAction
    \/ InsertTruncateLedgerAction
    \/ InsertOtherTxnAction

TraceSpec ==
    TraceInit /\ [][TraceNext]_<<l, vars>>

-------------------------------------------------------------------------------------

Termination ==
    l = Len(JsonLog) => TLCSet("exit", TRUE)

-------------------------------------------------------------------------------------

TraceMatched ==
    \* We force TLC to check TraceMatched as a temporal property because TLC checks temporal
    \* properties after generating all successor states of the current state, unlike
    \* invariants that are checked after generating a successor state.
    \* If the queue is empty after generating all successors of the current state,
    \* and l is less than the length of the trace, then TLC failed to validate the trace.
    \*
    \* Note: Consider strengthening (Nat \ {0}) to {1} when validating traces with no nondeterminism.
    [](l <= Len(JsonLog) => [](TLCGet("queue") \in Nat \ {0} \/ l > Len(JsonLog)))

TraceMatchedNonTrivially ==
    \* If, e.g., the FALSE state constraint excludes all states, TraceMatched won't be violated.
    TLCGet("stats").diameter >= Len(JsonLog)

MNR == INSTANCE MultiNodeReads

MNRSpec == MNR!SpecMultiNodeReads

==================================================================================
