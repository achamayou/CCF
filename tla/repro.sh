# Run in the same directory as tlc.sh
# With DFS
JSON=trace.ndjson JVM_OPTIONS=-Dtlc2.tool.queue.IStateQueue=StateDeque ./tlc.sh consistency/TraceMultiNodeReads.tla | grep State | tail
# State 43: <IsRoTxResponseAction line 97, col 5 to line 108, col 67 of module TraceMultiNodeReads>
# State 44: <IsRwTxRequestAction line 50, col 5 to line 55, col 37 of module TraceMultiNodeReads>
# State 45: <BackfillLedgerBranch line 128, col 5 to line 141, col 24 of module TraceMultiNodeReads>
# State 46: <IsRwTxExecuteAction line 58, col 5 to line 68, col 67 of module TraceMultiNodeReads>
# State 47: <IsRwTxResponseAction line 71, col 5 to line 77, col 43 of module TraceMultiNodeReads>
# State 48: <IsStatusInvalidResponseAction line 111, col 5 to line 117, col 43 of module TraceMultiNodeReads>
# State 49: <IsRwTxRequestAction line 50, col 5 to line 55, col 37 of module TraceMultiNodeReads>
# State 50: <BackfillLedgerBranches line 144, col 5 to line 155, col 24 of module TraceMultiNodeReads>
# State 51: <BackfillLedgerBranch line 128, col 5 to line 141, col 24 of module TraceMultiNodeReads>
# State 52: <IsRwTxExecuteAction line 58, col 5 to line 68, col 67 of module TraceMultiNodeReads>
$ JSON=trace.ndjson ./tlc.sh consistency/TraceMultiNodeReads.tla | grep State | tail
# State 45: <BackfillLedgerBranch line 128, col 5 to line 141, col 24 of module TraceMultiNodeReads>
# State 46: <IsRwTxExecuteAction line 58, col 5 to line 68, col 67 of module TraceMultiNodeReads>
# State 47: <IsRwTxResponseAction line 71, col 5 to line 77, col 43 of module TraceMultiNodeReads>
# State 48: <IsStatusInvalidResponseAction line 111, col 5 to line 117, col 43 of module TraceMultiNodeReads>
# State 49: <IsRwTxRequestAction line 50, col 5 to line 55, col 37 of module TraceMultiNodeReads>
# State 50: <BackfillLedgerBranches line 144, col 5 to line 155, col 24 of module TraceMultiNodeReads>
# State 51: <BackfillLedgerBranch line 128, col 5 to line 141, col 24 of module TraceMultiNodeReads>
# State 52: <IsRwTxExecuteAction line 58, col 5 to line 68, col 67 of module TraceMultiNodeReads>
# State 53: <IsRwTxResponseAction line 71, col 5 to line 77, col 43 of module TraceMultiNodeReads>
# State 54: <IsStatusCommittedResponseAction line 80, col 5 to line 86, col 43 of module TraceMultiNodeReads>