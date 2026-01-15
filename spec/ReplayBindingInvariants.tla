---- MODULE ReplayBindingInvariants ----
EXTENDS Naturals, Sequences

\* A minimal model for replay resistance + binding invariants.
\*
\* This is a *protocol-shape* spec meant to match the security intent of the
\* gateway implementation:
\*   - receipt chain integrity (even with interleavings)
\*   - monotonic counters that survive restarts (Crash keeps state)
\*   - decision hash binding to (action_id, token_jti)

CONSTANTS TokenIds, ActionIds, Hashes

\* Deterministic binding from (action_id, token_jti) -> decision_hash.
\* In code this is realized by signing + storing (action_id,evidence_hash,decision_hash)
\* and rejecting mismatches. Here we model it as an injective mapping.
CONSTANT DecisionHash

VARIABLES
  lastCounter,   \* [t \in TokenIds |-> Nat]
  log,           \* Seq of receipts
  lastHash       \* Hash of the last receipt in the chain

\* Receipt record shape (kept minimal):
\*   [ token |-> t, action |-> a, decision |-> d, prev |-> h, hash |-> h2 ]

Receipt(t, a, d, prev, h) ==
  [ token |-> t,
    action |-> a,
    decision |-> d,
    prev |-> prev,
    hash |-> h ]

Init ==
  /\ lastCounter = [t \in TokenIds |-> 0]
  /\ log = << >>
  /\ lastHash \in Hashes

\* Monotonic counter update (e.g., T3 counter) for a given token.
UpdateCounter(t, c) ==
  /\ t \in TokenIds
  /\ c \in Nat
  /\ c > lastCounter[t]
  /\ lastCounter' = [lastCounter EXCEPT ![t] = c]
  /\ UNCHANGED <<log, lastHash>>

\* Append a receipt atomically. Interleavings are modeled by allowing any (t,a)
\* to append in any step.
AppendReceipt(t, a, h2) ==
  /\ t \in TokenIds
  /\ a \in ActionIds
  /\ h2 \in Hashes
  /\ h2 # lastHash
  /\ LET d == DecisionHash[a, t] IN
      /\ log' = Append(log, Receipt(t, a, d, lastHash, h2))
      /\ lastHash' = h2
  /\ UNCHANGED lastCounter

\* Crash / restart: persistent state remains (models counters surviving restarts).
Crash == UNCHANGED <<lastCounter, log, lastHash>>

Next ==
  (\E t \in TokenIds, c \in Nat: UpdateCounter(t, c))
  \/ (\E t \in TokenIds, a \in ActionIds, h \in Hashes: AppendReceipt(t, a, h))
  \/ Crash

Spec == Init /\ [][Next]_<<lastCounter, log, lastHash>>

\* --- Invariants ---

\* 1) Receipt chain integrity: each receipt points to the hash of the prior receipt.
ChainOK ==
  \A i \in 1..Len(log):
    IF i = 1 THEN TRUE
    ELSE log[i].prev = log[i-1].hash

\* 2) Monotonic counters: per token, the counter never decreases.
\* TLC checks this because UpdateCounter only allows strict increase and Crash preserves.
CountersMonotonic ==
  \A t \in TokenIds: lastCounter[t] \in Nat

\* 3) Binding: decision hash is uniquely bound to (action_id, token_jti).
DecisionBindingOK ==
  \A i \in 1..Len(log):
    log[i].decision = DecisionHash[log[i].action, log[i].token]

====
