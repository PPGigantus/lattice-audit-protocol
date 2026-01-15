---- MODULE BudgetInvariants ----
EXTENDS Naturals
CONSTANTS TotalBudget, MaxStep, TokenIds
VARIABLES reserved, spent, issued, jtiSeen
TotalIssued == Sum({ issued[t] : t \in TokenIds })
Init == /\ reserved = 0
        /\ spent = 0
        /\ issued = [t \in TokenIds |-> 0]
        /\ jtiSeen = {}
Reserve(n) ==
  /\ n \in 1..MaxStep
  /\ reserved + spent + n <= TotalBudget
  /\ reserved' = reserved + n
  /\ UNCHANGED <<spent, issued, jtiSeen>>

Release(n) ==
  /\ n \in 1..MaxStep
  /\ n <= reserved
  /\ TotalIssued <= reserved - n
  /\ reserved' = reserved - n
  /\ UNCHANGED <<spent, issued, jtiSeen>>
Mint(t,n) ==
  /\ t \in TokenIds \ jtiSeen
  /\ n \in 1..MaxStep
  /\ n <= reserved - TotalIssued
  /\ issued' = [issued EXCEPT ![t] = n]
  /\ jtiSeen' = jtiSeen \cup {t}
  /\ UNCHANGED <<reserved, spent>>

Spend(t,n) ==
  /\ t \in jtiSeen
  /\ n \in 1..MaxStep
  /\ n <= issued[t]
  /\ issued' = [issued EXCEPT ![t] = issued[t] - n]
  /\ reserved' = reserved - n
  /\ spent' = spent + n
  /\ UNCHANGED jtiSeen
Crash == UNCHANGED <<reserved, spent, issued, jtiSeen>>

Next ==
  \E n \in 1..MaxStep: Reserve(n)
  \/ \E n \in 1..MaxStep: Release(n)
  \/ \E t \in TokenIds, n \in 1..MaxStep: Mint(t,n)
  \/ \E t \in TokenIds, n \in 1..MaxStep: Spend(t,n)
  \/ Crash

Spec == Init /\ [][Next]_<<reserved, spent, issued, jtiSeen>>

BudgetSafety == reserved + spent <= TotalBudget
TokenWithinReserve == TotalIssued <= reserved
NoDoubleMint == \A t \in TokenIds: (issued[t] > 0) => t \in jtiSeen

====
