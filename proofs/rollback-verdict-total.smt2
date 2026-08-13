; expect: unsat
; REQ-PROOF-001 / REQ-ROLLBACK-001 — `check` returns Rollback exactly when the
; presented counter is below the stored high-water mark, and Accept otherwise
; (the `_ =>` arm). A model would be a counter that is BOTH accepted and below
; the mark: the fail-open case. Encoded as: accepted (not below) yet below.
(set-logic QF_BV)
(declare-fun counter () (_ BitVec 64))
(declare-fun high_water () (_ BitVec 64))
(assert (bvuge counter high_water))
(assert (bvult counter high_water))
(check-sat)
