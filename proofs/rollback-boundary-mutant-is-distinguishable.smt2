; expect: sat
; REQ-PROOF-001 — replaces an earlier `rollback-verdict-total.smt2` that clean-room
; review correctly called theatre: it asserted `c >= h AND c < h`, a bare
; contradiction that is unsat whatever `check` does, and so could never fail.
;
; This asks a question the code can actually answer wrongly. `check` refuses when
; `counter < high_water` (rollback.rs) and accepts otherwise, so the boundary
; `counter == high_water` is ACCEPTED — re-presenting the layer already at the
; mark, which is what a re-install or a re-verify does. Mutating `<` to `<=`
; moves that boundary. Ask for a counter where the two disagree: the model is
; the case a test must cover. It returns c == h, and rollback.rs's
; `an_equal_counter_reinstalls_cleanly` is exactly that test — proof and test
; agree, which is the outcome you want when both are honest.
(set-logic QF_BV)
(declare-fun c () (_ BitVec 64))
(declare-fun h () (_ BitVec 64))
(declare-fun impl () (_ BitVec 1))
(declare-fun mutant () (_ BitVec 1))
; impl:   refuse iff c <  h        mutant: refuse iff c <= h
(assert (= impl   (ite (bvult c h) #b1 #b0)))
(assert (= mutant (ite (bvule c h) #b1 #b0)))
(assert (distinct impl mutant))
(check-sat)
