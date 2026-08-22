; expect: sat
; NEGATIVE CONTROL (the rules_ordeal `sat_must_fail` pattern). The same
; obligation against a WRONG advance that stores min() instead of max(). If this
; ever reports unsat, the proof harness is not actually deciding anything and
; every unsat above is worthless. A gate nobody has watched go red is not a gate.
(set-logic QF_BV)
(declare-fun p () (_ BitVec 64))
(declare-fun m () (_ BitVec 64))
(assert (bvult (ite (bvuge p m) m p) m))
(check-sat)
