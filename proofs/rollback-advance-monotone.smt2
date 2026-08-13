; expect: unsat
; REQ-PROOF-001 / REQ-ROLLBACK-001 — HighWaterMarks::advance stores
; max(presented, mark), so the mark can never DECREASE. A model here would be a
; (presented, mark) pair whose advance lowers the mark: anti-rollback defeated
; by the anti-rollback code itself. proptest samples this over 0..1e6; this
; discharges it over the whole 64-bit space, with an LRAT certificate.
(set-logic QF_BV)
(declare-fun p () (_ BitVec 64))
(declare-fun m () (_ BitVec 64))
(assert (bvult (ite (bvuge p m) p m) m))
(check-sat)
