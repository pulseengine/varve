; expect: sat
; REQ-PROOF-001 — a mutation, turned into a test generator.
;
; PROVENANCE, corrected after clean-room review checked it against git history:
; an earlier version of this comment claimed three cargo-mutants survivors on
; 2026-08-08 were `||`->`&&` in the LEAP predicate at rollback.rs:136. That is
; not supported. The leap predicate has never been at line 136 (it is at 145),
; and the commit that introduced it also introduced the 2000-02-29 anchor, which
; already kills the leap mutant. The survivors actually killed that day were the
; other `||`s in epoch_days — the shape and day-range guards — per commit cc08bf1
; "kill epoch_days validation-guard mutants". The claim was asserted from a
; summary rather than verified against history; the correction stands as the
; record.
;
; The obligation below is still worth keeping and is stated honestly: it asks
; for a four-digit year where the correct leap rule and the `||`->`&&` mutation
; disagree. It returns 8192, and `8192-02-29` is a real date under the correct
; rule and not under the mutant — verified by mutating rollback.rs and watching
; the test fail. That makes it defence in depth over the 2000/8000 anchors
; rather than the only thing killing that mutant.
; Booleans are 1-bit vectors to stay inside ordeal's QF_BV fragment.
(set-logic QF_BV)
(declare-fun y () (_ BitVec 64))
(declare-fun a4 () (_ BitVec 1))
(declare-fun n100 () (_ BitVec 1))
(declare-fun a400 () (_ BitVec 1))
(assert (bvuge y (_ bv1000 64)))
(assert (bvule y (_ bv9999 64)))
(assert (= a4   (ite (= (bvurem y (_ bv4 64))   (_ bv0 64)) #b1 #b0)))
(assert (= n100 (ite (= (bvurem y (_ bv100 64)) (_ bv0 64)) #b0 #b1)))
(assert (= a400 (ite (= (bvurem y (_ bv400 64)) (_ bv0 64)) #b1 #b0)))
(assert (distinct (bvor  (bvand a4 n100) a400)
                  (bvand (bvand a4 n100) a400)))
(check-sat)
