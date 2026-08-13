; expect: sat
; REQ-PROOF-001 — the surviving-mutant case, turned into a test generator.
; On 2026-08-08 cargo-mutants reported THREE survivors, all
; "replace || with && in epoch_days" at rollback.rs:136 — the Gregorian leap
; predicate `(y%4==0 && y%100!=0) || y%400==0`. proptest never generated a year
; that distinguishes them. This asks the solver for one: a four-digit year where
; the correct predicate and the mutant disagree. The model IS the regression
; test (it yielded 8192, hence the `8192-02-29` case in rollback.rs).
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
