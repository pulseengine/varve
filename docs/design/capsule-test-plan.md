# Capsule test plan (REQ-CAPSULE-001, DD-044)

> **DRAFT — nothing here exists yet.** Each entry is a test to write, with the
> file it would live in and the clause it verifies. Names are final-form so
> they can go into `claims.yaml` and rivet `verifies` comments unchanged.
> Design: `docs/design/cmd-capsule.md`.

Three levels, because every significant varve defect so far came from system
exercise, not units: unit tests in `crates/varve-core/src/capsule.rs`, CLI tests
in `crates/varve/tests/capsule.rs`, and one system script that IS the acceptance
run, `tools/systest/capsule-assessor.sh`, as a required job in
`.github/workflows/systest.yml`.

## A. Acceptance (the plan's five, as written in REQ-CAPSULE-001)

All five run in `tools/systest/capsule-assessor.sh` inside a network namespace
with no interface but loopback (`unshare --net --map-root-user`, or
`docker run --network none`), `HOME` and `VARVE_ROOT` pointing at new empty
directories, no `~/.docker/config.json`, no `GITHUB_TOKEN`/`VARVE_*` credential
variables. The fixture is a three-realm composition (the `compose-realms.sh`
fixture extended): a pinning realm composing two realms, one MIXED override, a
line whose index lists a layer newer than the pinned one.

| # | test (step in the script / CLI test) | file | clause |
|---|---|---|---|
| A1 | `reconstruct_then_verify_then_check_attestation_all_exit_zero` | `tools/systest/capsule-assessor.sh`; mirrored in `crates/varve/tests/capsule.rs` | 2 |
| A2 | `the_verdict_names_layer_digest_overrides_and_yanks` (asserts the `--json` fields and the text VERDICT line; the fixture has one yanked override so "yanks" is not vacuously empty) | `crates/varve/tests/capsule.rs` | 2 |
| A3 | `a_layer_one_counter_behind_reconstructs_on_a_machine_that_has_seen_the_newer_one` (the machine store first installs counter N+1 for real, then reconstructs counter N) | `crates/varve/tests/capsule.rs`; step in the script | 3 |
| A4 | `assessor_mode_does_not_leak_a_normal_install_of_the_superseded_layer_is_still_refused` (after A3: a name-only pin of counter N in the machine store exits non-zero with the `rollback refused` error, and `high-water-marks.json` is byte-identical to before A3) | `crates/varve/tests/capsule.rs`; step in the script | 3 |
| A5a | `negative_control_a_dropped_composed_layer_is_refused_naming_it` | `crates/varve/tests/capsule.rs`; step in the script | 4 |
| A5b | `negative_control_a_dropped_line_index_is_refused_naming_the_line` | `crates/varve/tests/capsule.rs`; step in the script | 4 |
| A5c | `negative_control_a_flipped_payload_byte_is_refused_with_the_blob_digest_error` | `crates/varve/tests/capsule.rs`; step in the script | 4 |
| A5d | `negative_control_a_pure_pin_attestation_for_a_mixed_capsule_is_refused` | `crates/varve/tests/capsule.rs`; step in the script | 4 |

Each negative control asserts **the named cause** (a substring of the refusal
naming the layer, line, entry or overrides), not only a non-zero exit, and
asserts `--into` is still empty: a control that passes on any failure would pass
on a crash.

### Harness potency (the sandbox can fail)

| test | file | why |
|---|---|---|
| `harness_control_a_normal_install_inside_the_sandbox_fails_with_a_transport_error` | `tools/systest/capsule-assessor.sh` | proves the namespace really has no network; without it A1 passing proves nothing about "no network call" |
| `harness_control_the_fixture_registries_are_unroutable` | `tools/systest/capsule-assessor.sh` | the fixture realms' `registry` points at an address that cannot answer, so an attempted call fails loudly rather than succeeding through a leak |
| `kill_criterion_reconstruct_makes_no_network_call` (`strace -f -e trace=network` on Linux, asserting no `connect` to a non-loopback address) | `tools/systest/capsule-assessor.sh` | the plan's first kill criterion, observed rather than inferred |

## B. Assessor mode does not leak (clause 3, beyond A4)

| test | file |
|---|---|
| `the_machine_store_is_byte_identical_after_reconstruct` (marks, line-index and line-status caches, core listing) | `crates/varve/tests/capsule.rs` |
| `reconstruct_ignores_varve_root_and_never_opens_the_machine_store` (`VARVE_ROOT` set to a directory with mode 000: reconstruct still succeeds) | `crates/varve/tests/capsule.rs` |
| `reconstruct_refuses_an_into_that_is_inside_or_contains_the_machine_store` | `crates/varve/tests/capsule.rs` |
| `reconstruct_refuses_a_non_empty_into_and_writes_nothing` | `crates/varve/tests/capsule.rs` |
| `install_into_an_assessor_store_is_refused_naming_the_record` | `crates/varve/tests/capsule.rs` |
| `seed_archive_and_shim_install_refuse_an_assessor_store` | `crates/varve/tests/capsule.rs` |
| `verify_status_and_which_in_an_assessor_store_say_so_on_their_first_line` | `crates/varve/tests/capsule.rs` |
| `no_flag_config_key_or_environment_variable_selects_assessor_rules` (source scan: the clap tree of `install` has no such flag; `RawToolchain`, the realms parser and every `VARVE_*` read are unchanged) | `crates/varve/tests/capsule.rs` |
| `the_assessor_rule_is_constructed_only_in_capsule_rs` (source scan: `AssessorRule` / its token is built nowhere but `capsule.rs`, and `install_inner` callers outside it pass `RollbackRule::Enforce`) | `crates/varve-core/src/capsule.rs` |
| `capsule_rs_reaches_no_network_source` (source scan: no `registry::`, `mirror::`, `ureq`, `reqwest` in `capsule.rs`; its only `LayerSource` is `OciLayoutSource`) | `crates/varve-core/src/capsule.rs` |

## C. First contact and trust (hard part 1)

| test | file |
|---|---|
| `a_carried_root_is_accepted_only_when_it_hashes_to_the_brought_fingerprint` | `crates/varve-core/src/capsule.rs` |
| `a_sixteen_hex_partition_id_is_refused_as_a_root` | `crates/varve-core/src/capsule.rs` |
| `every_realm_in_the_closure_needs_a_brought_root_and_the_refusal_names_the_carried_fingerprint` | `crates/varve-core/src/capsule.rs` |
| `a_key_roles_realm_needs_its_carried_delegation_and_it_verifies_against_the_brought_root` | `crates/varve-core/src/capsule.rs` |
| `the_target_comes_from_the_attestation_not_the_packing_list` (packing list names another layer: refused, the attestation wins) | `crates/varve-core/src/capsule.rs` |
| `an_attestation_signed_by_another_root_is_refused` | `crates/varve-core/src/capsule.rs` |
| `a_layer_below_the_first_contact_floor_reconstructs_and_the_verdict_says_so` | `crates/varve-core/src/capsule.rs` |
| `a_newer_status_brought_with_status_supersedes_the_carried_one` | `crates/varve-core/src/capsule.rs` |
| `an_older_status_brought_with_status_changes_nothing` | `crates/varve-core/src/capsule.rs` |
| `a_status_or_index_for_another_line_or_realm_is_ignored_not_trusted` | `crates/varve-core/src/capsule.rs` |
| `a_capsule_never_answers_first_contact_for_a_normal_store` (unpacked capsule as a mirror of a never-installed store: `first contact … needs the realm's primary`, unchanged) | `crates/varve/tests/capsule.rs` |

## D. Composition and overrides (hard parts 3 and 4)

| test | file |
|---|---|
| `archive_capsule_carries_every_composed_layer_transitively` | `crates/varve-core/src/capsule.rs` |
| `archive_capsule_refuses_when_a_composed_layer_is_not_installed_and_writes_nothing` | `crates/varve-core/src/capsule.rs` |
| `archive_capsule_carries_each_lines_index_and_status_and_each_realms_root` | `crates/varve-core/src/capsule.rs` |
| `archive_capsule_carries_override_layers_and_their_composition` | `crates/varve-core/src/capsule.rs` |
| `a_mixed_attestation_whose_override_is_not_in_the_capsule_is_refused_naming_it` | `crates/varve-core/src/capsule.rs` |
| `a_mixed_capsule_reconstructs_and_the_verdict_says_mixed` (#378) | `crates/varve/tests/capsule.rs` |
| `a_yanked_override_is_named_in_the_verdict` (#381) | `crates/varve/tests/capsule.rs` |
| `a_yanked_composed_layer_is_named_in_the_verdict` | `crates/varve/tests/capsule.rs` |

## E. Format (hard part 5)

| test | file |
|---|---|
| `the_capsule_is_byte_identical_when_written_twice` | `crates/varve-core/src/capsule.rs` |
| `an_unpacked_capsule_is_a_valid_seed_directory` (each subdirectory installs as a mirror for a store with history) | `crates/varve-core/src/capsule.rs` |
| `a_capsule_entry_that_is_a_link_device_absolute_or_dotdot_is_refused_before_extraction` | `crates/varve-core/src/capsule.rs` |
| `a_capsule_with_a_duplicate_path_is_refused` | `crates/varve-core/src/capsule.rs` |
| `a_capsule_for_another_platform_is_refused_naming_both` | `crates/varve-core/src/capsule.rs` |
| `capsule_size_budget_covalent_one_platform_under_2_gib` (measured on the real covalent pin; prints the size; fails above 2 GiB, warns above 1 GiB) | `tools/measure/capsule-size.sh`, run in `measure-verify.yml` (needs registry access, so not in the sandboxed job) |

## Mutation

`capsule.rs` joins `mutation-scope.toml`. The negative controls in A5 and the
fingerprint and leak tests in B and C are the tests expected to kill its
mutants; a mutant surviving in the decision step is a missing negative control.
