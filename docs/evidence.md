# Evidence

Generated from `tests/traceability.toml` by `python3 tests/traceability.py
evidence`; CI fails if this page is out of date. Every test listed here
exists in the source, and the `traceability` job checks that every VM,
Kubernetes and package test passed on every kernel and distribution in
the same run (docs/testing.md).

## Phase 0

### no-object-override

Release builds contain no runtime override for the BPF object path

- `no_object_path_flag` (Rust test)

## Phase 2

### net-enforce-eperm

ENFORCE: the deny set gives EPERM over TCP and UDP, IPv4 and IPv6

- `net_enforce_tcp_v4` (VM suite, every kernel)
- `net_enforce_tcp_v6` (VM suite, every kernel)
- `net_enforce_udp_connect_v4` (VM suite, every kernel)
- `net_enforce_udp_connect_v6` (VM suite, every kernel)
- `net_enforce_udp_sendmsg_v4` (VM suite, every kernel)
- `net_enforce_udp_sendmsg_v6` (VM suite, every kernel)
- `net_enforce_v4_mapped` (VM suite, every kernel)

### net-telemetry-independent

Verdicts are the same with the consumer paused, and when every emit fails

- `net_verdicts_independent_of_telemetry` (VM suite, every kernel)
- `net_verdicts_with_emit_failing` (VM suite, every kernel)

### net-audit

AUDIT: operations succeed and report audit-would-deny with the rule id

- `net_audit_reports_rule_id` (VM suite, every kernel)

### net-ungoverned

Processes outside governed cgroups are unaffected

- `net_ungoverned_untouched` (VM suite, every kernel)
- `net_unbound_sibling_untouched` (VM suite, every kernel)

### net-atomic-reload

Policy reload is atomic

- `net_reload_atomic` (VM suite, every kernel)

### net-bypasses

Raw/packet sockets, io_uring, TCP Fast Open and NAT64 can't bypass the rules

- `net_raw_socket_denied` (VM suite, every kernel)
- `net_packet_vnet_hdr_denied` (VM suite, every kernel)
- `net_io_uring_connect_denied` (VM suite, every kernel)
- `net_tcp_fastopen_denied` (VM suite, every kernel)
- `net_nat64_equivalence` (VM suite, every kernel)

### net-compiler

The compiled kernel lookup always agrees with the reference evaluator

- `compiled_lookup_matches_reference` (Rust test)

## Phase 3

### exec-allowlist

ENFORCE: unlisted executables are denied, listed ones run

- `exec_enforce_unlisted_denied` (VM suite, every kernel)
- `exec_enforce_listed_runs` (VM suite, every kernel)

### exec-identity

Exec decisions follow file identity: symlinks, replaced binaries, scripts, unlinked files

- `exec_symlink_resolves_to_target` (VM suite, every kernel)
- `exec_replaced_binary_denied_until_reload` (VM suite, every kernel)
- `exec_script_requires_interpreter` (VM suite, every kernel)
- `exec_unlinked_denied` (VM suite, every kernel)
- `exec_unlinked_override_allows` (VM suite, every kernel)

### exec-events

Exec events carry the full argv, with a truncation flag when cut

- `exec_records_full_argv` (VM suite, every kernel)
- `exec_records_truncation_flag` (VM suite, every kernel)

### exec-audit

AUDIT reports would-deny for exec

- `exec_audit_reports_would_deny` (VM suite, every kernel)

### exec-reload-quarantine

Exec policy reload is atomic; quarantine blocks exec and network

- `exec_reload_atomic` (VM suite, every kernel)
- `exec_quarantine_blocks_exec_and_network` (VM suite, every kernel)

### exec-ungoverned

Ungoverned processes are untouched by exec policy

- `exec_ungoverned_untouched` (VM suite, every kernel)
- `exec_unbound_sibling_untouched` (VM suite, every kernel)

## Phase 4

### file-access-types

Each access type is denied separately: read, write, truncate, delete, rename, link, create, setattr

- `file_open_read_denied` (VM suite, every kernel)
- `file_open_write_denied` (VM suite, every kernel)
- `file_openat2_denied` (VM suite, every kernel)
- `file_io_uring_openat_denied` (VM suite, every kernel)
- `file_o_trunc_denied` (VM suite, every kernel)
- `file_truncate_denied` (VM suite, every kernel)
- `file_ftruncate_denied` (VM suite, every kernel)
- `file_unlink_denied` (VM suite, every kernel)
- `file_unlinkat_dir_denied` (VM suite, every kernel)
- `file_rename_source_denied` (VM suite, every kernel)
- `file_rename_replace_target_denied` (VM suite, every kernel)
- `file_rename_exchange_denied` (VM suite, every kernel)
- `file_link_denied` (VM suite, every kernel)
- `file_create_in_protected_dir_denied` (VM suite, every kernel)
- `file_chmod_denied` (VM suite, every kernel)

### file-identity

Every way of naming the same file gets the same verdict

- `file_hardlink_same_verdict` (VM suite, every kernel)
- `file_bind_mount_same_verdict` (VM suite, every kernel)
- `file_symlink_same_verdict` (VM suite, every kernel)
- `file_proc_fd_reopen_same_verdict` (VM suite, every kernel)
- `file_relative_path_same_verdict` (VM suite, every kernel)

### file-subtree

Subtree rules apply; excessive nesting fails closed

- `file_subtree_rule_applies` (VM suite, every kernel)
- `file_deep_nesting_fails_closed` (VM suite, every kernel)

### file-protect-allowlist

Allow-listed executables can't be modified or replaced

- `file_exec_allowlist_write_denied` (VM suite, every kernel)
- `file_exec_allowlist_replace_denied` (VM suite, every kernel)

### file-audit-reload-ungoverned

AUDIT reports would-deny; reload is atomic; ungoverned processes untouched

- `file_audit_reports_would_deny` (VM suite, every kernel)
- `file_reload_atomic` (VM suite, every kernel)
- `file_ungoverned_untouched` (VM suite, every kernel)
- `file_unbound_sibling_untouched` (VM suite, every kernel)

## Phase 5

### agent-first-instruction

An agent started with rk run is governed from its first instruction

- `agent_governed_from_first_instruction` (VM suite, every kernel)

### agent-children

Children of a governed agent are governed automatically

- `agent_children_governed` (VM suite, every kernel)

### policy-pipeline

Policy apply is atomic and reversible with one command; dry-run and diff work

- `policy_apply_atomic` (VM suite, every kernel)
- `policy_rollback_one_command` (VM suite, every kernel)
- `policy_dry_run_changes_nothing` (VM suite, every kernel)
- `policy_diff_reports_changes` (VM suite, every kernel)

### agent-unprivileged

Agents run unprivileged and can't leave their cgroup

- `agent_runs_unprivileged` (VM suite, every kernel)
- `agent_cannot_leave_cgroup` (VM suite, every kernel)
- `clone_flags_match_uapi` (Rust test)

### agent-authorisation

Only authorised callers change policy or launch a profile

- `socket_rejects_unauthorised_apply` (VM suite, every kernel)
- `run_rejects_non_launchable_profile` (VM suite, every kernel)

### agent-lifecycle-session

Agent exit removes binding and cgroup; events carry the session id

- `agent_exit_removes_binding_and_cgroup` (VM suite, every kernel)
- `agent_session_id_in_events` (VM suite, every kernel)

## Phase 5b

### k8s-first-instruction

An annotated pod is governed from its first instruction, exec sessions and sidecars included

- `k8s_pod_governed_from_first_instruction` (Kubernetes (kind))
- `k8s_exec_session_governed` (Kubernetes (kind))
- `k8s_init_and_sidecar_governed` (Kubernetes (kind))

### k8s-selection

Profile selection: unannotated untouched, namespace default, disallowed and unknown refused

- `k8s_unannotated_pod_unaffected` (Kubernetes (kind))
- `k8s_namespace_default_applied` (Kubernetes (kind))
- `k8s_disallowed_profile_refused` (Kubernetes (kind))
- `k8s_unknown_profile_refused` (Kubernetes (kind))
- `pod_profile_resolution_table` (Rust test)

### k8s-lifecycle

Removal unbinds; ConfigMap updates apply live; the daemon resyncs and stays inside NRI's timeout

- `k8s_container_removal_unbinds` (Kubernetes (kind))
- `k8s_configmap_update_applies` (Kubernetes (kind))
- `k8s_daemon_restart_resyncs` (Kubernetes (kind))
- `k8s_daemon_replies_fast` (Kubernetes (kind))
- `TestSynchronizeDoesNotBlockOnDaemon` (Go test)

### k8s-fail-closed

Fail closed when the daemon is down, without blocking ungovernable pods

- `k8s_daemon_down_fails_closed` (Kubernetes (kind))
- `TestDaemonDownRefusesOnlyGovernablePods` (Go test)

### capability-honesty

Without BPF LSM, exec, file and raw-socket rules are refused, not silently unenforced

- `apply_rejects_lsm_rules_without_bpf_lsm` (Kubernetes (kind))
- `lsm_rules_refused_without_bpf_lsm` (Rust test)

### nri-contract

The NRI plugin and the daemon agree on the wire format; the chart renders and validates

- `nri_wire_contract` (Rust test)
- `TestWireContract` (Go test)
- `helm_chart_renders` (Kubernetes (kind))

## Phase 6

### survives-restart

Restarting or killing the sensor does not remove protection; enforcing verdicts continue

- `sensor_kill_keeps_enforcement` (VM suite, every kernel)
- `sensor_restart_adopts_pins` (VM suite, every kernel)
- `k8s_daemon_restart_resyncs` (Kubernetes (kind))

### heartbeat-fail-closed

After the heartbeat timeout, governed ENFORCE workloads are denied until the sensor returns

- `heartbeat_stale_denies_enforce` (VM suite, every kernel)
- `heartbeat_recovers_on_restart` (VM suite, every kernel)

### self-protection

Governed workloads get EPERM for the self-protection actions

- `guard_bpf_syscall_denied` (VM suite, every kernel)
- `guard_signal_sensor_denied` (VM suite, every kernel)
- `guard_ptrace_sensor_denied` (VM suite, every kernel)
- `guard_pins_cannot_be_removed` (VM suite, every kernel)

### pins-lifecycle

Pin directory restricted; incompatible pins replaced; uninstall removes protection

- `pin_dir_restricted` (VM suite, every kernel)
- `incompatible_pins_replaced` (VM suite, every kernel)
- `uninstall_removes_protection` (VM suite, every kernel)

## Phase 7

### perf-reported

p50 and p99 per-hook overhead reported by CI on at least two kernels

- `bench-report` (CI job)
- `test_main_without_budget_reports_only` (Python test)

### perf-gate

An overhead budget set from the first baseline is enforced as a regression gate

- `bench-report` (CI job)
- `test_check_passes_within_budget_and_flags_regressions` (Python test)
- `test_main_fails_over_budget` (Python test)

### perf-zero-loss

Zero event loss at a defined sustained rate; loss beyond it counted and reported

- `bench-report` (CI job)
- `test_check_flags_loss_at_sustained_rate` (Python test)

## Phase 8

### traceability

Every acceptance criterion maps to named tests that exist, would run (no #[ignore]d or non-test Rust fn, no skipped Python test, no disabled or emptied CI job), and passed on every kernel

- `test_repository_index_is_complete` (Python test)
- `test_reports_flag_missing_kernel` (Python test)
- `traceability` (CI job)
- `test_static_flags_an_ignored_or_non_test_rust_fn` (Python test)
- `test_static_flags_a_skipped_python_test` (Python test)
- `test_static_flags_an_emptied_ci_job` (Python test)
- `test_static_flags_a_disabled_ci_job` (Python test)

### conformance

The policy conformance corpus agrees with both the userspace evaluator and the kernel

- `conformance_corpus_is_well_formed` (Rust test)
- `conformance_userspace` (Rust test)
- `conformance_kernel` (VM suite, every kernel)

### fuzzing

The event decoder and the policy compiler are fuzzed on every run

- `fuzz` (CI job)

### properties

Property tests cover the identity encodings, CIDR normalisation and the engine state file

- `kernel_dev_matches_kernel_encoding` (Rust test)
- `ipv4_cidr_normalises_to_v4_mapped` (Rust test)
- `v4_and_v4_mapped_get_the_same_verdict` (Rust test)
- `engine_state_round_trips` (Rust test)
- `engine_state_rejects_foreign_epoch` (Rust test)

### coverage

Userspace line coverage is reported on every run

- `coverage` (CI job)
- `test_groups_by_crate_and_skips_dependencies` (Python test)

## Phase 9

### audit_complete

Every enforced or audit-would-deny decision appears in the audit log with its rule id, and lost events are recorded, not silent

- `audit_every_decision_logged` (VM suite, every kernel)
- `audit_records_loss` (VM suite, every kernel)
- `deny_and_audit_map_to_ocsf_dispositions` (Rust test)

### audit_tamper

Tampering with a stored audit batch is detected by verification

- `audit_tamper_detected` (VM suite, every kernel)
- `audit_verify_detects_modified_record` (Rust test)
- `audit_verify_detects_deleted_batch` (Rust test)
- `audit_verify_detects_reordered_batches` (Rust test)
- `audit_verify_detects_inserted_batch` (Rust test)
- `audit_verify_detects_bad_signature_and_pinned_key` (Rust test)
- `deleting_the_middle_segment_is_detected` (Rust test)
- `reopening_continues_the_chain_and_seals_leftovers` (Rust test)

### ocsf_schema

Audit records are valid OCSF 1.9.0

- `ocsf_records_validate` (Rust test)
- `validator_rejects_broken_records` (Rust test)

### metrics

A Prometheus endpoint exposes decisions, losses, policy generation, heartbeat age and enforcement availability; the dashboard queries only exported metrics

- `metrics_endpoint_serves` (VM suite, every kernel)
- `renders_every_family` (Rust test)
- `serves_metrics_over_http` (Rust test)
- `test_dashboard_metrics_exist` (Python test)

### otlp

Decisions in an agent session are exported as OTLP spans in the session's trace, which the launched agent also receives

- `spans_join_the_session_trace` (Rust test)
- `exports_to_a_collector` (Rust test)
- `a_full_queue_counts_the_loss` (Rust test)
- `traceparent_is_w3c_shaped_and_stable` (Rust test)

### process_table

The process table enriches records from exec records, falls back to procfs, is bounded, and says where enrichment came from

- `exec_records_fill_the_table_and_procfs_adds_the_parent` (Rust test)
- `misses_fall_back_to_procfs_and_exited_processes_are_unavailable` (Rust test)
- `the_table_is_bounded` (Rust test)

## Phase 10

### upgrade_continuous

Upgrade keeps enforcement continuous: a different object replaces the running one with zero denied actions getting through

- `upgrade_replaces_object_without_gap` (VM suite, every kernel)
- `upgrade_gap_detector_works` (VM suite, every kernel)
- `pkg_upgrade_keeps_enforcement` (package test, every distribution)
- `reconcile_drops_an_unfinished_replacement` (Rust test)
- `reconcile_completes_an_interrupted_switch` (Rust test)
- `finish_replacement_swaps_and_abort_keeps_the_old_set` (Rust test)

### install_upgrade_uninstall

Fresh install, upgrade and uninstall are tested on two distributions (Ubuntu 24.04 deb, Rocky Linux 9 rpm)

- `pkg_fresh_install_enforces` (package test, every distribution)
- `pkg_upgrade_keeps_enforcement` (package test, every distribution)
- `pkg_uninstall_removes_everything` (package test, every distribution)
- `package` (CI job)

### systemd_unit

The systemd unit verifies and runs the sensor, including rk run, under its bounded capability set

- `pkg_unit_verifies` (package test, every distribution)
- `pkg_fresh_install_enforces` (package test, every distribution)

### doctor

rk doctor explains missing kernel features, and passes on every supported kernel

- `doctor_passes_on_supported_kernels` (VM suite, every kernel)
- `healthy_host_passes` (Rust test)
- `missing_bpf_lsm_is_explained_as_a_warning` (Rust test)
- `blocking_problems_fail` (Rust test)
- `kernel_versions_are_graded` (Rust test)
- `stale_pins_without_a_sensor_are_flagged` (Rust test)

## Phase 11

### scorecard

OpenSSF Scorecard analyses main weekly and on every push and publishes the result; the repository-controlled properties it scores are tested: actions pinned by commit SHA and read-only default token permissions

- `analysis` (CI job)
- `test_actions_pinned_by_commit_sha` (Python test)
- `test_default_token_permissions_are_read_only` (Python test)

### sast

CodeQL analyses the Rust, Go, Python and workflow code on every pull request and push to main

- `analyze` (CI job)

### nri_fuzz

The NRI plugin's message handling is fuzzed: decoding a reply never panics and accepts only valid JSON, and every bind request survives encoding unchanged

- `FuzzDecodeReply` (Go test)
- `FuzzEncodeBind` (Go test)

### release_signed

Every release artifact and the image is signed (Sigstore), with SLSA build provenance and an SPDX SBOM, and the release is drafted only after all of them verify

- `release` (CI job)
- `image` (CI job)
- `test_release_signs_attests_and_verifies_every_artifact` (Python test)

### readme_claims

Every README claim links to the criterion that proves it, every evidence link resolves, the evidence page is current, and the README states no performance number or superlative outside its claims

- `test_readme_claims_have_evidence` (Python test)
- `test_claim_without_evidence_fails` (Python test)
- `test_unknown_criterion_fails_in_readme_and_docs` (Python test)
- `test_numbers_and_superlatives_outside_claims_fail` (Python test)
- `test_stale_evidence_page_fails` (Python test)

### dco

Every commit in a pull request is signed off by its author under the DCO; bot commits are exempt

- `dco` (CI job)
- `test_signed_off_commits_pass` (Python test)
- `test_missing_or_foreign_sign_off_fails` (Python test)
- `test_bot_commits_are_exempt` (Python test)

## Phase 12

### retired_product_removed

The repository holds only the open-source project: the hosted API, its backend crates, the analysis engine and the SDK are gone, and the workspace has only the product crates

- `test_retired_product_is_gone` (Python test)

### release_complete

The release builds every binary the Helm chart runs, and the release job can verify its own image while the package is still private

- `test_release_builds_every_chart_binary` (Python test)
- `test_release_job_logs_in_before_verifying` (Python test)
- `release` (CI job)

### go_vulnerabilities

rk-nri builds with a pinned, current Go toolchain, and CI fails on any known vulnerability reachable from it, the standard library included

- `test_go_vulnerabilities_are_checked` (Python test)
- `go` (CI job)

### site_honest

The website has no broken links, nothing of the retired product, no performance number or superlative, and no inline script or style, so it runs under a strict Content-Security-Policy

- `test_site_links_resolve` (Python test)
- `test_site_has_no_retired_product` (Python test)
- `test_site_claims_rules` (Python test)
- `test_site_fits_the_content_security_policy` (Python test)
- `test_site_partials_current` (Python test)
- `test_site_config_and_sitemap` (Python test)

## Phase 16

### tun-containment

ENFORCE: a governed process cannot create a TUN/TAP interface, attach to one (even one its own user owns, with no capability), or re-attach a detached queue; AUDIT records each as audit_would_deny; ungoverned processes and profiles with deny_raw_sockets = false are unaffected

- `tun_attach_owned_ungoverned` (VM suite, every kernel)
- `tun_create_denied` (VM suite, every kernel)
- `tun_attach_owned_denied` (VM suite, every kernel)
- `tun_attach_queue_denied` (VM suite, every kernel)
- `tun_audit_would_deny` (VM suite, every kernel)
- `tun_allowed_without_flag` (VM suite, every kernel)
- `decodes_tun` (Rust test)
- `tun_operations_are_named` (Rust test)

## Release v0.2.0

### adoption

One command installs a verified release (a tampered package is refused); rk init writes a starter AUDIT profile that fits the host and never replaces a policy in use; rk policy suggest turns a verified audit log into an ENFORCE profile under which the learned connections and executables work, everything unobserved is denied, and secret files stay denied

- `adoption_round_trip` (VM suite, every kernel)
- `pkg_fresh_install_enforces` (package test, every distribution)
- `pkg_init_suggest` (package test, every distribution)
- `test_install_script_refuses_a_tampered_package` (Python test)
- `test_install_script_checks_before_it_installs` (Python test)
- `test_install_script_pins_the_release_identity` (Python test)
- `starter_with_bpf_lsm_learns_network_exec_and_secrets` (Rust test)
- `starter_without_bpf_lsm_is_network_only` (Rust test)
- `a_policy_in_use_is_never_replaced` (Rust test)
- `suggests_an_enforce_profile_from_would_denies` (Rust test)
- `a_log_that_does_not_verify_is_refused` (Rust test)
- `no_records_is_an_error_not_an_empty_allow_list` (Rust test)

### cli-cannot-be-steered

rk init and rk policy suggest --out, run as root, never write through a symbolic link planted at the policy, staging, backup or output path; suggest keeps the observed port ranges (at most eight per address, the rest reported) instead of widening them, and never learns an executable whose file was replaced after it ran

- `root_writes_never_follow_a_planted_symlink` (Rust test)
- `replace_overwrites_a_regular_file_atomically` (Rust test)
- `backup_never_follows_a_planted_symlink` (Rust test)
- `out_never_writes_through_a_planted_symlink` (Rust test)
- `observed_port_ranges_are_never_widened` (Rust test)
- `a_replaced_executable_is_not_learned` (Rust test)
