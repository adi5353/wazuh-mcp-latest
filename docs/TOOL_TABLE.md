# Tool Inventory (auto-generated)

**239 tools** across **54 domain modules** in `wazuh_mcp/tools/`, plus **16 MCP prompts**.

> Regenerate with `python scripts/generate_tool_table.py`. Do not edit by hand.

### `rbac` (2)

- `run_active_response`
- `run_active_response`

### `server` (5)

- `enrich_alert_full`
- `enrich_alerts_batch`
- `list_tenants`
- `set_session_role_tool`
- `switch_tenant`

### `tools/active_response` (6)

- `active_response_effectiveness`
- `approve_response`
- `correlate_alert_with_response`
- `deny_response`
- `get_active_responses`
- `propose_active_response`

### `tools/agent_health` (3)

- `get_agent_health_score`
- `get_health_breakdown`
- `list_unhealthy_agents`

### `tools/agent_upgrades` (4)

- `get_agent_upgrade_status`
- `list_agent_upgrades`
- `rollback_agent_upgrade`
- `trigger_agent_upgrade`

### `tools/agents` (7)

- `add_agent_to_group`
- `get_agent`
- `get_group_agents`
- `list_agents`
- `list_groups`
- `restart_agent`
- `run_active_response`

### `tools/alerts` (9)

- `alert_summary`
- `alert_timeline`
- `get_alert_by_id`
- `get_precomputed_summary`
- `get_recent_alerts_24h`
- `search_alerts`
- `search_authentication_failures`
- `search_by_mitre`
- `search_by_source_ip`

### `tools/archive` (2)

- `search_archive_logs`
- `search_archive_logs_by_agent`

### `tools/audit_mgmt` (3)

- `get_audit_log_stats`
- `search_audit_log`
- `verify_audit_log_integrity`

### `tools/autonomous_soc` (8)

- `approve_suppression`
- `configure_auto_ticketing`
- `configure_scheduled_reports`
- `get_autonomous_status`
- `list_pending_suppressions`
- `reject_suppression`
- `start_autonomous_monitor`
- `stop_autonomous_monitor`

### `tools/azure_devops` (3)

- `create_azure_devops_work_item`
- `get_azure_devops_work_item`
- `update_azure_devops_work_item`

### `tools/baseline` (3)

- `compute_agent_baseline`
- `list_anomalous_agents`
- `score_agent_deviation`

### `tools/cdb` (7)

- `add_to_cdb_list`
- `export_cdb_backup`
- `get_cdb_list_contents`
- `import_cdb_backup`
- `list_cdb_lists`
- `preview_cdb_list_impact`
- `remove_from_cdb_list`

### `tools/cluster` (2)

- `check_event_queue_health`
- `get_cluster_health`

### `tools/compliance` (9)

- `compliance_control_details`
- `compliance_drift`
- `compliance_summary`
- `generate_compliance_report`
- `hipaa_compliance_summary`
- `iso27001_compliance_summary`
- `nist_csf2_compliance_summary`
- `pci_dss_compliance_summary`
- `soc2_compliance_summary`

### `tools/correlation` (2)

- `correlate_alerts`
- `get_attack_chains`

### `tools/credential_mgmt` (2)

- `get_credential_age`
- `rotate_wazuh_api_password`

### `tools/cve_watchlist` (6)

- `add_cve_to_watchlist`
- `check_sla_breaches`
- `get_watchlist_exposure`
- `list_cve_watchlist`
- `mark_patched`
- `prioritize_cve_risk`

### `tools/explain_alert` (2)

- `explain_alert`
- `explain_recent_alerts`

### `tools/export` (6)

- `export_alerts_csv`
- `export_alerts_json`
- `export_alerts_ndjson`
- `export_compliance_csv`
- `export_report_html`
- `export_vulnerabilities_csv`

### `tools/fim` (4)

- `critical_file_changes`
- `fim_summary`
- `get_recent_fim_changes`
- `search_fim_alerts`

### `tools/fleet` (9)

- `fleet_batch_syscollector`
- `fleet_find_listening_port`
- `fleet_find_package`
- `fleet_find_process`
- `get_agent_hardware_os`
- `get_agent_login_history`
- `get_agent_open_ports`
- `get_agent_packages`
- `get_agent_processes`

### `tools/geo_intel` (2)

- `classify_ip_infrastructure`
- `enrich_ip_extended`

### `tools/health_check` (1)

- `get_wazuh_api_health`

### `tools/incidents` (6)

- `blast_radius_analysis`
- `bulk_suppress_rule`
- `correlate_multi_agent_incident`
- `create_incident_report`
- `incident_timeline`
- `tag_alert`

### `tools/index_mgmt` (5)

- `get_cluster_index_health`
- `get_index_settings`
- `get_index_stats`
- `list_index_aliases`
- `list_index_policies`

### `tools/integrations` (3)

- `create_jira_ticket`
- `create_thehive_case`
- `update_ticket_status`

### `tools/manager_audit` (3)

- `get_manager_login_history`
- `list_manager_api_users`
- `search_manager_audit_log`

### `tools/manager_config` (5)

- `get_manager_config_section`
- `get_manager_info`
- `get_manager_logs`
- `get_manager_status`
- `list_manager_config_sections`

### `tools/metrics` (3)

- `get_mcp_server_metrics`
- `get_slow_queries`
- `get_tool_usage_stats`

### `tools/mitre` (2)

- `get_mitre_gaps`
- `mitre_coverage_analysis`

### `tools/network_topology` (3)

- `get_agent_neighbors`
- `get_network_topology`
- `map_subnet_exposure`

### `tools/notifications` (8)

- `email_compliance_report`
- `send_alert_to_slack`
- `send_alert_to_teams`
- `send_critical_alert_notify`
- `send_critical_alert_to_teams`
- `send_shift_handover_to_slack`
- `send_weekly_summary_to_slack`
- `send_weekly_summary_to_teams`

### `tools/onboarding` (3)

- `agent_onboarding_checklist`
- `generate_enrollment_command`
- `list_never_connected_agents`

### `tools/pagerduty` (3)

- `acknowledge_pagerduty_alert`
- `resolve_pagerduty_alert`
- `trigger_pagerduty_alert`

### `tools/playbooks` (4)

- `get_playbook_status`
- `list_playbooks`
- `resume_playbook`
- `run_playbook`

### `tools/prompt_advisor` (3)

- `check_response_size`
- `get_recommended_system_prompt`
- `get_routing_advice`

### `tools/quick_wins` (7)

- `auto_triage_alert`
- `batch_auto_triage`
- `deduplicate_alerts`
- `get_abac_status`
- `get_recent_alerts_30d`
- `get_recent_alerts_7d`
- `nl_to_opensearch_query`

### `tools/reporting` (4)

- `compare_alert_volume`
- `detect_rule_anomalies`
- `generate_shift_handover`
- `generate_weekly_summary`

### `tools/roi` (3)

- `generate_roi_report`
- `roi_session_end`
- `roi_session_start`

### `tools/rootcheck` (3)

- `clear_rootcheck_results`
- `get_agent_rootcheck_results`
- `get_rootcheck_last_scan`

### `tools/rule_wizard_deploy` (3)

- `push_custom_decoder`
- `push_custom_rule`
- `sigma_bulk_import`

### `tools/rule_wizard_generate` (3)

- `convert_sigma_rule`
- `generate_rule_xml`
- `sigma_coverage_gap`

### `tools/rule_wizard_validate` (3)

- `suggest_rule_tuning`
- `test_sigma_rule_against_archive`
- `validate_rule_xml`

### `tools/rules` (9)

- `get_custom_rules`
- `get_rule_details`
- `list_decoders`
- `list_rule_files`
- `rollback_custom_rule`
- `search_rules`
- `test_decoder`
- `test_log_against_rules`
- `test_rule_coverage`

### `tools/sca` (4)

- `fleet_sca_weakest_agents`
- `get_agent_sca_policies`
- `get_sca_failed_checks`
- `sca_alerts_summary`

### `tools/scheduler` (3)

- `create_report_schedule`
- `delete_report_schedule`
- `list_report_schedules`

### `tools/servicenow` (3)

- `create_servicenow_incident`
- `get_servicenow_incident`
- `update_servicenow_incident`

### `tools/suppression` (3)

- `expire_suppression`
- `list_suppressed_rules`
- `noise_score_rule`

### `tools/syslog_config` (3)

- `get_syslog_config_section`
- `list_syslog_outputs`
- `test_syslog_connection`

### `tools/threat_feeds` (3)

- `correlate_alerts_with_feed`
- `list_threat_feeds`
- `sync_threat_feed`

### `tools/threat_hunting` (3)

- `hunt_data_exfiltration`
- `hunt_lateral_movement`
- `hunt_persistence_mechanisms`

### `tools/threat_intel` (9)

- `bulk_enrich_iocs`
- `enrich_domain`
- `enrich_email`
- `enrich_file_hash`
- `enrich_ip`
- `enrich_ip_geo`
- `enrich_url`
- `get_threat_intel_status`
- `ioc_to_alert_match`

### `tools/ueba` (4)

- `detect_user_anomalies`
- `get_peer_group_baseline`
- `get_user_activity_profile`
- `list_privileged_escalations`

### `tools/vulnerabilities` (7)

- `check_kev_exposure`
- `enrich_cve_epss`
- `get_agent_vulnerabilities_detailed`
- `prioritize_patches`
- `prioritize_patches_with_epss`
- `search_cve`
- `vulnerability_summary`

### `tools/workspaces` (4)

- `add_to_workspace`
- `create_workspace`
- `export_workspace`
- `get_workspace`
