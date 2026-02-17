#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, securitygoblin
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

DOCUMENTATION = r"""
---
module: win_job_log
short_description: Log Ansible job status to a JSON file on Windows hosts
description:
  - Creates and maintains a structured JSON log file tracking Ansible playbook
    job execution on Windows hosts.
  - Supports upsert logic — updates an existing job entry by C(job_name), or
    creates a new one if it does not exist. Creates the file if it is missing.
  - Auto-generates timestamps, hostname, duration, and job IDs so that
    callers only need to supply minimal parameters.
  - Designed to be called twice per job — once with C(state=started) at the
    beginning and once with C(state=completed) at the end.
version_added: "1.0.0"
options:
  path:
    description:
      - Absolute path to the JSON log file on the Windows host.
      - Parent directories are created automatically when I(create_directory=true).
    type: path
    required: true
  job_name:
    description:
      - Unique name identifying the job.
      - Used as the upsert key — if a job with this name already exists in
        the file it is updated; otherwise a new entry is appended.
    type: str
    required: true
  state:
    description:
      - C(started) — record the start of a job (sets status to C(running),
        timestamps the start, opens a maintenance window).
      - C(completed) — record the end of a job (sets final status, calculates
        duration, closes the maintenance window).
    type: str
    required: true
    choices: [started, completed]
  status:
    description:
      - Final execution status of the job.
      - Only meaningful when I(state=completed).
    type: str
    default: ok
    choices: [ok, failed, unreachable]
  health:
    description:
      - Health assessment for the job.
    type: str
    default: healthy
    choices: [healthy, degraded, unhealthy]
  source:
    description:
      - Metadata about the Ansible controller and playbook run.
      - Values are merged into the log file; existing values are preserved
        unless explicitly overridden.
    type: dict
    default: {}
    suboptions:
      ansible_controller:
        description: Hostname or identifier of the Ansible controller.
        type: str
        default: unknown
      playbook:
        description: Name of the playbook being executed.
        type: str
        default: unknown
      run_id:
        description:
          - Unique identifier for this playbook run.
          - Auto-generated from timestamp and job name if not provided.
        type: str
        default: ""
      environment:
        description: Target environment (e.g. prod, staging, dev).
        type: str
        default: unknown
      ansible_version:
        description: Ansible version running on the controller.
        type: str
        default: unknown
  summary:
    description:
      - Task execution statistics. Typically set when I(state=completed).
    type: dict
    default: {}
    suboptions:
      ok:
        description: Number of successful tasks.
        type: int
        default: 0
      changed:
        description: Number of tasks that made changes.
        type: int
        default: 0
      failed:
        description: Number of failed tasks.
        type: int
        default: 0
      unreachable:
        description: Number of unreachable targets.
        type: int
        default: 0
  host_info:
    description:
      - Additional host-level information to record.
    type: dict
    default: {}
    suboptions:
      software_installed:
        description: List of software installed on the host.
        type: list
        elements: str
        default: []
      config_applied:
        description: List of configuration items applied to the host.
        type: list
        elements: str
        default: []
      siem:
        description: SIEM integration status.
        type: dict
        default: {}
        suboptions:
          onboarded:
            description: Whether the host is onboarded to SIEM.
            type: bool
            default: false
          collector:
            description: SIEM collector hostname.
            type: str
            default: ""
          syslog_running:
            description: Whether syslog forwarding is active.
            type: bool
            default: false
          forwarding_ok:
            description: Whether log forwarding is healthy.
            type: bool
            default: false
          last_seen:
            description: ISO 8601 timestamp of last SIEM heartbeat.
            type: str
            default: ""
  job_id:
    description:
      - Custom job ID. If not set, one is auto-generated as
        C(host-HOSTNAME-NNNNN).
    type: str
    default: ""
  create_directory:
    description:
      - Create parent directories for I(path) if they do not exist.
    type: bool
    default: true
  mutex_timeout_ms:
    description:
      - Maximum time in milliseconds to wait for the file lock.
    type: int
    default: 30000
notes:
  - This module runs on Windows targets using PowerShell.
  - File access is serialised with a Windows named mutex so that
    concurrent playbook runs can safely write to the same file.
  - Writes are atomic (temp file + rename) to prevent corruption.
  - Host-level C(status) and C(health) are automatically aggregated
    from all job entries in the file.
seealso:
  - module: ansible.windows.win_copy
  - module: ansible.windows.win_file
author:
  - securitygoblin
"""

EXAMPLES = r"""
# ── Minimal: log start and end of a job ────────────────────────────────────
- name: Log job start
  securitygoblin.jsonlogging.win_job_log:
    path: C:\ansible\status.json
    job_name: patch-windows
    state: started

- name: Run patching tasks
  ansible.windows.win_updates:
    category_names: [SecurityUpdates, CriticalUpdates]
    state: installed

- name: Log job success
  securitygoblin.jsonlogging.win_job_log:
    path: C:\ansible\status.json
    job_name: patch-windows
    state: completed
    status: ok

# ── Full example with source metadata and error handling ───────────────────
- name: Patching with full logging
  hosts: windows_servers
  vars:
    log_path: C:\ansible\status.json
  tasks:
    - name: Log job start
      securitygoblin.jsonlogging.win_job_log:
        path: "{{ log_path }}"
        job_name: patch-windows
        state: started
        source:
          ansible_controller: "{{ inventory_hostname }}"
          playbook: "{{ ansible_play_name }}"
          run_id: "{{ lookup('pipe', 'date +%Y%m%d-%H%M%S') }}-{{ ansible_play_name }}"
          environment: "{{ env | default('prod') }}"
          ansible_version: "{{ ansible_version.full }}"

    - block:
        - name: Install updates
          ansible.windows.win_updates:
            category_names: [SecurityUpdates]
            state: installed
          register: update_result

        - name: Log success
          securitygoblin.jsonlogging.win_job_log:
            path: "{{ log_path }}"
            job_name: patch-windows
            state: completed
            status: ok
            health: healthy
            summary:
              ok: 1
              changed: "{{ update_result.changed | int }}"
              failed: 0
              unreachable: 0
      rescue:
        - name: Log failure
          securitygoblin.jsonlogging.win_job_log:
            path: "{{ log_path }}"
            job_name: patch-windows
            state: completed
            status: failed
            health: unhealthy
            summary:
              ok: 0
              changed: 0
              failed: 1
              unreachable: 0

# ── Update host info and SIEM status ──────────────────────────────────────
- name: Log compliance scan with host info
  securitygoblin.jsonlogging.win_job_log:
    path: C:\ansible\status.json
    job_name: compliance-scan
    state: completed
    status: ok
    host_info:
      software_installed:
        - wec-agent-2.1.0
      config_applied:
        - wec-subscription.xml
      siem:
        onboarded: true
        collector: wec-collector-01
        syslog_running: true
        forwarding_ok: true
        last_seen: "{{ ansible_date_time.iso8601 }}"
"""

RETURN = r"""
changed:
  description: Whether the log file was modified.
  returned: always
  type: bool
  sample: true
path:
  description: Path to the JSON log file.
  returned: always
  type: str
  sample: C:\ansible\status.json
job_name:
  description: Name of the job that was logged.
  returned: always
  type: str
  sample: patch-windows
state:
  description: State that was recorded.
  returned: always
  type: str
  sample: completed
job_id:
  description: ID assigned to the job entry.
  returned: always
  type: str
  sample: host-srv001-48291
"""
