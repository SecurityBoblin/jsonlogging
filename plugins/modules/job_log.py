#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, securitygoblin
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: job_log
short_description: Log Ansible job status to a JSON file on Linux hosts
description:
  - Creates and maintains a structured JSON log file tracking Ansible playbook
    job execution on Linux hosts.
  - Supports upsert logic — updates an existing job entry by C(job_name), or
    creates a new one if it does not exist. Creates the file if it is missing.
  - Auto-generates timestamps, hostname, duration, and job IDs so that
    callers only need to supply minimal parameters.
  - Designed to be called twice per job — once with C(state=started) at the
    beginning and once with C(state=completed) at the end.
  - This is the Linux counterpart of C(win_job_log). Both modules produce
    the same JSON schema.
version_added: "1.0.0"
options:
  path:
    description:
      - Absolute path to the JSON log file on the Linux host.
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
  lock_timeout_sec:
    description:
      - Maximum time in seconds to wait for the file lock.
    type: int
    default: 30
notes:
  - This module runs on Linux targets using Python.
  - File access is serialised with C(fcntl.flock) so that concurrent
    playbook runs can safely write to the same file.
  - Writes are atomic (temp file + rename) to prevent corruption.
  - Host-level C(status) and C(health) are automatically aggregated
    from all job entries in the file.
  - Produces the same JSON schema as C(win_job_log).
seealso:
  - module: securitygoblin.jsonlogging.win_job_log
  - module: ansible.builtin.copy
  - module: ansible.builtin.file
author:
  - securitygoblin
"""

EXAMPLES = r"""
# ── Minimal: log start and end of a job ────────────────────────────────────
- name: Log job start
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: patch-linux
    state: started

- name: Run patching tasks
  ansible.builtin.yum:
    name: '*'
    state: latest
    security: true

- name: Log job success
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: patch-linux
    state: completed
    status: ok

# ── Full example with source metadata and error handling ───────────────────
- name: Patching with full logging
  hosts: linux_servers
  vars:
    log_path: /var/log/ansible/status.json
  tasks:
    - name: Log job start
      securitygoblin.jsonlogging.job_log:
        path: "{{ log_path }}"
        job_name: patch-linux
        state: started
        source:
          ansible_controller: "{{ inventory_hostname }}"
          playbook: "{{ ansible_play_name }}"
          run_id: "{{ lookup('pipe', 'date +%Y%m%d-%H%M%S') }}-{{ ansible_play_name }}"
          environment: "{{ env | default('prod') }}"
          ansible_version: "{{ ansible_version.full }}"

    - block:
        - name: Install updates
          ansible.builtin.yum:
            name: '*'
            state: latest
            security: true
          register: update_result

        - name: Log success
          securitygoblin.jsonlogging.job_log:
            path: "{{ log_path }}"
            job_name: patch-linux
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
          securitygoblin.jsonlogging.job_log:
            path: "{{ log_path }}"
            job_name: patch-linux
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
  securitygoblin.jsonlogging.job_log:
    path: /var/log/ansible/status.json
    job_name: compliance-scan
    state: completed
    status: ok
    host_info:
      software_installed:
        - rsyslog-8.2102
        - auditd-3.0.7
      config_applied:
        - cis-benchmark-level2
      siem:
        onboarded: true
        collector: syslog-collector-01
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
  sample: /var/log/ansible/status.json
job_name:
  description: Name of the job that was logged.
  returned: always
  type: str
  sample: patch-linux
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

import fcntl
import json
import os
import random
import signal
import socket
import tempfile
from collections import OrderedDict
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule


# ── Helpers ────────────────────────────────────────────────────────────────

def utc_timestamp():
    """Return current UTC time as ISO 8601 string."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_job_id():
    """Generate a job ID like host-hostname-12345."""
    hostname = socket.gethostname().lower()
    suffix = random.randint(10000, 99999)
    return "host-%s-%d" % (hostname, suffix)


def new_job_log_structure(source_params):
    """Create a blank JSON log structure."""
    src = source_params or {}
    return OrderedDict([
        ("schema_version", "1.0"),
        ("generated_at", utc_timestamp()),
        ("source", OrderedDict([
            ("ansible_controller", src.get("ansible_controller", "unknown")),
            ("playbook", src.get("playbook", "unknown")),
            ("run_id", src.get("run_id", "")),
            ("environment", src.get("environment", "unknown")),
            ("ansible_version", src.get("ansible_version", "unknown")),
        ])),
        ("jobs", []),
        ("host", OrderedDict([
            ("name", socket.gethostname().lower()),
            ("status", "unknown"),
            ("health", "unknown"),
            ("software_installed", []),
            ("config_applied", []),
            ("siem", OrderedDict([
                ("onboarded", False),
                ("collector", ""),
                ("syslog_running", False),
                ("forwarding_ok", False),
                ("last_seen", ""),
            ])),
        ])),
    ])


def new_job_entry(job_name, job_id):
    """Create a blank job entry."""
    return OrderedDict([
        ("job_name", job_name),
        ("job_id", job_id),
        ("status", "running"),
        ("started_at", ""),
        ("finished_at", ""),
        ("duration_sec", 0),
        ("health", "healthy"),
        ("summary", OrderedDict([
            ("ok", 0),
            ("changed", 0),
            ("failed", 0),
            ("unreachable", 0),
        ])),
        ("maintenance_window", OrderedDict([
            ("started_at", ""),
            ("ended_at", ""),
            ("ended", False),
        ])),
    ])


def update_host_aggregate(job_log):
    """Recalculate host-level status and health from all jobs."""
    jobs = job_log.get("jobs", [])
    if not jobs:
        job_log["host"]["status"] = "unknown"
        job_log["host"]["health"] = "unknown"
        return

    has_failed = any(j.get("status") in ("failed", "unreachable") for j in jobs)
    has_running = any(j.get("status") == "running" for j in jobs)

    if has_failed:
        job_log["host"]["status"] = "failed"
    elif has_running:
        job_log["host"]["status"] = "running"
    else:
        job_log["host"]["status"] = "ok"

    has_unhealthy = any(j.get("health") == "unhealthy" for j in jobs)
    has_degraded = any(j.get("health") == "degraded" for j in jobs)

    if has_unhealthy:
        job_log["host"]["health"] = "unhealthy"
    elif has_degraded:
        job_log["host"]["health"] = "degraded"
    else:
        job_log["host"]["health"] = "healthy"


def parse_existing(raw):
    """Parse existing JSON into an ordered structure, filling missing keys."""
    parsed = json.loads(raw, object_pairs_hook=OrderedDict)
    hostname = socket.gethostname().lower()

    job_log = OrderedDict([
        ("schema_version", parsed.get("schema_version", "1.0")),
        ("generated_at", parsed.get("generated_at", utc_timestamp())),
        ("source", OrderedDict([
            ("ansible_controller", (parsed.get("source") or {}).get("ansible_controller", "unknown")),
            ("playbook", (parsed.get("source") or {}).get("playbook", "unknown")),
            ("run_id", (parsed.get("source") or {}).get("run_id", "")),
            ("environment", (parsed.get("source") or {}).get("environment", "unknown")),
            ("ansible_version", (parsed.get("source") or {}).get("ansible_version", "unknown")),
        ])),
        ("jobs", []),
        ("host", OrderedDict([
            ("name", (parsed.get("host") or {}).get("name", hostname)),
            ("status", (parsed.get("host") or {}).get("status", "unknown")),
            ("health", (parsed.get("host") or {}).get("health", "unknown")),
            ("software_installed", list((parsed.get("host") or {}).get("software_installed") or [])),
            ("config_applied", list((parsed.get("host") or {}).get("config_applied") or [])),
            ("siem", OrderedDict([
                ("onboarded", ((parsed.get("host") or {}).get("siem") or {}).get("onboarded", False)),
                ("collector", ((parsed.get("host") or {}).get("siem") or {}).get("collector", "")),
                ("syslog_running", ((parsed.get("host") or {}).get("siem") or {}).get("syslog_running", False)),
                ("forwarding_ok", ((parsed.get("host") or {}).get("siem") or {}).get("forwarding_ok", False)),
                ("last_seen", ((parsed.get("host") or {}).get("siem") or {}).get("last_seen", "")),
            ])),
        ])),
    ])

    for existing_job in parsed.get("jobs") or []:
        summary = existing_job.get("summary") or {}
        mw = existing_job.get("maintenance_window") or {}
        j = OrderedDict([
            ("job_name", existing_job.get("job_name", "")),
            ("job_id", existing_job.get("job_id", "")),
            ("status", existing_job.get("status", "")),
            ("started_at", existing_job.get("started_at", "")),
            ("finished_at", existing_job.get("finished_at", "")),
            ("duration_sec", existing_job.get("duration_sec", 0)),
            ("health", existing_job.get("health", "healthy")),
            ("summary", OrderedDict([
                ("ok", int(summary.get("ok", 0))),
                ("changed", int(summary.get("changed", 0))),
                ("failed", int(summary.get("failed", 0))),
                ("unreachable", int(summary.get("unreachable", 0))),
            ])),
            ("maintenance_window", OrderedDict([
                ("started_at", mw.get("started_at", "")),
                ("ended_at", mw.get("ended_at", "")),
                ("ended", mw.get("ended", False)),
            ])),
        ])
        job_log["jobs"].append(j)

    return job_log


def acquire_lock(fd, timeout):
    """Acquire an exclusive flock with a timeout via SIGALRM."""
    def _timeout_handler(signum, frame):
        raise OSError("Failed to acquire file lock within %d seconds" % timeout)

    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


# ── Main ───────────────────────────────────────────────────────────────────

def run_module():
    source_spec = dict(
        ansible_controller=dict(type="str", default="unknown"),
        playbook=dict(type="str", default="unknown"),
        run_id=dict(type="str", default=""),
        environment=dict(type="str", default="unknown"),
        ansible_version=dict(type="str", default="unknown"),
    )
    summary_spec = dict(
        ok=dict(type="int", default=0),
        changed=dict(type="int", default=0),
        failed=dict(type="int", default=0),
        unreachable=dict(type="int", default=0),
    )
    siem_spec = dict(
        onboarded=dict(type="bool", default=False),
        collector=dict(type="str", default=""),
        syslog_running=dict(type="bool", default=False),
        forwarding_ok=dict(type="bool", default=False),
        last_seen=dict(type="str", default=""),
    )
    host_info_spec = dict(
        software_installed=dict(type="list", elements="str", default=[]),
        config_applied=dict(type="list", elements="str", default=[]),
        siem=dict(type="dict", default={}, options=siem_spec),
    )

    argument_spec = dict(
        path=dict(type="path", required=True),
        job_name=dict(type="str", required=True),
        state=dict(type="str", required=True, choices=["started", "completed"]),
        status=dict(type="str", default="ok", choices=["ok", "failed", "unreachable"]),
        health=dict(type="str", default="healthy", choices=["healthy", "degraded", "unhealthy"]),
        source=dict(type="dict", default={}, options=source_spec),
        summary=dict(type="dict", default={}, options=summary_spec),
        host_info=dict(type="dict", default={}, options=host_info_spec),
        job_id=dict(type="str", default=""),
        create_directory=dict(type="bool", default=True),
        lock_timeout_sec=dict(type="int", default=30),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    path = module.params["path"]
    job_name = module.params["job_name"]
    state = module.params["state"]
    lock_timeout = module.params["lock_timeout_sec"]

    # ── Ensure parent directory exists ─────────────────────────────────
    if module.params["create_directory"]:
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            if not module.check_mode:
                try:
                    os.makedirs(directory, mode=0o755)
                except OSError as e:
                    module.fail_json(msg="Failed to create directory '%s': %s" % (directory, str(e)))

    if module.check_mode:
        module.exit_json(changed=True, path=path, job_name=job_name, state=state, job_id="")
        return

    # ── Open lock file and acquire exclusive lock ──────────────────────
    lock_path = path + ".lock"
    lock_fd = None
    try:
        lock_fd = open(lock_path, "w")
        try:
            acquire_lock(lock_fd.fileno(), lock_timeout)
        except OSError as e:
            module.fail_json(msg=str(e))

        # ── Read or create the JSON structure ──────────────────────────
        job_log = None
        if os.path.isfile(path):
            try:
                with open(path, "r") as f:
                    raw = f.read()
                job_log = parse_existing(raw)
            except (ValueError, KeyError) as e:
                module.fail_json(
                    msg="Failed to parse existing JSON file at '%s'. File may be corrupted: %s" % (path, str(e))
                )
        else:
            job_log = new_job_log_structure(module.params.get("source"))

        # ── Merge source metadata ─────────────────────────────────────
        source_param = module.params.get("source") or {}
        for key in ("ansible_controller", "playbook", "environment", "ansible_version"):
            val = source_param.get(key)
            if val and val != "unknown":
                job_log["source"][key] = val
        if source_param.get("run_id"):
            job_log["source"]["run_id"] = source_param["run_id"]

        # Auto-generate run_id if still empty
        if not job_log["source"]["run_id"]:
            ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            job_log["source"]["run_id"] = "%s-%s" % (ts, job_name)

        # ── Find or create job entry ──────────────────────────────────
        job_index = -1
        for i, j in enumerate(job_log["jobs"]):
            if j.get("job_name") == job_name:
                job_index = i
                break

        if job_index == -1:
            jid = module.params["job_id"] if module.params["job_id"] else generate_job_id()
            entry = new_job_entry(job_name, jid)
            job_log["jobs"].append(entry)
            job_index = len(job_log["jobs"]) - 1

        job = job_log["jobs"][job_index]

        # ── Apply state-specific updates ──────────────────────────────
        now = utc_timestamp()

        if state == "started":
            job["started_at"] = now
            job["finished_at"] = ""
            job["duration_sec"] = 0
            job["status"] = "running"
            job["health"] = module.params["health"]
            job["maintenance_window"]["started_at"] = now
            job["maintenance_window"]["ended_at"] = ""
            job["maintenance_window"]["ended"] = False
            job["summary"]["ok"] = 0
            job["summary"]["changed"] = 0
            job["summary"]["failed"] = 0
            job["summary"]["unreachable"] = 0
            if module.params["job_id"]:
                job["job_id"] = module.params["job_id"]

        elif state == "completed":
            job["finished_at"] = now
            job["status"] = module.params["status"]
            job["health"] = module.params["health"]
            job["maintenance_window"]["ended_at"] = now
            job["maintenance_window"]["ended"] = True

            # Calculate duration
            if job["started_at"]:
                try:
                    fmt = "%Y-%m-%dT%H:%M:%SZ"
                    start_dt = datetime.strptime(job["started_at"], fmt)
                    end_dt = datetime.strptime(job["finished_at"], fmt)
                    job["duration_sec"] = int((end_dt - start_dt).total_seconds())
                except (ValueError, TypeError):
                    module.warn("Could not calculate duration for job '%s'" % job_name)
                    job["duration_sec"] = 0
            else:
                module.warn("Job '%s' has no started_at timestamp. Duration set to 0." % job_name)

            # Update summary
            summary_param = module.params.get("summary") or {}
            job["summary"]["ok"] = int(summary_param.get("ok", 0))
            job["summary"]["changed"] = int(summary_param.get("changed", 0))
            job["summary"]["failed"] = int(summary_param.get("failed", 0))
            job["summary"]["unreachable"] = int(summary_param.get("unreachable", 0))

        job_log["jobs"][job_index] = job

        # ── Merge host_info ───────────────────────────────────────────
        host_info = module.params.get("host_info") or {}
        if host_info:
            sw = host_info.get("software_installed")
            if sw:
                job_log["host"]["software_installed"] = list(sw)
            ca = host_info.get("config_applied")
            if ca:
                job_log["host"]["config_applied"] = list(ca)
            siem = host_info.get("siem") or {}
            if siem:
                if siem.get("onboarded") is not None:
                    job_log["host"]["siem"]["onboarded"] = siem["onboarded"]
                if siem.get("collector"):
                    job_log["host"]["siem"]["collector"] = siem["collector"]
                if siem.get("syslog_running") is not None:
                    job_log["host"]["siem"]["syslog_running"] = siem["syslog_running"]
                if siem.get("forwarding_ok") is not None:
                    job_log["host"]["siem"]["forwarding_ok"] = siem["forwarding_ok"]
                if siem.get("last_seen"):
                    job_log["host"]["siem"]["last_seen"] = siem["last_seen"]

        # ── Recalculate host aggregates ───────────────────────────────
        update_host_aggregate(job_log)

        # ── Update generated_at ───────────────────────────────────────
        job_log["generated_at"] = utc_timestamp()

        # ── Atomic write ──────────────────────────────────────────────
        dir_name = os.path.dirname(path) or "."
        try:
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".job_log_", suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as tmp_f:
                    json.dump(job_log, tmp_f, indent=2)
                os.rename(tmp_path, path)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as e:
            module.fail_json(msg="Failed to write JSON log file: %s" % str(e))

        result_job_id = job_log["jobs"][job_index].get("job_id", "")

    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            lock_fd.close()

    module.exit_json(
        changed=True,
        path=path,
        job_name=job_name,
        state=state,
        job_id=result_job_id,
    )


def main():
    run_module()


if __name__ == "__main__":
    main()
